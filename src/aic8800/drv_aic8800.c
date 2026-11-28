/*
 * drv_aic8800.c - AIC8800D80 (UGREEN 368b:8d85) chip driver, see wifi_drv.h.
 *
 * Port of yokitea AIC8800WiFi.kext (BSD-3, see third_party/yokitea/LICENSE) to userspace: libusb for
 * the single vendor interface (IN 0x81 carries both LMAC messages and data; OUT #1 = data,
 * OUT #2 = messages). The firmware is loaded beforehand by "usbwifid fwload" (mass-storage stage).
 */
#include "wifi_drv.h"

#include <errno.h>
#include <libusb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "aic8800_abi.h"
#include "aic8800_framing.h"
#include "aic8800_lmac.h"
#include "rx_reord.h"
#include "aic8800_wifi_ctl.h"
#include "wifi_ctl.h"

/* the core's cipher, band and connect flag codes go to the LMAC unchanged */
#define SAME_CODE(w, a) _Static_assert((int)(w) == (int)(a), #w " != " #a)
SAME_CODE(WIFI_CIPHER_WEP40, AIC_CIPHER_WEP40);
SAME_CODE(WIFI_CIPHER_TKIP, AIC_CIPHER_TKIP);
SAME_CODE(WIFI_CIPHER_CCMP, AIC_CIPHER_CCMP);
SAME_CODE(WIFI_CIPHER_WEP104, AIC_CIPHER_WEP104);
SAME_CODE(WIFI_CIPHER_BIP_CMAC_128, AIC_CIPHER_BIP_CMAC_128);
SAME_CODE(WIFI_CIPHER_GCMP_128, AIC_CIPHER_GCMP_128);
SAME_CODE(WIFI_CIPHER_GCMP_256, AIC_CIPHER_GCMP_256);
SAME_CODE(WIFI_CIPHER_CCMP_256, AIC_CIPHER_CCMP_256);
SAME_CODE(WIFI_CIPHER_INVALID, AIC_CIPHER_INVALID);
SAME_CODE(WIFI_BAND_2G4, AIC_PHY_BAND_2G4);
SAME_CODE(WIFI_BAND_5G, AIC_PHY_BAND_5G);
SAME_CODE(WIFI_CONN_CONTROL_PORT_HOST, AIC_CONTROL_PORT_HOST);
SAME_CODE(WIFI_CONN_WPA_WPA2_IN_USE, AIC_WPA_WPA2_IN_USE);

#define RX_BUF_BYTES 32768

static const struct wifi_drv_events *ev;

static struct {
    libusb_context *ctx;
    libusb_device_handle *h;
    uint8_t ep_in, ep_out_data, ep_out_msg;
    uint16_t mps_data, mps_msg;
    pthread_t rx_thr;
    volatile bool stopping;

    /* command path */
    pthread_mutex_t cmd_serial, cmd_lock;
    pthread_cond_t cmd_cond;
    aic_lmac_cmd_matcher_t matcher;

    uint8_t mac[6], vif_idx, is_5g, sta_idx, qos;
    volatile bool associated;
    uint32_t chip_id, lmac_ver, fw_features;
    uint8_t vendor_info;
    char fw_version[64];
    uint8_t hw_keys[8], n_hw_keys; /* installed by add_key; deleted before the next connect */
    uint64_t tx_pkts;

    pthread_mutex_t tx_lock;
    uint8_t rx_eth_scratch[AIC_DATA_BUF_MAX + 64];
} a = { .cmd_serial = PTHREAD_MUTEX_INITIALIZER, .cmd_lock = PTHREAD_MUTEX_INITIALIZER,
        .cmd_cond = PTHREAD_COND_INITIALIZER, .tx_lock = PTHREAD_MUTEX_INITIALIZER };

static int usb_bulk_out(uint8_t ep, uint16_t mps, const uint8_t *buf, int len, unsigned timeout_ms) {
    int done = 0;
    int rc = libusb_bulk_transfer(a.h, ep, (unsigned char *)buf, len, &done, timeout_ms);
    if (rc != 0 || done != len) return rc ? rc : LIBUSB_ERROR_IO;
    if (aic_usb_needs_zlp((uint32_t)len, mps)) {
        rc = libusb_bulk_transfer(a.h, ep, NULL, 0, &done, timeout_ms);
    }
    return rc;
}

static struct timespec conn_t0; /* connect start, for connect timing logs */
static double since_ms(const struct timespec *t) {
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (double)(n.tv_sec - t->tv_sec) * 1e3 + (double)(n.tv_nsec - t->tv_nsec) / 1e6;
}

/* ------------------------------------------------------------- RX path */

static void on_async_ind(uint16_t id, const uint8_t *param, uint16_t len, void *ctx);

/* RX BlockAck reorder: A-MPDU subframes can arrive out of order (retries), TCP needs them in order.
   Frames waiting in the window are copies from a fixed pool; rx_lock guards pool + window because
   libusb may run RX callbacks on any thread that handles events (sync bulk transfers do too). */
#define REORD_POOL 512
typedef struct rpkt { struct rpkt *next; uint16_t len; uint8_t data[AIC_DATA_BUF_MAX]; } rpkt_t;
static rpkt_t rpool[REORD_POOL], *rfree;
static rx_reord_t reord;
static pthread_mutex_t rx_lock = PTHREAD_MUTEX_INITIALIZER;
static bool reord_pending;
static struct timespec reord_armed;

static void rpkt_drop(void *head, void *ctx) {
    (void)ctx;
    for (rpkt_t *p = head, *n; p; p = n) { n = p->next; p->next = rfree; rfree = p; }
}
static void rpkt_deliver(void *head, uint32_t bytes, void *ctx) {
    (void)bytes;
    for (rpkt_t *p = head; p; p = p->next) ev->rx(p->data, p->len, false);
    rpkt_drop(head, ctx);
}
static void rpkt_append(void *tail, void *pkt) { ((rpkt_t *)tail)->next = pkt; }

/* frames buffered for the old link must not leak into the next one */
static void reord_reset(void) {
    pthread_mutex_lock(&rx_lock);
    rx_reord_flush_all(&reord, true, NULL, rpkt_drop, NULL);
    rx_reord_init(&reord);
    reord_pending = false;
    pthread_mutex_unlock(&rx_lock);
}

/* rx_thread tick: release frames stuck behind a lost subframe after RX_REORD_TIMEOUT_MS */
static void reord_tick(void) {
    pthread_mutex_lock(&rx_lock);
    if (reord_pending && since_ms(&reord_armed) >= RX_REORD_TIMEOUT_MS) {
        reord_pending = rx_reord_timeout_flush(&reord, rpkt_deliver, NULL);
        if (reord_pending) clock_gettime(CLOCK_MONOTONIC, &reord_armed);
    }
    pthread_mutex_unlock(&rx_lock);
}

/* called with rx_lock held (from on_data_chunk) */
static void on_eth(const uint8_t *eth, size_t len, const aic_rx_frame_meta_t *meta, void *ctx) {
    (void)ctx;
    if (meta && meta->is_eapol) {
        ev->rx(eth, len, true);
        return;
    }
    if (!meta || !meta->is_qos || len > AIC_DATA_BUF_MAX) { ev->rx(eth, len, false); return; }
    if (!meta->need_reord) {
        /* firmware says this TID has no BA session: anything buffered for it is stale */
        if (reord.tids[meta->tid & 7].pending_count) rx_reord_flush_tid(&reord, meta->tid, false, rpkt_deliver, rpkt_drop, NULL);
        ev->rx(eth, len, false);
        return;
    }
    rpkt_t *p = rfree;
    if (!p) { ev->rx(eth, len, false); return; } /* pool exhausted: deliver unordered rather than drop */
    rfree = p->next;
    p->next = NULL;
    p->len = (uint16_t)len;
    memcpy(p->data, eth, len);
    bool timer = false;
    rx_reord_submit(&reord, meta->tid, meta->seq_num, p, (uint32_t)len, meta->amsdu_sub_idx > 0,
                    rpkt_deliver, rpkt_append, rpkt_drop, NULL, &timer);
    if (timer && !reord_pending) clock_gettime(CLOCK_MONOTONIC, &reord_armed);
    reord_pending = reord_pending || timer; /* timer is per-TID; reord_tick() clears it once all TIDs drain */
}

/* RX diagnostics: where data chunks go (logged every 10 s when changed) */
static struct { uint64_t chunks, emitted, zero, err, mpdu, ga, decr[8], last_sum, xfers, bytes; time_t last_log; } rxs;

static void log_rx_stats(void) {
    time_t now = time(NULL);
    uint64_t sum = rxs.chunks + a.tx_pkts;
    if (now - rxs.last_log < 10 || sum == rxs.last_sum) return;
    rxs.last_log = now;
    rxs.last_sum = sum;
    fprintf(stderr, "aic8800: rx xfers=%llu bytes=%llu chunks=%llu eth=%llu skip=%llu err=%llu mpdu=%llu group=%llu decr[unenc/tkip/ccmp]=%llu/%llu/%llu tx=%llu reord[buf/dup/tmo]=%llu/%llu/%llu\n",
            rxs.xfers, rxs.bytes, rxs.chunks, rxs.emitted, rxs.zero, rxs.err, rxs.mpdu, rxs.ga,
            rxs.decr[AIC_RX_HD_DECR_UNENC], rxs.decr[AIC_RX_HD_DECR_TKIP], rxs.decr[AIC_RX_HD_DECR_CCMP128],
            a.tx_pkts, reord.buffered_reorders, reord.dup_drops, reord.timeout_flushes);
}

static void on_data_chunk(const uint8_t *chunk, size_t len, void *ctx) {
    (void)ctx;
    rxs.chunks++;
    if (len >= sizeof(aic_hw_rxhdr_t)) {
        aic_hw_rxhdr_t h;
        memcpy(&h, chunk, sizeof(h));
        rxs.decr[h.hwvect.decr_status & 7]++;
        rxs.mpdu += h.flags_is_80211_mpdu;
        rxs.ga += h.hwvect.ga_frame;
    }
    pthread_mutex_lock(&rx_lock);
    int n = aic_rx_chunk_to_eth_frames(chunk, len, a.rx_eth_scratch, sizeof(a.rx_eth_scratch), on_eth, NULL);
    pthread_mutex_unlock(&rx_lock);
    if (n > 0) rxs.emitted += (uint64_t)n; else if (n == 0) rxs.zero++; else rxs.err++;
}

static void on_cfg_pkt(uint8_t type, const uint8_t *payload, size_t len, void *ctx) {
    (void)ctx;
    if (!payload || len > UINT16_MAX) return;
    aic_msg_rx_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.matcher = &a.matcher;
    d.on_async_ind = on_async_ind;
    pthread_mutex_lock(&a.cmd_lock);
    (void)aic_usb_handle_ctrl_pkt(&d, type, payload, (uint16_t)len);
    if (d.matched_cmd_cfm || a.matcher.completed) pthread_cond_broadcast(&a.cmd_cond);
    pthread_mutex_unlock(&a.cmd_lock);
    if (d.print_ptr && d.print_len > 0U && getenv("AICD_FWLOG")) {
        fprintf(stderr, "[fw] %.*s\n", (int)d.print_len, (const char *)d.print_ptr);
    }
}

/* Several IN transfers stay queued so the dongle can push the next chunk while we process the last one
   (a single synchronous read left the bus idle between frames and capped RX near 25 Mbit/s).
   libusb completes transfers of one endpoint in submission order, so the stream stays ordered. */
#define RX_XFERS 16
static void LIBUSB_CALL rx_done(struct libusb_transfer *t) {
    static int errs; /* consecutive failed transfers; callbacks run one at a time on the event thread */
    errs = t->status == LIBUSB_TRANSFER_COMPLETED ? 0 : errs + 1;
    /* unplugged (the dongle returns to stage 0), or ~1 s of nothing but errors: RX is dead, restart */
    if (t->status == LIBUSB_TRANSFER_NO_DEVICE || errs == 100) ev->gone();
    if (t->status == LIBUSB_TRANSFER_COMPLETED) { rxs.xfers++; rxs.bytes += (uint64_t)t->actual_length; }
    if (t->status == LIBUSB_TRANSFER_COMPLETED && t->actual_length >= 4)
        (void)aic_rx_demux_usb_aggr(t->buffer, (size_t)t->actual_length, on_data_chunk, on_cfg_pkt, NULL);
    else if (t->status != LIBUSB_TRANSFER_COMPLETED) usleep(10000); /* transient error: don't spin */
    if (a.stopping) return;
    /* a stalled IN endpoint (seen with two dongles on one hub): clear it instead of dropping the dongle */
    if (t->status == LIBUSB_TRANSFER_STALL) (void)libusb_clear_halt(a.h, a.ep_in);
    int rc = libusb_submit_transfer(t);
    if (rc == LIBUSB_ERROR_PIPE && libusb_clear_halt(a.h, a.ep_in) == 0) rc = libusb_submit_transfer(t);
    if (rc != 0) { fprintf(stderr, "aic8800: RX resubmit failed: %s\n", libusb_error_name(rc)); ev->gone(); }
}

static void *rx_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < RX_XFERS; ++i) {
        struct libusb_transfer *t = libusb_alloc_transfer(0);
        uint8_t *buf = malloc(RX_BUF_BYTES);
        if (!t || !buf) exit(1);
        libusb_fill_bulk_transfer(t, a.h, a.ep_in, buf, RX_BUF_BYTES, rx_done, NULL, 0);
        int rc = libusb_submit_transfer(t);
        if (rc == LIBUSB_ERROR_NO_DEVICE) ev->gone();
        if (rc != 0) { fprintf(stderr, "aic8800: RX submit failed: %s\n", libusb_error_name(rc)); exit(1); }
    }
    while (!a.stopping) {
        struct timeval tv = { 0, reord_pending ? 10000 : 500000 };
        (void)libusb_handle_events_timeout_completed(a.ctx, &tv, NULL);
        reord_tick();
        log_rx_stats();
    }
    return NULL;
}

/* ------------------------------------------------------------ LMAC cmds */

/* 0, -EIO (USB or firmware status) or -ETIMEDOUT */
static int send_cmd(uint16_t msg_id, uint16_t dest, const void *param, uint16_t plen,
                    uint16_t cfm_id, void *cfm_out, uint16_t cfm_max, uint16_t *cfm_len) {
    uint8_t wire[AIC_USB_MSG_MAX_PKT_SIZE];
    size_t wlen = 0;
    if (aic_encode_lmac_msg(wire, sizeof(wire), msg_id, dest, AIC_DRV_TASK_ID, param, plen, &wlen) != 0)
        return -EINVAL;

    pthread_mutex_lock(&a.cmd_serial);
    pthread_mutex_lock(&a.cmd_lock);
    aic_lmac_cmd_matcher_arm(&a.matcher, cfm_id);
    pthread_mutex_unlock(&a.cmd_lock);

    int urc = usb_bulk_out(a.ep_out_msg, a.mps_msg, wire, (int)wlen, AIC_CMD_TX_TIMEOUT_MS);
    int ret = -ETIMEDOUT;
    pthread_mutex_lock(&a.cmd_lock);
    if (urc != 0) {
        ret = -EIO;
    } else {
        struct timespec dl;
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += AIC_CMD_TX_TIMEOUT_MS / 1000;
        while (!a.matcher.completed && !a.stopping) {
            if (pthread_cond_timedwait(&a.cmd_cond, &a.cmd_lock, &dl) == ETIMEDOUT) break;
        }
        if (a.matcher.completed) {
            if (a.matcher.status == 0) {
                if (cfm_len) *cfm_len = a.matcher.rx_param_len;
                if (cfm_out && cfm_max) {
                    uint16_t n = a.matcher.rx_param_len < cfm_max ? a.matcher.rx_param_len : cfm_max;
                    memcpy(cfm_out, a.matcher.rx_param, n);
                }
                ret = 0;
            } else {
                ret = -EIO;
            }
        }
    }
    aic_lmac_cmd_matcher_disarm(&a.matcher);
    pthread_mutex_unlock(&a.cmd_lock);
    pthread_mutex_unlock(&a.cmd_serial);
    if (ret != 0 && getenv("AICD_DEBUG"))
        fprintf(stderr, "aic8800: cmd 0x%04x -> cfm 0x%04x failed (%d, usb=%d)\n", msg_id, cfm_id, ret, urc);
    return ret;
}

#define CMD(id, task, req, cfmid, cfm)                                                     \
    do {                                                                                   \
        uint16_t _l = 0;                                                                   \
        int _r = send_cmd(id, task, req, (uint16_t)(req ? sizeof(*req) : 0),               \
                          cfmid, cfm, (uint16_t)(cfm ? sizeof(*cfm) : 0), &_l);            \
        if (_r != 0 || (cfm && _l < sizeof(*cfm) && (int)(id) != (int)AIC_MM_GET_FW_VERSION_REQ)) { \
            fprintf(stderr, "aic8800: %s failed ret=%d len=%u\n", #id, _r, _l);            \
            return -1;                                                                     \
        }                                                                                  \
    } while (0)

static int bring_up_lmac(void) {
    aic_dbg_mem_read_req_t chip_req = { AIC_DBG_MEM_ADDR_CHIP_ID };
    aic_dbg_mem_read_cfm_t chip_cfm = {0};
    CMD(AIC_DBG_MEM_READ_REQ, AIC_TASK_DBG, &chip_req, AIC_DBG_MEM_READ_CFM, &chip_cfm);
    a.chip_id = chip_cfm.memdata;
    /* a worker that died associated (crash, kill -9) leaves station 0 in the warm firmware: MM_RESET keeps
       it, the next connect fails once and the leaked entry can crash the firmware later. Tear it down the
       way a clean exit does; on a fresh firmware vif 0 is inactive and this only gets its CFM */
    aic_sm_disconnect_req_t dis = { .reason_code = 3, .vif_idx = 0 };
    (void)send_cmd(AIC_SM_DISCONNECT_REQ, AIC_TASK_SM, &dis, sizeof(dis), AIC_SM_DISCONNECT_CFM, NULL, 0, NULL);

    aic_mm_set_stack_start_req_t ss_req = { 1U, 0U, AIC_STACK_START_VENDOR_BIT, 0U };
    aic_mm_set_stack_start_cfm_t ss_cfm = {0};
    CMD(AIC_MM_SET_STACK_START_REQ, AIC_TASK_MM, &ss_req, AIC_MM_SET_STACK_START_CFM, &ss_cfm);
    a.is_5g = ss_cfm.is_5g_support;
    a.vendor_info = ss_cfm.vendor_info;

    uint8_t fwv_req = 0;
    aic_mm_get_fw_version_cfm_t fwv = {0};
    CMD(AIC_MM_GET_FW_VERSION_REQ, AIC_TASK_MM, &fwv_req, AIC_MM_GET_FW_VERSION_CFM, &fwv);
    size_t vl = fwv.fw_version_len < sizeof(fwv.fw_version) ? fwv.fw_version_len : sizeof(fwv.fw_version);
    if (vl > sizeof(a.fw_version) - 1) vl = sizeof(a.fw_version) - 1;
    memset(a.fw_version, 0, sizeof(a.fw_version));
    for (size_t i = 0; i < vl && fwv.fw_version[i]; i++)
        a.fw_version[i] = (fwv.fw_version[i] >= 0x20 && fwv.fw_version[i] <= 0x7e) ? (char)fwv.fw_version[i] : ' ';

    aic_mm_set_txpwr_lvl_req_t pwr = {0};
    aic_fill_d80_txpwr_lvl_v3(&pwr);
    CMD(AIC_MM_SET_TXPWR_IDX_LVL_REQ, AIC_TASK_MM, &pwr, AIC_MM_SET_TXPWR_IDX_LVL_CFM, (uint8_t *)NULL);

    aic_mm_set_rf_calib_req_t cal = {0};
    aic_build_d80_rf_calib_req(&cal);
    CMD(AIC_MM_SET_RF_CALIB_REQ, AIC_TASK_MM, &cal, AIC_MM_SET_RF_CALIB_CFM, (uint8_t *)NULL);

    aic_mm_get_mac_addr_req_t mac_req = { 1U };
    aic_mm_get_mac_addr_cfm_t mac_cfm = {0};
    CMD(AIC_MM_GET_MAC_ADDR_REQ, AIC_TASK_MM, &mac_req, AIC_MM_GET_MAC_ADDR_CFM, &mac_cfm);
    const uint8_t *m = mac_cfm.mac_addr;
    if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) && !(m[0] & 1)) {
        memcpy(a.mac, m, 6);
    } else {
        /* shortcut: two dongles without an eFuse MAC share this address (and its adapter slot);
           derive it from the USB serial or port path if such dongles show up */
        static const uint8_t fallback[6] = { 0x02, 0xa1, 0xc8, 0x80, 0x00, 0x01 };
        memcpy(a.mac, fallback, 6);
    }

    CMD(AIC_MM_RESET_REQ, AIC_TASK_MM, (uint8_t *)NULL, AIC_MM_RESET_CFM, (uint8_t *)NULL);

    aic_mm_version_cfm_t ver = {0};
    CMD(AIC_MM_VERSION_REQ, AIC_TASK_MM, (uint8_t *)NULL, AIC_MM_VERSION_CFM, &ver);
    a.lmac_ver = ver.version_lmac;
    a.fw_features = ver.features;

    aic_me_config_req_t me = {0};
    aic_build_d80_me_config_req(&me, a.fw_features, a.is_5g);
    /* without vht_supp the LMAC ignores the AP's VHT Operation IE and caps the link at HT40 */
    if (a.is_5g && !getenv("AICD_NO_VHT")) me.vht_supp = 1;
    /* AIC firmware does not set the rwnx HE feature bit either; D80 is an 11ax chip */
    if (!getenv("AICD_NO_HE")) me.he_supp = me.he_ul_on = 1;
    /* ps_on/dpsm only make power save available; aic_power_save() switches it */
    CMD(AIC_ME_CONFIG_REQ, AIC_TASK_ME, &me, AIC_ME_CONFIG_CFM, (uint8_t *)NULL);

    aic_me_chan_config_req_t ch = {0};
    aic_build_d80_me_chan_config_req(&ch, a.is_5g);
    CMD(AIC_ME_CHAN_CONFIG_REQ, AIC_TASK_ME, &ch, AIC_ME_CHAN_CONFIG_CFM, (uint8_t *)NULL);

    aic_mm_start_req_t st = {0};
    aic_build_d80_mm_start_req(&st);
    CMD(AIC_MM_START_REQ, AIC_TASK_MM, &st, AIC_MM_START_CFM, (uint8_t *)NULL);

    aic_mm_set_coex_req_t coex = {0};
    aic_build_d80_set_coex_req(&coex);
    CMD(AIC_MM_SET_COEX_REQ, AIC_TASK_MM, &coex, AIC_MM_SET_COEX_CFM, (uint8_t *)NULL);

    aic_mm_add_if_req_t addif = {0};
    aic_mm_add_if_cfm_t addif_cfm = {0};
    aic_build_d80_add_if_sta_req(&addif, a.mac);
    CMD(AIC_MM_ADD_IF_REQ, AIC_TASK_MM, &addif, AIC_MM_ADD_IF_CFM, &addif_cfm);
    if (addif_cfm.status != 0) {
        fprintf(stderr, "aic8800: ADD_IF status=%u\n", addif_cfm.status);
        return -1;
    }
    a.vif_idx = addif_cfm.inst_nbr;

    /* TX + RX A-MPDU on; RX order is restored by the reorder window in on_eth(). AICD_NO_RX_AGG=1 turns RX agg off. */
    aic_mm_set_agg_disable_req_t agg = {0};
    aic_build_d80_agg_enable_req(&agg);
    if (getenv("AICD_NO_RX_AGG")) agg.disable_rx = 1;
    CMD(AIC_MM_SET_AGG_DISABLE_REQ, AIC_TASK_MM, &agg, AIC_MM_SET_AGG_DISABLE_CFM, (uint8_t *)NULL);

    const uint8_t ps_off = 0; /* MM_PS_MODE_OFF: the wifi_drv contract starts with power save off */
    CMD(AIC_ME_SET_PS_MODE_REQ, AIC_TASK_ME, &ps_off, AIC_ME_SET_PS_MODE_CFM, (uint8_t *)NULL);

    fprintf(stderr, "aic8800: features=0x%08x ht=%u vht=%u he=%u ps=%u dpsm=%u bw_max=%u\n", a.fw_features,
            me.ht_supp, me.vht_supp, me.he_supp, me.ps_on, me.dpsm, me.phy_bw_max);
    fprintf(stderr, "aic8800: LMAC ready chip=0x%08x fw=%s lmac=0x%08x 5G=%u mac=%02x:%02x:%02x:%02x:%02x:%02x vif=%u\n",
            a.chip_id, a.fw_version, a.lmac_ver, a.is_5g,
            a.mac[0], a.mac[1], a.mac[2], a.mac[3], a.mac[4], a.mac[5], a.vif_idx);
    return 0;
}

static void on_async_ind(uint16_t id, const uint8_t *param, uint16_t len, void *ctx) {
    (void)ctx;
    if (id == AIC_SCANU_RESULT_IND) {
        aic_scanu_result_ind_hdr_t h;
        if (!param || len < sizeof(h)) return;
        memcpy(&h, param, sizeof(h));
        size_t flen = len - sizeof(h);
        ev->bss(param + sizeof(h), h.length < flen ? h.length : flen, h.center_freq, h.rssi);
    } else if (id == AIC_SCANU_START_CFM) {
        ev->scan_done(false);
    } else if (id == AIC_SM_CONNECT_IND) {
        if (!param || len < offsetof(aic_sm_connect_ind_t, assoc_ie_buf)) return;
        aic_sm_connect_ind_t ind;
        memset(&ind, 0, sizeof(ind));
        memcpy(&ind, param, len < sizeof(ind) ? len : sizeof(ind));
        struct wifi_drv_assoc r = { .status = ind.status_code, .freq = ind.center_freq, .band = ind.band,
                                    .width = ind.width, .qos = ind.qos };
        memcpy(r.bssid, ind.bssid.array, 6);
        a.sta_idx = ind.ap_idx;
        a.qos = ind.qos;
        a.associated = ind.status_code == 0;
        if (!a.associated) reord_reset();
        fprintf(stderr, "aic8800: SM_CONNECT_IND status=%u ap_idx=%u freq=%u width=%u cf1=%u qos=%u at=%.1fms\n", ind.status_code,
                ind.ap_idx, ind.center_freq, ind.width, ind.center_freq1, ind.qos, since_ms(&conn_t0));
        ev->assoc(&r);
    } else if (id == AIC_SM_DISCONNECT_IND) {
        if (!param || len < sizeof(aic_sm_disconnect_ind_t)) return;
        aic_sm_disconnect_ind_t ind;
        memcpy(&ind, param, sizeof(ind));
        a.associated = false;
        reord_reset();
        fprintf(stderr, "aic8800: SM_DISCONNECT_IND reason=%u\n", ind.reason_code);
        ev->disconnected(ind.reason_code);
    }
}

/* -------------------------------------------------------------- TX path */

/* Async TX pool: a synchronous bulk write per frame waits a full USB round trip, which capped upload
   near 1 frame per 125 us microframe (~96 Mbit/s). Keeping TX_XFERS frames queued lets the host
   controller stream them back to back; one endpoint completes in submission order, so order holds. */
#define TX_XFERS 64
static struct libusb_transfer *tx_free[TX_XFERS];
static int tx_nfree = -1; /* -1 = pool not built yet */
static pthread_cond_t tx_cond = PTHREAD_COND_INITIALIZER;

static void LIBUSB_CALL tx_done(struct libusb_transfer *t) {
    pthread_mutex_lock(&a.tx_lock);
    if (t->status == LIBUSB_TRANSFER_COMPLETED) a.tx_pkts++;
    tx_free[tx_nfree++] = t;
    pthread_cond_signal(&tx_cond);
    pthread_mutex_unlock(&a.tx_lock);
}

static pthread_mutex_t tx_serial = PTHREAD_MUTEX_INITIALIZER; /* submit order; tx_lock guards only the pool */

static int aic_tx(const uint8_t *eth, size_t len) {
    pthread_mutex_lock(&tx_serial);
    pthread_mutex_lock(&a.tx_lock);
    if (tx_nfree < 0) {
        for (tx_nfree = 0; tx_nfree < TX_XFERS; ++tx_nfree) {
            struct libusb_transfer *t = libusb_alloc_transfer(0);
            uint8_t *buf = malloc(AIC_DATA_BUF_MAX + 64);
            if (!t || !buf) exit(1);
            libusb_fill_bulk_transfer(t, a.h, a.ep_out_data, buf, 0, tx_done, NULL, 1000);
            tx_free[tx_nfree] = t;
        }
    }
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 1;
    while (tx_nfree == 0 && !a.stopping)
        if (pthread_cond_timedwait(&tx_cond, &a.tx_lock, &dl) == ETIMEDOUT) break;
    struct libusb_transfer *t = tx_nfree > 0 ? tx_free[--tx_nfree] : NULL;
    pthread_mutex_unlock(&a.tx_lock);
    if (!t) { pthread_mutex_unlock(&tx_serial); return -ETIMEDOUT; }

    size_t wlen = 0;
    uint8_t tid = a.qos ? AIC_STA_DEFAULT_TID : AIC_STA_NONQOS_TID;
    int rc = aic_tx_encode_eth_frame(eth, len, a.sta_idx, a.vif_idx, tid, AIC_RWNX_HWQ_BE, 0U, true,
                                     t->buffer, AIC_DATA_BUF_MAX + 64, &wlen) != 0 ? -1 : 0;
    if (rc == 0) {
        t->length = (int)wlen;
        rc = libusb_submit_transfer(t);
        /* rare (len % 512 == 0): the ZLP queues behind the data on the same pipe, so order holds */
        if (rc == 0 && aic_usb_needs_zlp((uint32_t)wlen, a.mps_data)) {
            int done = 0;
            (void)libusb_bulk_transfer(a.h, a.ep_out_data, NULL, 0, &done, 1000);
        }
    }
    if (rc != 0) {
        pthread_mutex_lock(&a.tx_lock);
        tx_free[tx_nfree++] = t;
        pthread_mutex_unlock(&a.tx_lock);
    }
    pthread_mutex_unlock(&tx_serial);
    return rc ? -EIO : 0;
}

/* ------------------------------------------------------------ lifecycle */

/* the first AIC8800 in runtime mode whose interface is free: with several dongles plugged, one that
   another usbwifid worker already claimed fails the claim (LIBUSB_ERROR_ACCESS) and is skipped */
static libusb_device_handle *open_free_aic(void) {
    libusb_device **list;
    libusb_device_handle *h = NULL;
    ssize_t n = libusb_get_device_list(a.ctx, &list);
    for (ssize_t i = 0; i < n && !h; i++) {
        struct libusb_device_descriptor dd;
        if (libusb_get_device_descriptor(list[i], &dd) != 0 || dd.idVendor != AIC_USB_VID_AICS_WIFI ||
            dd.idProduct != AIC_USB_PID_WIFI_BT_RUNTIME || wifi_usb_lock(list[i]) != 0 ||
            libusb_open(list[i], &h) != 0) {
            h = NULL;
            continue;
        }
        if (libusb_claim_interface(h, 0) != 0) { libusb_close(h); h = NULL; }
    }
    if (n > 0) libusb_free_device_list(list, 1);
    return h;
}

static int usb_open(void) {
    /* one context for the process: a new one re-reads every USB device's descriptors over EP0, which
       every 1.5 s (the idle worker's retry) stalls the register I/O of a dongle another worker drives */
    if (!a.ctx && libusb_init(&a.ctx) != 0) return -1;
    a.h = open_free_aic();
    if (!a.h) goto fail;
    struct libusb_config_descriptor *cfg = NULL;
    if (libusb_get_active_config_descriptor(libusb_get_device(a.h), &cfg) != 0) goto fail;
    const struct libusb_interface_descriptor *id = &cfg->interface[0].altsetting[0];
    for (int i = 0; i < id->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *ep = &id->endpoint[i];
        if ((ep->bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK) continue;
        uint16_t mps = ep->wMaxPacketSize & 0x7ff;
        if (ep->bEndpointAddress & 0x80) {
            if (!a.ep_in) a.ep_in = ep->bEndpointAddress;
        } else if (!a.ep_out_data) {
            a.ep_out_data = ep->bEndpointAddress; a.mps_data = mps;
        } else if (!a.ep_out_msg) {
            a.ep_out_msg = ep->bEndpointAddress; a.mps_msg = mps;
        }
    }
    libusb_free_config_descriptor(cfg);
    if (!a.ep_in || !a.ep_out_data) goto fail;
    if (!a.ep_out_msg) { a.ep_out_msg = a.ep_out_data; a.mps_msg = a.mps_data; }
    return 0;
fail:
    if (a.h) libusb_close(a.h);
    a.h = NULL;
    return -1;
}

static int aic_open(const struct wifi_drv_events *events, struct wifi_drv_info *info, int timeout_ms) {
    (void)timeout_ms; /* the firmware loader has already switched the dongle to runtime mode, or not */
    if (usb_open() != 0) return -ENODEV;
    ev = events;
    aic_lmac_cmd_matcher_init(&a.matcher);
    for (int i = 0; i < REORD_POOL; ++i) { rpool[i].next = rfree; rfree = &rpool[i]; }
    reord_reset();
    if (pthread_create(&a.rx_thr, NULL, rx_thread, NULL) != 0) return -ENOMEM;
    if (bring_up_lmac() != 0) {
        fprintf(stderr, "error: LMAC bring-up failed (replug dongle and reload firmware)\n");
        return -EIO;
    }
    memcpy(info->mac, a.mac, 6);
    info->band_5g = a.is_5g != 0;
    snprintf(info->chip, sizeof(info->chip), "AIC8800D80");
    snprintf(info->fw_version, sizeof(info->fw_version), "%s", a.fw_version);
    info->chip_id = a.chip_id;
    info->fw_version_num = a.lmac_ver;
    info->fw_features = a.fw_features;
    return 0;
}

/* ------------------------------------------------------- station control */

static int aic_scan(const uint8_t *ssid, uint8_t ssid_len, const uint16_t *freqs, int n_freqs) {
    aic_scanu_start_req_t req;
    aic_build_scanu_start_req(&req, a.vif_idx, a.is_5g != 0, ssid_len ? ssid : NULL, ssid_len, false);
    if (n_freqs > 0) { /* keep only the requested channels (with their band/flags from the full list) */
        uint8_t k = 0;
        for (uint8_t i = 0; i < req.chan_cnt; ++i)
            for (int j = 0; j < n_freqs; ++j)
                if (req.chan[i].freq == freqs[j]) { req.chan[k++] = req.chan[i]; break; }
        if (k > 0) req.chan_cnt = k;
    }
    return send_cmd(AIC_SCANU_START_REQ, AIC_TASK_SCANU, &req, sizeof(req), AIC_SCANU_START_CFM_ADDTIONAL,
                    NULL, 0, NULL);
}

static int aic_connect(const struct wifi_connect_params *p) {
    aic_sm_connect_req_t r;
    if (p->ie_len > sizeof(r.ie_buf)) return -EINVAL;
    clock_gettime(CLOCK_MONOTONIC, &conn_t0);
    /* stale keys from the previous association make the next 4-way handshake fail (AP never sends msg3);
       Linux deletes them via wpa_supplicant del_key on disconnect */
    for (uint8_t i = 0; i < a.n_hw_keys; ++i) {
        aic_mm_key_del_req_t d = { a.hw_keys[i] };
        (void)send_cmd(AIC_MM_KEY_DEL_REQ, AIC_TASK_MM, &d, sizeof(d), AIC_MM_KEY_DEL_CFM, NULL, 0, NULL);
    }
    a.n_hw_keys = 0;
    a.associated = false;
    reord_reset();

    memset(&r, 0, sizeof(r));
    r.ssid.length = p->ssid_len;
    memcpy(r.ssid.array, p->ssid, p->ssid_len);
    memcpy(r.bssid.array, p->bssid, 6);
    r.vif_idx = a.vif_idx;
    r.chan.band = p->band;
    r.chan.freq = p->freq ? p->freq : (uint16_t)-1;
    r.flags = p->flags;
    r.ctrl_port_ethertype = p->ctrl_port_ethertype;
    r.ie_len = (uint16_t)p->ie_len;
    if (p->ie_len) memcpy(r.ie_buf, p->ie, p->ie_len);
    r.listen_interval = 10;
    r.auth_type = p->auth_type;

    aic_sm_connect_cfm_t cfm = {0};
    uint16_t l = 0;
    int ret = send_cmd(AIC_SM_CONNECT_REQ, AIC_TASK_SM, &r, sizeof(r), AIC_SM_CONNECT_CFM, &cfm, sizeof(cfm), &l);
    fprintf(stderr, "aic8800: connect timing cfm=%.1fms\n", since_ms(&conn_t0));
    if (ret) return ret;
    return l >= sizeof(cfm) ? cfm.status : 0;
}

static void aic_disconnect(uint16_t reason) {
    if (a.associated) {
        aic_me_set_control_port_req_t p = { a.sta_idx, 0 };
        (void)send_cmd(AIC_ME_SET_CONTROL_PORT_REQ, AIC_TASK_ME, &p, sizeof(p), AIC_ME_SET_CONTROL_PORT_CFM, NULL, 0, NULL);
    }
    a.associated = false;
    reord_reset();
    aic_sm_disconnect_req_t d;
    d.reason_code = reason;
    d.vif_idx = a.vif_idx;
    (void)send_cmd(AIC_SM_DISCONNECT_REQ, AIC_TASK_SM, &d, sizeof(d), AIC_SM_DISCONNECT_CFM, NULL, 0, NULL);
}

static int aic_add_key(bool pairwise, uint8_t idx, uint32_t cipher, const uint8_t *key, uint8_t len) {
    const uint8_t suite[4] = { cipher >> 24, cipher >> 16, cipher >> 8, cipher };
    aic_mm_key_add_req_t r;
    memset(&r, 0, sizeof(r));
    if (len > sizeof(r.key.array)) return -EINVAL;
    r.sta_idx = pairwise ? a.sta_idx : 0xFF;
    r.key_idx = pairwise ? 0 : idx;
    r.pairwise = pairwise ? 1 : 0;
    r.inst_nbr = a.vif_idx;
    r.cipher_suite = wifi_cipher_from_suite(suite);
    if (r.cipher_suite == WIFI_CIPHER_INVALID) return -EOPNOTSUPP;
    r.key.length = len;
    memcpy(r.key.array, key, len);
    aic_mm_key_add_cfm_t cfm = {0};
    uint16_t l = 0;
    int ret = send_cmd(AIC_MM_KEY_ADD_REQ, AIC_TASK_MM, &r, sizeof(r), AIC_MM_KEY_ADD_CFM, &cfm, sizeof(cfm), &l);
    if (ret) return ret;
    if (l < sizeof(cfm) || cfm.status != 0) return -EIO;
    bool known = false; /* GTK rekeys reuse the same hw slot */
    for (uint8_t i = 0; i < a.n_hw_keys; ++i) known |= a.hw_keys[i] == cfm.hw_key_idx;
    if (!known && a.n_hw_keys < sizeof(a.hw_keys)) a.hw_keys[a.n_hw_keys++] = cfm.hw_key_idx;
    return 0;
}

static int aic_set_authorized(bool on) {
    aic_me_set_control_port_req_t p = { a.sta_idx, on ? 1 : 0 };
    return send_cmd(AIC_ME_SET_CONTROL_PORT_REQ, AIC_TASK_ME, &p, sizeof(p), AIC_ME_SET_CONTROL_PORT_CFM, NULL, 0, NULL);
}

/* off by default: the AP then holds our frames until the next beacon (~100 ms latency spikes) */
static int aic_power_save(bool on) {
    uint8_t mode = on ? 2U : 0U; /* MM_PS_MODE_ON_DYN : MM_PS_MODE_OFF */
    return send_cmd(AIC_ME_SET_PS_MODE_REQ, AIC_TASK_ME, &mode, 1, AIC_ME_SET_PS_MODE_CFM, NULL, 0, NULL);
}

const struct wifi_drv wifi_drv_aic8800 = {
    .name = "aic8800",
    .open = aic_open,
    .scan = aic_scan,
    .connect = aic_connect,
    .disconnect = aic_disconnect,
    .add_key = aic_add_key,
    .set_authorized = aic_set_authorized,
    .tx = aic_tx,
    .power_save = aic_power_save,
};
