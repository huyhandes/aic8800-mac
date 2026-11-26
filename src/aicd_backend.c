/*
 * aicd_backend.c - userspace AIC8800D80 (UGREEN 368b:8d85) driver core.
 *
 * Port of yokitea AIC8800WiFi.kext (BSD-3, see third_party/yokitea/LICENSE)
 * to userspace: libusb for the single vendor interface (IN 0x81 carries both
 * LMAC messages and data; OUT #1 = data, OUT #2 = messages) and a feth pair +
 * BPF for the macOS network side (same approach as TetherKit).
 */
#include "aicd_backend.h"

#include <errno.h>
#include <fcntl.h>
#include <libusb.h>
#include <net/bpf.h>
#include <net/if.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "aic8800_abi.h"
#include "aic8800_framing.h"
#include "aic8800_lmac.h"

extern char **environ;

#define RX_BUF_BYTES  32768
#define BPF_BUF_BYTES 65536

typedef struct {
    bool started;
    libusb_context *ctx;
    libusb_device_handle *h;
    uint8_t ep_in, ep_out_data, ep_out_msg;
    uint16_t mps_data, mps_msg;
    pthread_t rx_thr, bpf_thr;
    volatile bool stopping;

    /* command path */
    pthread_mutex_t cmd_serial;
    pthread_mutex_t cmd_lock;
    pthread_cond_t  cmd_cond;
    aic_lmac_cmd_matcher_t matcher;

    /* state (state_lock) */
    pthread_mutex_t state_lock;
    bool lmac_ready, scanning, scan_done, associated, link_up;
    uint8_t mac[6], ap_bssid[6], ap_sta_idx, ap_qos, ap_band, ap_width, vif_idx, is_5g;
    uint16_t ap_center_freq, assoc_status, disconnect_reason;
    uint8_t target_ssid[AIC_MAC_SSID_LEN], target_ssid_len;
    uint32_t chip_id, lmac_ver, fw_features;
    uint8_t vendor_info;
    uint8_t fw_version[64];
    aic_wifi_scan_bss_t scan_bss[AIC_WIFI_MAX_SCAN_BSS];
    uint16_t scan_count;
    aic_wifi_eapol_frame_t eapol_ring[AIC_WIFI_EAPOL_RING_CAP];
    uint16_t eapol_head, eapol_tail, eapol_count;
    uint64_t eapol_total, tx_pkts, rx_pkts;

    /* network side */
    int bpf_fd;
    pthread_mutex_t tx_lock;
    uint8_t rx_eth_scratch[AIC_DATA_BUF_MAX + 64];
} aicd_t;

static aicd_t g = { .bpf_fd = -1 };

/* ---------------------------------------------------------------- helpers */

static int run_cmd(const char *path, char *const argv[]) {
    pid_t pid;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) != 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int usb_bulk_out(uint8_t ep, uint16_t mps, const uint8_t *buf, int len, unsigned timeout_ms) {
    int done = 0;
    int rc = libusb_bulk_transfer(g.h, ep, (unsigned char *)buf, len, &done, timeout_ms);
    if (rc != 0 || done != len) return rc ? rc : LIBUSB_ERROR_IO;
    if (aic_usb_needs_zlp((uint32_t)len, mps)) {
        rc = libusb_bulk_transfer(g.h, ep, NULL, 0, &done, timeout_ms);
    }
    return rc;
}

/* Host side link state mirrors the WiFi link so configd (Network UI) runs DHCP / shows status. */
static void set_host_link(bool up) {
    if (g.bpf_fd < 0) return;
    char *a[] = { "ifconfig", AICD_IF_HOST, up ? "up" : "down", NULL };
    (void)run_cmd("/sbin/ifconfig", a);
}

/* ------------------------------------------------------------- RX path */

static void on_async_ind(uint16_t id, const uint8_t *param, uint16_t len, void *ctx);

static void enqueue_eapol(const uint8_t *eth, size_t len) {
    if (len < 14U || len > AIC_WIFI_EAPOL_MAX_FRAME) return;
    pthread_mutex_lock(&g.state_lock);
    if (g.eapol_count < AIC_WIFI_EAPOL_RING_CAP) {
        aic_wifi_eapol_frame_t *s = &g.eapol_ring[g.eapol_tail];
        s->len = (uint16_t)len;
        s->has_frame = 1U;
        s->reserved = 0U;
        memcpy(s->data, eth, len);
        g.eapol_tail = (uint16_t)((g.eapol_tail + 1U) % AIC_WIFI_EAPOL_RING_CAP);
        g.eapol_count++;
    }
    g.eapol_total++;
    pthread_mutex_unlock(&g.state_lock);
}

static void on_eth(const uint8_t *eth, size_t len, const aic_rx_frame_meta_t *meta, void *ctx) {
    (void)ctx;
    if (meta && meta->is_eapol) {
        enqueue_eapol(eth, len);
        return;
    }
    if (!g.link_up || g.bpf_fd < 0 || len < 14U) return;
    /* BPF write on the peer = frame received by the host interface. */
    if (write(g.bpf_fd, eth, len) == (ssize_t)len) {
        g.rx_pkts++;
    }
}

static void on_data_chunk(const uint8_t *chunk, size_t len, void *ctx) {
    (void)ctx;
    (void)aic_rx_chunk_to_eth_frames(chunk, len, g.rx_eth_scratch, sizeof(g.rx_eth_scratch), on_eth, NULL);
}

static void on_cfg_pkt(uint8_t type, const uint8_t *payload, size_t len, void *ctx) {
    (void)ctx;
    if (!payload || len > UINT16_MAX) return;
    aic_msg_rx_dispatch_t d;
    memset(&d, 0, sizeof(d));
    d.matcher = &g.matcher;
    d.on_async_ind = on_async_ind;
    pthread_mutex_lock(&g.cmd_lock);
    (void)aic_usb_handle_ctrl_pkt(&d, type, payload, (uint16_t)len);
    if (d.matched_cmd_cfm || g.matcher.completed) pthread_cond_broadcast(&g.cmd_cond);
    pthread_mutex_unlock(&g.cmd_lock);
    if (d.print_ptr && d.print_len > 0U && getenv("AICD_FWLOG")) {
        fprintf(stderr, "[fw] %.*s\n", (int)d.print_len, (const char *)d.print_ptr);
    }
}

static void *rx_thread(void *arg) {
    (void)arg;
    uint8_t *buf = malloc(RX_BUF_BYTES);
    while (buf && !g.stopping) {
        int got = 0;
        int rc = libusb_bulk_transfer(g.h, g.ep_in, buf, RX_BUF_BYTES, &got, 500);
        if (rc == LIBUSB_ERROR_TIMEOUT && got == 0) continue;
        if (rc != 0 && rc != LIBUSB_ERROR_TIMEOUT) {
            if (rc == LIBUSB_ERROR_NO_DEVICE) {
                /* unplugged: dongle returns to stage 0; exit so launchd restarts us for the next plug */
                fprintf(stderr, "aicd: device gone, exiting\n");
                set_host_link(false);
                exit(1);
            }
            usleep(10000);
            continue;
        }
        if (got >= 4) (void)aic_rx_demux_usb_aggr(buf, (size_t)got, on_data_chunk, on_cfg_pkt, NULL);
    }
    free(buf);
    return NULL;
}

/* ------------------------------------------------------------ LMAC cmds */

static kern_return_t send_cmd(uint16_t msg_id, uint16_t dest, const void *param, uint16_t plen,
                              uint16_t cfm_id, void *cfm_out, uint16_t cfm_max, uint16_t *cfm_len) {
    uint8_t wire[AIC_USB_MSG_MAX_PKT_SIZE];
    size_t wlen = 0;
    if (aic_encode_lmac_msg(wire, sizeof(wire), msg_id, dest, AIC_DRV_TASK_ID, param, plen, &wlen) != 0)
        return kIOReturnBadArgument;

    pthread_mutex_lock(&g.cmd_serial);
    pthread_mutex_lock(&g.cmd_lock);
    aic_lmac_cmd_matcher_arm(&g.matcher, cfm_id);
    pthread_mutex_unlock(&g.cmd_lock);

    int urc = usb_bulk_out(g.ep_out_msg, g.mps_msg, wire, (int)wlen, AIC_CMD_TX_TIMEOUT_MS);
    kern_return_t ret = kIOReturnTimeout;
    pthread_mutex_lock(&g.cmd_lock);
    if (urc != 0) {
        ret = kIOReturnIOError;
    } else {
        struct timespec dl;
        clock_gettime(CLOCK_REALTIME, &dl);
        dl.tv_sec += AIC_CMD_TX_TIMEOUT_MS / 1000;
        while (!g.matcher.completed && !g.stopping) {
            if (pthread_cond_timedwait(&g.cmd_cond, &g.cmd_lock, &dl) == ETIMEDOUT) break;
        }
        if (g.matcher.completed) {
            if (g.matcher.status == 0) {
                if (cfm_len) *cfm_len = g.matcher.rx_param_len;
                if (cfm_out && cfm_max) {
                    uint16_t n = g.matcher.rx_param_len < cfm_max ? g.matcher.rx_param_len : cfm_max;
                    memcpy(cfm_out, g.matcher.rx_param, n);
                }
                ret = KERN_SUCCESS;
            } else {
                ret = kIOReturnIOError;
            }
        }
    }
    aic_lmac_cmd_matcher_disarm(&g.matcher);
    pthread_mutex_unlock(&g.cmd_lock);
    pthread_mutex_unlock(&g.cmd_serial);
    if (ret != KERN_SUCCESS && getenv("AICD_DEBUG"))
        fprintf(stderr, "aicd: cmd 0x%04x -> cfm 0x%04x failed (0x%x, usb=%d)\n", msg_id, cfm_id, ret, urc);
    return ret;
}

#define CMD(id, task, req, cfmid, cfm)                                                     \
    do {                                                                                   \
        uint16_t _l = 0;                                                                   \
        kern_return_t _r = send_cmd(id, task, req, (uint16_t)(req ? sizeof(*req) : 0),     \
                                    cfmid, cfm, (uint16_t)(cfm ? sizeof(*cfm) : 0), &_l);  \
        if (_r != KERN_SUCCESS || (cfm && _l < sizeof(*cfm) && (int)(id) != (int)AIC_MM_GET_FW_VERSION_REQ)) { \
            fprintf(stderr, "aicd: %s failed ret=0x%x len=%u\n", #id, _r, _l);             \
            return -1;                                                                     \
        }                                                                                  \
    } while (0)

static int bring_up_lmac(void) {

    aic_dbg_mem_read_req_t chip_req = { AIC_DBG_MEM_ADDR_CHIP_ID };
    aic_dbg_mem_read_cfm_t chip_cfm = {0};
    CMD(AIC_DBG_MEM_READ_REQ, AIC_TASK_DBG, &chip_req, AIC_DBG_MEM_READ_CFM, &chip_cfm);
    g.chip_id = chip_cfm.memdata;

    aic_mm_set_stack_start_req_t ss_req = { 1U, 0U, AIC_STACK_START_VENDOR_BIT, 0U };
    aic_mm_set_stack_start_cfm_t ss_cfm = {0};
    CMD(AIC_MM_SET_STACK_START_REQ, AIC_TASK_MM, &ss_req, AIC_MM_SET_STACK_START_CFM, &ss_cfm);
    g.is_5g = ss_cfm.is_5g_support;
    g.vendor_info = ss_cfm.vendor_info;

    uint8_t fwv_req = 0;
    aic_mm_get_fw_version_cfm_t fwv = {0};
    CMD(AIC_MM_GET_FW_VERSION_REQ, AIC_TASK_MM, &fwv_req, AIC_MM_GET_FW_VERSION_CFM, &fwv);
    size_t vl = fwv.fw_version_len < sizeof(fwv.fw_version) ? fwv.fw_version_len : sizeof(fwv.fw_version);
    if (vl > sizeof(g.fw_version) - 1) vl = sizeof(g.fw_version) - 1;
    memset(g.fw_version, 0, sizeof(g.fw_version));
    for (size_t i = 0; i < vl && fwv.fw_version[i]; i++)
        g.fw_version[i] = (fwv.fw_version[i] >= 0x20 && fwv.fw_version[i] <= 0x7e) ? fwv.fw_version[i] : ' ';

    aic_mm_set_txpwr_lvl_req_t pwr = {0};
    aic_fill_d80_txpwr_lvl_v3(&pwr);
    CMD(AIC_MM_SET_TXPWR_IDX_LVL_REQ, AIC_TASK_MM, &pwr, AIC_MM_SET_TXPWR_IDX_LVL_CFM, (uint8_t *)NULL);

    aic_mm_set_rf_calib_req_t cal = {0};
    aic_mm_set_rf_calib_cfm_t cal_cfm = {0};
    aic_build_d80_rf_calib_req(&cal);
    CMD(AIC_MM_SET_RF_CALIB_REQ, AIC_TASK_MM, &cal, AIC_MM_SET_RF_CALIB_CFM, (uint8_t *)NULL);
    (void)cal_cfm;

    aic_mm_get_mac_addr_req_t mac_req = { 1U };
    aic_mm_get_mac_addr_cfm_t mac_cfm = {0};
    CMD(AIC_MM_GET_MAC_ADDR_REQ, AIC_TASK_MM, &mac_req, AIC_MM_GET_MAC_ADDR_CFM, &mac_cfm);
    const uint8_t *m = mac_cfm.mac_addr;
    if ((m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) && !(m[0] & 1)) {
        memcpy(g.mac, m, 6);
    } else {
        static const uint8_t fallback[6] = { 0x02, 0xa1, 0xc8, 0x80, 0x00, 0x01 };
        memcpy(g.mac, fallback, 6);
    }

    CMD(AIC_MM_RESET_REQ, AIC_TASK_MM, (uint8_t *)NULL, AIC_MM_RESET_CFM, (uint8_t *)NULL);

    aic_mm_version_cfm_t ver = {0};
    CMD(AIC_MM_VERSION_REQ, AIC_TASK_MM, (uint8_t *)NULL, AIC_MM_VERSION_CFM, &ver);
    g.lmac_ver = ver.version_lmac;
    g.fw_features = ver.features;

    aic_me_config_req_t me = {0};
    aic_build_d80_me_config_req(&me, g.fw_features, g.is_5g);
    CMD(AIC_ME_CONFIG_REQ, AIC_TASK_ME, &me, AIC_ME_CONFIG_CFM, (uint8_t *)NULL);

    aic_me_chan_config_req_t ch = {0};
    aic_build_d80_me_chan_config_req(&ch, g.is_5g);
    CMD(AIC_ME_CHAN_CONFIG_REQ, AIC_TASK_ME, &ch, AIC_ME_CHAN_CONFIG_CFM, (uint8_t *)NULL);

    aic_mm_start_req_t st = {0};
    aic_build_d80_mm_start_req(&st);
    CMD(AIC_MM_START_REQ, AIC_TASK_MM, &st, AIC_MM_START_CFM, (uint8_t *)NULL);

    aic_mm_set_coex_req_t coex = {0};
    aic_build_d80_set_coex_req(&coex);
    CMD(AIC_MM_SET_COEX_REQ, AIC_TASK_MM, &coex, AIC_MM_SET_COEX_CFM, (uint8_t *)NULL);

    aic_mm_add_if_req_t addif = {0};
    aic_mm_add_if_cfm_t addif_cfm = {0};
    aic_build_d80_add_if_sta_req(&addif, g.mac);
    CMD(AIC_MM_ADD_IF_REQ, AIC_TASK_MM, &addif, AIC_MM_ADD_IF_CFM, &addif_cfm);
    if (addif_cfm.status != 0) {
        fprintf(stderr, "aicd: ADD_IF status=%u\n", addif_cfm.status);
        return -1;
    }
    g.vif_idx = addif_cfm.inst_nbr;

    /* shortcut: RX A-MPDU disabled so no BlockAck reorder is needed; port aic8800_reord.h if throughput is poor. */
    aic_mm_set_agg_disable_req_t agg = {0};
    aic_build_d80_agg_disable_req(&agg);
    CMD(AIC_MM_SET_AGG_DISABLE_REQ, AIC_TASK_MM, &agg, AIC_MM_SET_AGG_DISABLE_CFM, (uint8_t *)NULL);

    g.lmac_ready = true;
    fprintf(stderr, "aicd: LMAC ready chip=0x%08x fw=%s lmac=0x%08x 5G=%u mac=%02x:%02x:%02x:%02x:%02x:%02x vif=%u\n",
            g.chip_id, (char *)g.fw_version, g.lmac_ver, g.is_5g,
            g.mac[0], g.mac[1], g.mac[2], g.mac[3], g.mac[4], g.mac[5], g.vif_idx);
    return 0;
}

static void on_async_ind(uint16_t id, const uint8_t *param, uint16_t len, void *ctx) {
    (void)ctx;
    if (id == AIC_SCANU_RESULT_IND) {
        aic_wifi_scan_bss_t bss;
        if (aic_parse_scanu_result_ind(param, len, &bss) != 0) return;
        pthread_mutex_lock(&g.state_lock);
        int match = -1, weakest = 0;
        for (uint16_t i = 0; i < g.scan_count; i++) {
            if (memcmp(g.scan_bss[i].bssid, bss.bssid, 6) == 0) { match = i; break; }
            if (g.scan_bss[i].rssi < g.scan_bss[weakest].rssi) weakest = i;
        }
        if (match >= 0) {
            aic_wifi_scan_bss_t *o = &g.scan_bss[match];
            if (bss.ssid_len == 0 && o->ssid_len) { bss.ssid_len = o->ssid_len; memcpy(bss.ssid, o->ssid, AIC_MAC_SSID_LEN); }
            if (bss.sec_mask == 0 && o->sec_mask) {
                bss.sec_mask = o->sec_mask; bss.pairwise_cipher = o->pairwise_cipher;
                bss.group_cipher = o->group_cipher; bss.rsn_capab = o->rsn_capab;
            }
            *o = bss;
        } else if (g.scan_count < AIC_WIFI_MAX_SCAN_BSS) {
            g.scan_bss[g.scan_count++] = bss;
        } else if (bss.rssi > g.scan_bss[weakest].rssi) {
            g.scan_bss[weakest] = bss;
        }
        pthread_mutex_unlock(&g.state_lock);
    } else if (id == AIC_SCANU_START_CFM) {
        pthread_mutex_lock(&g.state_lock);
        g.scanning = false;
        g.scan_done = true;
        pthread_mutex_unlock(&g.state_lock);
    } else if (id == AIC_SM_CONNECT_IND) {
        if (!param || len < offsetof(aic_sm_connect_ind_t, assoc_ie_buf)) return;
        aic_sm_connect_ind_t ind;
        memset(&ind, 0, sizeof(ind));
        memcpy(&ind, param, len < sizeof(ind) ? len : sizeof(ind));
        pthread_mutex_lock(&g.state_lock);
        g.assoc_status = ind.status_code;
        if (ind.status_code == 0) {
            g.associated = true;
            g.ap_sta_idx = ind.ap_idx;
            g.ap_qos = ind.qos;
            g.ap_band = ind.band;
            g.ap_width = ind.width;
            g.ap_center_freq = ind.center_freq;
            g.disconnect_reason = 0;
            memcpy(g.ap_bssid, ind.bssid.array, 6);
        } else {
            g.associated = g.link_up = false;
        }
        pthread_mutex_unlock(&g.state_lock);
        fprintf(stderr, "aicd: SM_CONNECT_IND status=%u ap_idx=%u freq=%u\n", ind.status_code, ind.ap_idx, ind.center_freq);
    } else if (id == AIC_SM_DISCONNECT_IND) {
        if (!param || len < sizeof(aic_sm_disconnect_ind_t)) return;
        aic_sm_disconnect_ind_t ind;
        memcpy(&ind, param, sizeof(ind));
        pthread_mutex_lock(&g.state_lock);
        g.associated = g.link_up = false;
        g.disconnect_reason = ind.reason_code;
        g.eapol_head = g.eapol_tail = g.eapol_count = 0;
        pthread_mutex_unlock(&g.state_lock);
        fprintf(stderr, "aicd: SM_DISCONNECT_IND reason=%u\n", ind.reason_code);
        set_host_link(false);
    }
}

/* -------------------------------------------------------------- TX path */

static int tx_eth(const uint8_t *eth, size_t len, uint8_t sta_idx) {
    uint8_t wire[AIC_DATA_BUF_MAX + 64];
    size_t wlen = 0;
    uint8_t tid = g.ap_qos ? AIC_STA_DEFAULT_TID : AIC_STA_NONQOS_TID;
    if (aic_tx_encode_eth_frame(eth, len, sta_idx, g.vif_idx, tid, AIC_RWNX_HWQ_BE, 0U, true,
                                wire, sizeof(wire), &wlen) != 0)
        return -1;
    pthread_mutex_lock(&g.tx_lock);
    int rc = usb_bulk_out(g.ep_out_data, g.mps_data, wire, (int)wlen, 1000);
    pthread_mutex_unlock(&g.tx_lock);
    if (rc == 0) g.tx_pkts++;
    return rc;
}

/* ------------------------------------------------------- feth + BPF side */

static int setup_feth(void) {
    char mac[24];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             g.mac[0], g.mac[1], g.mac[2], g.mac[3], g.mac[4], g.mac[5]);
    /* create may fail if left over from a previous run; that's fine */
    char *c1[] = { "ifconfig", AICD_IF_HOST, "create", NULL };
    char *c2[] = { "ifconfig", AICD_IF_PEER, "create", NULL };
    (void)run_cmd("/sbin/ifconfig", c1);
    (void)run_cmd("/sbin/ifconfig", c2);
    char *c3[] = { "ifconfig", AICD_IF_HOST, "peer", AICD_IF_PEER, NULL };
    (void)run_cmd("/sbin/ifconfig", c3); /* already peered -> EEXIST */
    char *c4[] = { "ifconfig", AICD_IF_HOST, "lladdr", mac, "down", NULL }; /* up only once WiFi link is up */
    char *c5[] = { "ifconfig", AICD_IF_PEER, "up", NULL };
    if (run_cmd("/sbin/ifconfig", c4) != 0 || run_cmd("/sbin/ifconfig", c5) != 0) {
        fprintf(stderr, "aicd: feth setup failed (need root)\n");
        return -1;
    }

    int fd = -1;
    char dev[16];
    for (int i = 0; i < 256 && fd < 0; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
    }
    if (fd < 0) {
        fprintf(stderr, "aicd: no free /dev/bpf (%s)\n", strerror(errno));
        return -1;
    }
    u_int blen = BPF_BUF_BYTES, one = 1, zero = 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, AICD_IF_PEER, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSBLEN, &blen) < 0 || ioctl(fd, BIOCSETIF, &ifr) < 0 ||
        ioctl(fd, BIOCIMMEDIATE, &one) < 0 || ioctl(fd, BIOCPROMISC, NULL) < 0 ||
        ioctl(fd, BIOCSSEESENT, &zero) < 0 || ioctl(fd, BIOCSHDRCMPLT, &one) < 0) {
        fprintf(stderr, "aicd: BPF setup failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    g.bpf_fd = fd;
    return 0;
}

static void *bpf_thread(void *arg) {
    (void)arg;
    uint8_t *buf = malloc(BPF_BUF_BYTES);
    while (buf && !g.stopping) {
        ssize_t n = read(g.bpf_fd, buf, BPF_BUF_BYTES);
        if (n <= 0) {
            if (n < 0 && errno != EINTR) usleep(10000);
            continue;
        }
        for (uint8_t *p = buf; p < buf + n;) {
            struct bpf_hdr *bh = (struct bpf_hdr *)p;
            const uint8_t *frame = p + bh->bh_hdrlen;
            if (frame + bh->bh_caplen > buf + n) break;
            if (g.link_up && bh->bh_caplen == bh->bh_datalen && bh->bh_caplen >= 14)
                (void)tx_eth(frame, bh->bh_caplen, g.ap_sta_idx);
            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
    free(buf);
    return NULL;
}

/* ------------------------------------------------------------ lifecycle */

static int usb_open(bool quiet) {
    if (libusb_init(&g.ctx) != 0) return -1;
    g.h = libusb_open_device_with_vid_pid(g.ctx, AIC_USB_VID_AICS_WIFI, AIC_USB_PID_WIFI_BT_RUNTIME);
    if (!g.h) {
        if (!quiet) fprintf(stderr, "error: %04x:%04x not found - run aic8800_fwload --once first\n",
                            AIC_USB_VID_AICS_WIFI, AIC_USB_PID_WIFI_BT_RUNTIME);
        goto fail;
    }
    if (libusb_claim_interface(g.h, 0) != 0) {
        if (!quiet) fprintf(stderr, "error: cannot claim interface 0 (another aicd running?)\n");
        goto fail;
    }
    struct libusb_config_descriptor *cfg = NULL;
    if (libusb_get_active_config_descriptor(libusb_get_device(g.h), &cfg) != 0) goto fail;
    const struct libusb_interface_descriptor *id = &cfg->interface[0].altsetting[0];
    for (int i = 0; i < id->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *ep = &id->endpoint[i];
        if ((ep->bmAttributes & 3) != LIBUSB_TRANSFER_TYPE_BULK) continue;
        uint16_t mps = ep->wMaxPacketSize & 0x7ff;
        if (ep->bEndpointAddress & 0x80) {
            if (!g.ep_in) g.ep_in = ep->bEndpointAddress;
        } else if (!g.ep_out_data) {
            g.ep_out_data = ep->bEndpointAddress; g.mps_data = mps;
        } else if (!g.ep_out_msg) {
            g.ep_out_msg = ep->bEndpointAddress; g.mps_msg = mps;
        }
    }
    libusb_free_config_descriptor(cfg);
    if (!g.ep_in || !g.ep_out_data) goto fail;
    if (!g.ep_out_msg) { g.ep_out_msg = g.ep_out_data; g.mps_msg = g.mps_data; }
    return 0;
fail:
    if (g.h) libusb_close(g.h);
    g.h = NULL;
    libusb_exit(g.ctx);
    g.ctx = NULL;
    return -1;
}

int open_wifi_client(io_connect_t *out_conn, io_service_t *out_svc, bool quiet, kern_return_t *out_kr) {
    if (out_kr) *out_kr = KERN_FAILURE;
    /* Once the USB side is live (threads, claimed iface) a fresh process is the only clean
       reset: exit and let launchd KeepAlive restart us (replug, LMAC failure, feth failure). */
    if (g.started) {
        if (!g.lmac_ready) { fprintf(stderr, "aicd: device lost, exiting for restart\n"); exit(1); }
        goto ok;
    }
    static bool inited;
    if (!inited) {
        pthread_mutex_init(&g.cmd_serial, NULL);
        pthread_mutex_init(&g.cmd_lock, NULL);
        pthread_cond_init(&g.cmd_cond, NULL);
        pthread_mutex_init(&g.state_lock, NULL);
        pthread_mutex_init(&g.tx_lock, NULL);
        aic_lmac_cmd_matcher_init(&g.matcher);
        inited = true;
    }

    if (usb_open(quiet) != 0) return -1; /* not plugged / firmware not loaded yet: caller retries */
    if (pthread_create(&g.rx_thr, NULL, rx_thread, NULL) != 0) exit(1);
    if (bring_up_lmac() != 0) {
        fprintf(stderr, "error: LMAC bring-up failed (replug dongle and reload firmware)\n");
        exit(1);
    }
    if (getenv("AICD_NO_NET") == NULL) {
        if (setup_feth() != 0) exit(1);
        if (pthread_create(&g.bpf_thr, NULL, bpf_thread, NULL) != 0) exit(1);
    }
    g.started = true;
ok:
    if (out_kr) *out_kr = KERN_SUCCESS;
    *out_conn = 1;
    *out_svc = 1;
    return 0;
}

void get_bsd_name(io_service_t svc, char *buf, size_t cap) {
    (void)svc;
    snprintf(buf, cap, "%s", AICD_IF_HOST);
}

/* --------------------------------------------------- control operations */

kern_return_t uc_get_status(io_connect_t conn, aic_wifi_status_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    o->version = AIC_WIFI_CTL_VERSION;
    pthread_mutex_lock(&g.state_lock);
    o->lmac_ready = g.lmac_ready;
    o->is_5g_supported = g.is_5g;
    o->vif_idx = g.vif_idx;
    o->chip_id = g.chip_id;
    o->lmac_version = g.lmac_ver;
    o->fw_features = g.fw_features;
    memcpy(o->mac_addr, g.mac, 6);
    memcpy(o->fw_version, g.fw_version,
           sizeof(o->fw_version) < sizeof(g.fw_version) ? sizeof(o->fw_version) : sizeof(g.fw_version));
    o->tx_packets = g.tx_pkts;
    o->rx_packets = g.rx_pkts;
    o->scanning = g.scanning;
    o->scan_done = g.scan_done;
    o->associated = g.associated;
    o->link_up = g.link_up;
    o->ap_sta_idx = g.ap_sta_idx;
    o->ap_qos = g.ap_qos;
    o->ap_band = g.ap_band;
    o->ap_width = g.ap_width;
    o->ap_center_freq = g.ap_center_freq;
    o->assoc_status = g.assoc_status;
    o->disconnect_reason = g.disconnect_reason;
    o->scan_count = g.scan_count;
    o->eapol_rx_queued = g.eapol_count;
    o->eapol_rx_total = g.eapol_total;
    o->ssid_len = g.target_ssid_len;
    memcpy(o->ap_bssid, g.ap_bssid, 6);
    memcpy(o->ssid, g.target_ssid, AIC_MAC_SSID_LEN);
    pthread_mutex_unlock(&g.state_lock);
    return KERN_SUCCESS;
}

kern_return_t uc_start_scan(io_connect_t conn, const uint8_t *ssid, uint8_t ssid_len) {
    (void)conn;
    if (!g.lmac_ready) return kIOReturnNotReady;
    pthread_mutex_lock(&g.state_lock);
    g.scan_count = 0;
    g.scan_done = false;
    g.scanning = true;
    memset(g.scan_bss, 0, sizeof(g.scan_bss));
    pthread_mutex_unlock(&g.state_lock);

    aic_scanu_start_req_t req;
    aic_build_scanu_start_req(&req, g.vif_idx, g.is_5g != 0, ssid_len ? ssid : NULL, ssid_len, false);
    kern_return_t r = send_cmd(AIC_SCANU_START_REQ, AIC_TASK_SCANU, &req, sizeof(req),
                               AIC_SCANU_START_CFM_ADDTIONAL, NULL, 0, NULL);
    if (r != KERN_SUCCESS) {
        pthread_mutex_lock(&g.state_lock);
        g.scanning = g.scan_done = false;
        pthread_mutex_unlock(&g.state_lock);
    }
    return r;
}

kern_return_t uc_get_scan_results(io_connect_t conn, aic_wifi_scan_list_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    pthread_mutex_lock(&g.state_lock);
    o->count = g.scan_count;
    o->scanning = g.scanning;
    o->scan_done = g.scan_done;
    memcpy(o->bss, g.scan_bss, (size_t)g.scan_count * sizeof(aic_wifi_scan_bss_t));
    pthread_mutex_unlock(&g.state_lock);
    return KERN_SUCCESS;
}

kern_return_t uc_connect(io_connect_t conn, const aic_wifi_connect_req_t *in, aic_wifi_connect_req_t *out) {
    (void)conn;
    if (!g.lmac_ready) return kIOReturnNotReady;
    if (in->ssid_len == 0 || in->ssid_len > AIC_MAC_SSID_LEN || in->ie_len > sizeof(((aic_sm_connect_req_t *)0)->ie_buf))
        return kIOReturnBadArgument;
    *out = *in;
    out->out_status = 0xFF;

    pthread_mutex_lock(&g.state_lock);
    g.associated = g.link_up = false;
    g.assoc_status = 0xFFFF;
    g.disconnect_reason = 0;
    g.eapol_head = g.eapol_tail = g.eapol_count = 0;
    g.target_ssid_len = in->ssid_len;
    memset(g.target_ssid, 0, sizeof(g.target_ssid));
    memcpy(g.target_ssid, in->ssid, in->ssid_len);
    memset(g.ap_bssid, 0, 6);
    pthread_mutex_unlock(&g.state_lock);

    aic_sm_connect_req_t r;
    memset(&r, 0, sizeof(r));
    r.ssid.length = in->ssid_len;
    memcpy(r.ssid.array, in->ssid, in->ssid_len);
    memcpy(r.bssid.array, in->bssid, 6);
    r.vif_idx = g.vif_idx;
    r.chan.band = in->band;
    r.chan.freq = in->freq ? in->freq : (uint16_t)-1;
    r.flags = in->flags;
    r.ctrl_port_ethertype = in->ctrl_port_ethertype;
    r.ie_len = in->ie_len;
    memcpy(r.ie_buf, in->ie_buf, in->ie_len);
    r.listen_interval = 10;
    r.auth_type = in->auth_type;

    aic_sm_connect_cfm_t cfm = {0};
    uint16_t l = 0;
    kern_return_t ret = send_cmd(AIC_SM_CONNECT_REQ, AIC_TASK_SM, &r, sizeof(r),
                                 AIC_SM_CONNECT_CFM, &cfm, sizeof(cfm), &l);
    if (ret == KERN_SUCCESS) out->out_status = l >= sizeof(cfm) ? cfm.status : 0;
    return ret;
}

kern_return_t uc_disconnect(io_connect_t conn, uint16_t reason) {
    (void)conn;
    if (!g.lmac_ready) return kIOReturnNotReady;
    pthread_mutex_lock(&g.state_lock);
    bool was = g.associated;
    uint8_t sta = g.ap_sta_idx;
    g.associated = g.link_up = false;
    g.eapol_head = g.eapol_tail = g.eapol_count = 0;
    pthread_mutex_unlock(&g.state_lock);
    if (was) {
        aic_me_set_control_port_req_t p = { sta, 0 };
        (void)send_cmd(AIC_ME_SET_CONTROL_PORT_REQ, AIC_TASK_ME, &p, sizeof(p), AIC_ME_SET_CONTROL_PORT_CFM, NULL, 0, NULL);
    }
    aic_sm_disconnect_req_t d;
    d.reason_code = reason ? reason : 3;
    d.vif_idx = g.vif_idx;
    return send_cmd(AIC_SM_DISCONNECT_REQ, AIC_TASK_SM, &d, sizeof(d), AIC_SM_DISCONNECT_CFM, NULL, 0, NULL);
}

kern_return_t uc_poll_eapol(io_connect_t conn, aic_wifi_eapol_frame_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    pthread_mutex_lock(&g.state_lock);
    if (g.eapol_count) {
        *o = g.eapol_ring[g.eapol_head];
        g.eapol_head = (uint16_t)((g.eapol_head + 1U) % AIC_WIFI_EAPOL_RING_CAP);
        g.eapol_count--;
    }
    pthread_mutex_unlock(&g.state_lock);
    return KERN_SUCCESS;
}

kern_return_t uc_send_eapol(io_connect_t conn, const uint8_t *eth, size_t len) {
    (void)conn;
    if (len < 14U || len > AIC_WIFI_EAPOL_MAX_FRAME) return kIOReturnBadArgument;
    if (!g.associated) return kIOReturnNotReady;
    return tx_eth(eth, len, g.ap_sta_idx) == 0 ? KERN_SUCCESS : kIOReturnIOError;
}

kern_return_t uc_add_key(io_connect_t conn, uint8_t key_idx, bool pairwise, uint8_t cipher,
                         const uint8_t *key, uint8_t key_len, uint8_t *out_hw_idx) {
    (void)conn;
    if (!g.lmac_ready || !g.associated) return kIOReturnNotReady;
    if (key_len > AIC_MAC_SEC_KEY_LEN) return kIOReturnBadArgument;
    aic_mm_key_add_req_t r;
    memset(&r, 0, sizeof(r));
    r.sta_idx = pairwise ? g.ap_sta_idx : 0xFF;
    r.key_idx = pairwise ? 0 : key_idx;
    r.pairwise = pairwise ? 1 : 0;
    r.inst_nbr = g.vif_idx;
    r.cipher_suite = cipher;
    r.key.length = key_len;
    memcpy(r.key.array, key, key_len);
    aic_mm_key_add_cfm_t cfm = {0};
    uint16_t l = 0;
    kern_return_t ret = send_cmd(AIC_MM_KEY_ADD_REQ, AIC_TASK_MM, &r, sizeof(r), AIC_MM_KEY_ADD_CFM, &cfm, sizeof(cfm), &l);
    if (ret != KERN_SUCCESS) return ret;
    if (out_hw_idx) *out_hw_idx = cfm.hw_key_idx;
    return (l >= sizeof(cfm) && cfm.status == 0) ? KERN_SUCCESS : kIOReturnIOError;
}

kern_return_t uc_set_port_link(io_connect_t conn, bool open_port, bool link_up) {
    (void)conn;
    if (!g.lmac_ready) return kIOReturnNotReady;
    if (!g.associated && (open_port || link_up)) return kIOReturnNotReady;
    aic_me_set_control_port_req_t p = { g.ap_sta_idx, open_port ? 1 : 0 };
    kern_return_t ret = send_cmd(AIC_ME_SET_CONTROL_PORT_REQ, AIC_TASK_ME, &p, sizeof(p),
                                 AIC_ME_SET_CONTROL_PORT_CFM, NULL, 0, NULL);
    if (ret != KERN_SUCCESS) return ret;
    pthread_mutex_lock(&g.state_lock);
    g.link_up = link_up && g.associated;
    bool up = g.link_up;
    pthread_mutex_unlock(&g.state_lock);
    set_host_link(up);
    return KERN_SUCCESS;
}
