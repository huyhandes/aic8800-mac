/*
 * usbwifi_core.c - the chip-independent station core under usbwifid.
 *
 * Binds one dongle through the first chip driver that finds a free one (wifi_drv.h), keeps the station
 * state the daemon reads (scan list, association, WPA2 EAPOL queue), and bridges data frames to macOS
 * through a feth pair + BPF (same approach as TetherKit): the host side gets DHCP from configd, the
 * peer side is our BPF endpoint.
 */
#include "usbwifi_core.h"

#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "wifi_drv.h"
#include <libusb.h>

extern char **environ;

#define BPF_BUF_BYTES 524288 /* = debug.bpf_maxbufsize; a small buffer drops TX bursts while the USB pool is full */

/* tried in order; each skips dongles another process already holds */
static const struct wifi_drv *const wifi_drivers[] = { &wifi_drv_aic8800, &wifi_drv_rtw89 };
static const struct wifi_drv *drv;

static struct {
    bool started;
    struct wifi_drv_info info;
    pthread_t bpf_thr;
    int bpf_fd;

    /* state (state_lock) */
    pthread_mutex_t state_lock;
    bool scanning, scan_done, associated, link_up;
    uint8_t ap_bssid[6], ap_qos, ap_band, ap_width;
    uint16_t ap_center_freq, assoc_status, disconnect_reason;
    uint8_t target_ssid[AIC_MAC_SSID_LEN], target_ssid_len;
    wifi_scan_bss_t scan_bss[WIFI_MAX_SCAN_BSS];
    uint16_t scan_count;
    wifi_eapol_frame_t eapol_ring[WIFI_EAPOL_RING_CAP];
    uint16_t eapol_head, eapol_tail, eapol_count;
    uint64_t eapol_total, tx_pkts, rx_pkts;
} g = { .bpf_fd = -1, .state_lock = PTHREAD_MUTEX_INITIALIZER };

/* ---------------------------------------------------------------- helpers */

static int run_cmd(const char *path, char *const argv[]) {
    pid_t pid;
    if (posix_spawn(&pid, path, NULL, NULL, argv, environ) != 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static struct timespec conn_t0; /* wifi_connect start, for connect timing logs */
static double since_ms(const struct timespec *t) {
    struct timespec n;
    clock_gettime(CLOCK_MONOTONIC, &n);
    return (double)(n.tv_sec - t->tv_sec) * 1e3 + (double)(n.tv_nsec - t->tv_nsec) / 1e6;
}

char wifi_if_host[16] = "feth80", wifi_if_peer[16] = "feth81";
static int g_slot = -1;
int wifi_slot(void) { return g_slot; }

/* Host side link state mirrors the WiFi link so configd (Network UI) runs DHCP / shows status. */
/* feth link status follows peering, not up/down: unpeer on WiFi loss so configd sees link-down and
   re-runs DHCP on the next network (otherwise it keeps the previous SSID's lease). */
static bool host_up = true; /* unknown at start: the first down always runs */
static void set_host_link(bool up) {
    if (g.bpf_fd < 0) return;
    if (!up && !host_up) return; /* each ifconfig spawn costs connect time; already down */
    host_up = up;
    char *p[] = { "ifconfig", wifi_if_host, "peer", wifi_if_peer, NULL };
    char *np[] = { "ifconfig", wifi_if_host, "-peer", NULL };
    char *a[] = { "ifconfig", wifi_if_host, up ? "up" : "down", NULL };
    (void)run_cmd("/sbin/ifconfig", up ? p : np);
    (void)run_cmd("/sbin/ifconfig", a);
}

/* ------------------------------------------------------- driver events */

static void scan_add(wifi_scan_bss_t bss) {
    pthread_mutex_lock(&g.state_lock);
    int match = -1, weakest = 0;
    for (uint16_t i = 0; i < g.scan_count; i++) {
        if (memcmp(g.scan_bss[i].bssid, bss.bssid, 6) == 0) { match = i; break; }
        if (g.scan_bss[i].rssi < g.scan_bss[weakest].rssi) weakest = i;
    }
    if (match >= 0) {
        wifi_scan_bss_t *o = &g.scan_bss[match];
        if (bss.ssid_len == 0 && o->ssid_len) { bss.ssid_len = o->ssid_len; memcpy(bss.ssid, o->ssid, AIC_MAC_SSID_LEN); }
        if (bss.sec_mask == 0 && o->sec_mask) {
            bss.sec_mask = o->sec_mask; bss.pairwise_cipher = o->pairwise_cipher;
            bss.group_cipher = o->group_cipher; bss.rsn_capab = o->rsn_capab;
        }
        *o = bss;
    } else if (g.scan_count < WIFI_MAX_SCAN_BSS) {
        g.scan_bss[g.scan_count++] = bss;
    } else if (bss.rssi > g.scan_bss[weakest].rssi) {
        g.scan_bss[weakest] = bss;
    }
    pthread_mutex_unlock(&g.state_lock);
}

static void ev_bss(const uint8_t *mgmt, size_t len, uint16_t freq, int8_t rssi) {
    /* the beacon IE parser (wifi_ctl.h) takes the frame behind a scan-result header */
    uint8_t buf[sizeof(aic_scanu_result_ind_hdr_t) + 2400];
    aic_scanu_result_ind_hdr_t h = { .length = (uint16_t)len, .center_freq = freq,
                                     .band = freq > 4000 ? AIC_PHY_BAND_5G : AIC_PHY_BAND_2G4, .rssi = rssi };
    wifi_scan_bss_t bss;
    if (len > sizeof(buf) - sizeof(h)) return;
    memcpy(buf, &h, sizeof(h));
    memcpy(buf + sizeof(h), mgmt, len);
    if (aic_parse_scanu_result_ind(buf, sizeof(h) + len, &bss) == 0) scan_add(bss);
}

static void ev_scan_done(bool aborted) {
    (void)aborted;
    pthread_mutex_lock(&g.state_lock);
    g.scanning = false;
    g.scan_done = true;
    pthread_mutex_unlock(&g.state_lock);
}

static void ev_rx(const uint8_t *eth, size_t len, bool is_eapol) {
    if (len < 14U) return;
    if (is_eapol) {
        if (len > WIFI_EAPOL_MAX_FRAME) return;
        pthread_mutex_lock(&g.state_lock);
        if (g.eapol_count < WIFI_EAPOL_RING_CAP) {
            wifi_eapol_frame_t *s = &g.eapol_ring[g.eapol_tail];
            s->len = (uint16_t)len;
            s->has_frame = 1U;
            s->reserved = 0U;
            memcpy(s->data, eth, len);
            g.eapol_tail = (uint16_t)((g.eapol_tail + 1U) % WIFI_EAPOL_RING_CAP);
            g.eapol_count++;
        }
        g.eapol_total++;
        pthread_mutex_unlock(&g.state_lock);
        return;
    }
    /* BPF write on the peer = frame received by the host interface. */
    if (g.link_up && g.bpf_fd >= 0 && write(g.bpf_fd, eth, len) == (ssize_t)len) g.rx_pkts++;
}

static void ev_assoc(const struct wifi_drv_assoc *a) {
    pthread_mutex_lock(&g.state_lock);
    g.assoc_status = a->status;
    if (a->status == 0) {
        g.associated = true;
        g.ap_qos = a->qos;
        g.ap_band = a->band;
        g.ap_width = a->width;
        g.ap_center_freq = a->freq;
        g.disconnect_reason = 0;
        memcpy(g.ap_bssid, a->bssid, 6);
    } else {
        g.associated = g.link_up = false;
    }
    pthread_mutex_unlock(&g.state_lock);
    fprintf(stderr, "usbwifi: assoc status=%u freq=%u at=%.1fms\n", a->status, a->freq, since_ms(&conn_t0));
}

static void ev_disconnected(uint16_t reason) {
    pthread_mutex_lock(&g.state_lock);
    g.associated = g.link_up = false;
    g.disconnect_reason = reason;
    g.eapol_head = g.eapol_tail = g.eapol_count = 0;
    pthread_mutex_unlock(&g.state_lock);
    fprintf(stderr, "usbwifi: disconnected reason=%u\n", reason);
    set_host_link(false);
}

/* Once a dongle is bound (threads, claimed interface) a fresh process is the only clean reset: exit
   and let the supervisor start a new worker (replug, wake, hard failure). */
static void ev_gone(void) {
    fprintf(stderr, "usbwifi: device gone, exiting\n");
    set_host_link(false);
    exit(1);
}

static const struct wifi_drv_events events = { ev_bss, ev_scan_done, ev_rx, ev_assoc, ev_disconnected, ev_gone };

/* ------------------------------------------------------- feth + BPF side */

/* slot N = the Nth MAC in the adapters file, so a dongle keeps its feth pair, network service and saved
   network across replugs and wakes. Only the one searching worker binds at a time, so one writer. */
static int g_usb_lock = -1;

void wifi_usb_unlock(void) {
    if (g_usb_lock >= 0) close(g_usb_lock);
    g_usb_lock = -1;
}

int wifi_usb_lock(struct libusb_device *dev) {
    uint8_t ports[7];
    char path[128];
    int n = libusb_get_port_numbers(dev, ports, (int)sizeof(ports));
    int o = snprintf(path, sizeof(path), WIFI_RUN_DIR "/usb-%u", libusb_get_bus_number(dev));
    for (int i = 0; i < n && o < (int)sizeof(path); i++)
        o += snprintf(path + o, sizeof(path) - (size_t)o, "%c%u", i ? '.' : '-', ports[i]);
    wifi_usb_unlock();
    (void)mkdir(WIFI_RUN_DIR, 0755);
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return 0; /* not root (e.g. AICD_NO_NET scan): the interface claim still keeps workers apart */
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -EBUSY;
    }
    g_usb_lock = fd;
    return 0;
}

static int assign_slot(void) {
    const uint8_t *m = g.info.mac;
    char mac[18], line[32];
    int n = 0;
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    (void)mkdir(WIFI_CONF_DIR, 0755);
    FILE *f = fopen(WIFI_CONF_DIR "/adapters", "a+");
    if (!f) { fprintf(stderr, "usbwifi: cannot open the adapters file: %s\n", strerror(errno)); return -1; }
    (void)flock(fileno(f), LOCK_EX); /* two workers binding at once must not take the same line */
    rewind(f);                       /* macOS opens "a+" positioned at EOF for reading too */
    while (g_slot < 0 && fgets(line, sizeof(line), f)) {
        if (strncmp(line, mac, 17) == 0) g_slot = n;
        n++;
    }
    if (g_slot < 0 && n < WIFI_MAX_SLOTS && fprintf(f, "%s\n", mac) > 0) g_slot = n;
    fclose(f);
    /* shortcut: slots are never recycled, so the 17th dongle ever seen is refused; prune the file then */
    if (g_slot < 0) { fprintf(stderr, "usbwifi: all %d adapter slots used\n", WIFI_MAX_SLOTS); return -1; }
    snprintf(wifi_if_host, sizeof(wifi_if_host), "feth%d", 80 + 2 * g_slot);
    snprintf(wifi_if_peer, sizeof(wifi_if_peer), "feth%d", 81 + 2 * g_slot);
    fprintf(stderr, "usbwifi: %s is adapter slot %d (%s)\n", mac, g_slot, wifi_if_host);
    return 0;
}

static int setup_feth(void) {
    const uint8_t *m = g.info.mac;
    char mac[24];
    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    /* create may fail if left over from a previous run; that's fine */
    char *c1[] = { "ifconfig", wifi_if_host, "create", NULL };
    char *c2[] = { "ifconfig", wifi_if_peer, "create", NULL };
    (void)run_cmd("/sbin/ifconfig", c1);
    (void)run_cmd("/sbin/ifconfig", c2);
    char *c3[] = { "ifconfig", wifi_if_host, "-peer", NULL };
    (void)run_cmd("/sbin/ifconfig", c3); /* start link-down; set_host_link() peers once WiFi is up */
    char *c4[] = { "ifconfig", wifi_if_host, "lladdr", mac, "down", NULL }; /* up only once WiFi link is up */
    char *c5[] = { "ifconfig", wifi_if_peer, "up", NULL };
    if (run_cmd("/sbin/ifconfig", c4) != 0 || run_cmd("/sbin/ifconfig", c5) != 0) {
        fprintf(stderr, "usbwifi: feth setup failed (need root)\n");
        return -1;
    }

    int fd = -1;
    char dev[16];
    for (int i = 0; i < 256 && fd < 0; i++) {
        snprintf(dev, sizeof(dev), "/dev/bpf%d", i);
        fd = open(dev, O_RDWR);
    }
    if (fd < 0) {
        fprintf(stderr, "usbwifi: no free /dev/bpf (%s)\n", strerror(errno));
        return -1;
    }
    u_int blen = BPF_BUF_BYTES, one = 1, zero = 0;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, wifi_if_peer, sizeof(ifr.ifr_name));
    if (ioctl(fd, BIOCSBLEN, &blen) < 0 || ioctl(fd, BIOCSETIF, &ifr) < 0 ||
        ioctl(fd, BIOCIMMEDIATE, &one) < 0 || ioctl(fd, BIOCPROMISC, NULL) < 0 ||
        ioctl(fd, BIOCSSEESENT, &zero) < 0 || ioctl(fd, BIOCSHDRCMPLT, &one) < 0) {
        fprintf(stderr, "usbwifi: BPF setup failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    g.bpf_fd = fd;
    return 0;
}

static void *bpf_thread(void *arg) {
    (void)arg;
    uint8_t *buf = malloc(BPF_BUF_BYTES);
    while (buf) {
        ssize_t n = read(g.bpf_fd, buf, BPF_BUF_BYTES);
        if (n <= 0) {
            if (n < 0 && errno != EINTR) usleep(10000);
            continue;
        }
        for (uint8_t *p = buf; p < buf + n;) {
            struct bpf_hdr *bh = (struct bpf_hdr *)p;
            const uint8_t *frame = p + bh->bh_hdrlen;
            if (frame + bh->bh_caplen > buf + n) break;
            if (g.link_up && bh->bh_caplen == bh->bh_datalen && bh->bh_caplen >= 14 &&
                drv->tx(frame, bh->bh_caplen) == 0)
                g.tx_pkts++;
            p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
        }
    }
    free(buf);
    return NULL;
}

/* ------------------------------------------------------------ lifecycle */

int wifi_open(io_connect_t *out_conn, io_service_t *out_svc, bool quiet, kern_return_t *out_kr) {
    if (out_kr) *out_kr = KERN_FAILURE;
    if (!g.started) {
        for (size_t i = 0; i < sizeof(wifi_drivers) / sizeof(wifi_drivers[0]) && !drv; i++) {
            memset(&g.info, 0, sizeof(g.info));
            int rc = wifi_drivers[i]->open(&events, &g.info, 1000);
            if (rc == 0) drv = wifi_drivers[i];
            else if (rc != -ENODEV) exit(1); /* half-bound dongle: start over in a fresh process */
        }
        if (!drv) {
            wifi_usb_unlock();
            if (!quiet) fprintf(stderr, "error: no free supported USB WiFi dongle (AIC8800D80 or RTL8852BU)\n");
            return -1; /* not plugged / firmware not loaded yet: caller retries */
        }
        const uint8_t *m = g.info.mac;
        fprintf(stderr, "usbwifi: %s up (%s driver), mac %02x:%02x:%02x:%02x:%02x:%02x\n", g.info.chip, drv->name,
                m[0], m[1], m[2], m[3], m[4], m[5]);
        if (getenv("AICD_NO_NET") == NULL) {
            if (assign_slot() != 0 || setup_feth() != 0) exit(1);
            if (pthread_create(&g.bpf_thr, NULL, bpf_thread, NULL) != 0) exit(1);
        }
        g.started = true;
    }
    if (out_kr) *out_kr = KERN_SUCCESS;
    *out_conn = 1;
    *out_svc = 1;
    return 0;
}

void wifi_ifname(io_service_t svc, char *buf, size_t cap) {
    (void)svc;
    snprintf(buf, cap, "%s", wifi_if_host);
}

/* --------------------------------------------------- control operations */

void wifi_system_woke(void) { if (drv && drv->system_woke) drv->system_woke(); }

const char *wifi_chip_name(void) { return g.started ? g.info.chip : ""; }

kern_return_t wifi_get_status(io_connect_t conn, wifi_status_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    o->version = WIFI_CTL_VERSION;
    pthread_mutex_lock(&g.state_lock);
    o->lmac_ready = g.started;
    o->is_5g_supported = g.info.band_5g;
    o->chip_id = g.info.chip_id;
    o->lmac_version = g.info.fw_version_num;
    o->fw_features = g.info.fw_features;
    memcpy(o->mac_addr, g.info.mac, 6);
    snprintf((char *)o->fw_version, sizeof(o->fw_version), "%s", g.info.fw_version);
    o->tx_packets = g.tx_pkts;
    o->rx_packets = g.rx_pkts;
    o->scanning = g.scanning;
    o->scan_done = g.scan_done;
    o->associated = g.associated;
    o->link_up = g.link_up;
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

kern_return_t wifi_start_scan(io_connect_t conn, const uint8_t *ssid, uint8_t ssid_len,
                              const uint16_t *freqs, int n_freqs) {
    (void)conn;
    if (!g.started) return kIOReturnNotReady;
    pthread_mutex_lock(&g.state_lock);
    g.scan_count = 0;
    g.scan_done = false;
    g.scanning = true;
    memset(g.scan_bss, 0, sizeof(g.scan_bss));
    pthread_mutex_unlock(&g.state_lock);

    int rc = drv->scan(ssid, ssid_len, freqs, n_freqs);
    if (rc) {
        pthread_mutex_lock(&g.state_lock);
        g.scanning = g.scan_done = false;
        pthread_mutex_unlock(&g.state_lock);
    }
    return rc == 0 ? KERN_SUCCESS : rc == -EBUSY ? kIOReturnBusy : kIOReturnError;
}

kern_return_t wifi_get_scan_results(io_connect_t conn, wifi_scan_list_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    pthread_mutex_lock(&g.state_lock);
    o->count = g.scan_count;
    o->scanning = g.scanning;
    o->scan_done = g.scan_done;
    memcpy(o->bss, g.scan_bss, (size_t)g.scan_count * sizeof(wifi_scan_bss_t));
    pthread_mutex_unlock(&g.state_lock);
    return KERN_SUCCESS;
}

kern_return_t wifi_connect(io_connect_t conn, const wifi_connect_req_t *in, wifi_connect_req_t *out) {
    (void)conn;
    if (!g.started) return kIOReturnNotReady;
    if (in->ssid_len == 0 || in->ssid_len > AIC_MAC_SSID_LEN || in->ie_len > WIFI_CONNECT_IE_MAX)
        return kIOReturnBadArgument;
    *out = *in;
    out->out_status = 0xFF;
    clock_gettime(CLOCK_MONOTONIC, &conn_t0);

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
    set_host_link(false);
    fprintf(stderr, "usbwifi: connect timing hostlink=%.1fms\n", since_ms(&conn_t0));

    struct wifi_connect_params p = {
        .freq = in->freq, .band = in->band, .ssid = in->ssid, .ssid_len = in->ssid_len,
        .auth_type = in->auth_type, .flags = in->flags, .ctrl_port_ethertype = in->ctrl_port_ethertype,
        .ie = in->ie_len ? in->ie_buf : NULL, .ie_len = in->ie_len,
    };
    memcpy(p.bssid, in->bssid, 6);
    int rc = drv->connect(&p);
    if (rc < 0) return kIOReturnIOError;
    out->out_status = (uint8_t)rc;
    return KERN_SUCCESS;
}

kern_return_t wifi_disconnect(io_connect_t conn, uint16_t reason) {
    (void)conn;
    if (!g.started) return kIOReturnNotReady;
    pthread_mutex_lock(&g.state_lock);
    g.associated = g.link_up = false;
    g.eapol_head = g.eapol_tail = g.eapol_count = 0;
    pthread_mutex_unlock(&g.state_lock);
    set_host_link(false);
    drv->disconnect(reason ? reason : 3);
    return KERN_SUCCESS;
}

kern_return_t wifi_poll_eapol(io_connect_t conn, wifi_eapol_frame_t *o) {
    (void)conn;
    memset(o, 0, sizeof(*o));
    pthread_mutex_lock(&g.state_lock);
    if (g.eapol_count) {
        *o = g.eapol_ring[g.eapol_head];
        g.eapol_head = (uint16_t)((g.eapol_head + 1U) % WIFI_EAPOL_RING_CAP);
        g.eapol_count--;
    }
    pthread_mutex_unlock(&g.state_lock);
    return KERN_SUCCESS;
}

kern_return_t wifi_send_eapol(io_connect_t conn, const uint8_t *eth, size_t len) {
    (void)conn;
    if (len < 14U || len > WIFI_EAPOL_MAX_FRAME) return kIOReturnBadArgument;
    if (!g.associated) return kIOReturnNotReady;
    return drv->tx(eth, len) == 0 ? KERN_SUCCESS : kIOReturnIOError;
}

/* the 00-0F-AC suite selector of a wifi_ctl.h cipher code (what the WPA2 code hands us) */
static uint32_t cipher_suite(uint8_t cipher) {
    for (uint8_t s = 1; s <= 13; s++) {
        const uint8_t sel[4] = { 0x00, 0x0F, 0xAC, s };
        if (aic_rsn_cipher_suite_to_mac(sel) == cipher) return 0x000FAC00U | s;
    }
    return 0;
}

kern_return_t wifi_add_key(io_connect_t conn, uint8_t key_idx, bool pairwise, uint8_t cipher,
                           const uint8_t *key, uint8_t key_len, uint8_t *out_hw_idx) {
    (void)conn;
    if (!g.started || !g.associated) return kIOReturnNotReady;
    if (key_len > AIC_MAC_SEC_KEY_LEN) return kIOReturnBadArgument;
    const uint32_t suite = cipher_suite(cipher);
    if (!suite) return kIOReturnUnsupported;
    if (out_hw_idx) *out_hw_idx = pairwise ? 0 : key_idx;
    int rc = drv->add_key(pairwise, pairwise ? 0 : key_idx, suite, key, key_len);
    return rc == 0 ? KERN_SUCCESS : rc == -EOPNOTSUPP ? kIOReturnUnsupported : kIOReturnIOError;
}

kern_return_t wifi_set_port_link(io_connect_t conn, bool open_port, bool link_up) {
    (void)conn;
    if (!g.started) return kIOReturnNotReady;
    if (!g.associated && (open_port || link_up)) return kIOReturnNotReady;
    if (drv->set_authorized(open_port) != 0) return kIOReturnNotReady;
    pthread_mutex_lock(&g.state_lock);
    g.link_up = link_up && g.associated;
    bool up = g.link_up;
    pthread_mutex_unlock(&g.state_lock);
    set_host_link(up);
    return KERN_SUCCESS;
}
