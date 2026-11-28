/*
 * usbwifid.c - User-space Wi-Fi scan/connect/auto-daemon & WPA2-PSK CLI
 *
 * Connects to AIC8800WiFiUserClient (admin privilege required) via pure public
 * IOKit + CoreFoundation + CommonCrypto APIs.
 *
 * --daemon is a supervisor: it keeps one "--worker" process per plugged dongle plus one more that waits
 * for the next dongle. Each worker drives one dongle and exposes a root:admin (0660) UNIX domain
 * control socket at /var/run/usbwifi/<slot>.sock, so an unprivileged desktop Menu Bar app
 * (USB Wifi.app) can query status, scan, connect, save, and disconnect without sudo prompts while
 * keeping the saved profile root-only (0600).
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>
#include <IOKit/pwr_mgt/IOPMLib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ucred.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <dirent.h>
#include <net/if.h>
#include <unistd.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>

#include "aic8800_abi.h"
#include "aic8800_wifi_ctl.h"
#include "rtl_sae.h"
#include "usbwifi_core.h" /* in-process station core + chip drivers replace the kext */
#include "rtwd.h"

/* per adapter slot: slot 0 keeps the single-dongle wifi.conf, slot N uses wifi-N.conf */
static char g_conf_path[PATH_MAX] = WIFI_CONF_DIR "/wifi.conf";
/* shortcut: the CLI always talks to slot 0, add a --slot flag when someone drives several from a shell */
static char g_sock_path[104] = WIFI_RUN_DIR "/0.sock";
#define WIFI_CONF_PATH g_conf_path
#define WIFI_SOCK_PATH g_sock_path
#define AIC_IPC_BUF_SIZE   32768U

extern char **environ;

static volatile sig_atomic_t g_keep_running = 1;

static void on_sigterm(int sig) {
    (void)sig;
    g_keep_running = 0;
}

/* AIC8800D80 firmware loader (third_party/yokitea/fwload), linked in as the "fwload" subcommand */
int aic_fwload_main(int argc, char **argv);
#define AIC_FWLOAD_DIR WIFI_CONF_DIR "/fw/aic8800D80"
static volatile pid_t g_fwload_pid = 0;

/* Keeps "usbwifid fwload --daemon" running beside the daemon (one launchd job instead of two). It is
   spawned, not just forked: CoreFoundation aborts in a forked child that does not exec. */
static void *fwload_thread(void *arg) {
    (void)arg;
    char self[PATH_MAX];
    uint32_t n = sizeof(self);
    if (_NSGetExecutablePath(self, &n) != 0) return NULL;
    char *av[] = { self, "fwload", "--daemon", "--fw-dir", AIC_FWLOAD_DIR,
                   "--post-wake-delay-ms", "1200", "--usb-settle-timeout-ms", "8000", NULL };
    while (g_keep_running) {
        pid_t pid;
        if (posix_spawn(&pid, self, NULL, NULL, av, environ) == 0) {
            g_fwload_pid = pid;
            int st;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
            g_fwload_pid = 0;
        }
        if (g_keep_running) sleep(5); /* same throttle launchd used to apply */
    }
    return NULL;
}

static void set_err(char *err_buf, size_t err_cap, const char *fmt, ...) {
    if (!err_buf || err_cap == 0U) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_cap, fmt, ap);
    va_end(ap);
}


static int trigger_dhcp(const char *bsd) {
    if (bsd && strncmp(bsd, "feth", 4) == 0) {
        return 0; /* port: the feth80 network service (usbwifi_netsvc) runs DHCP via configd */
    }
    if (!bsd || strcmp(bsd, "unknown") == 0 || strncmp(bsd, "en", 2) != 0) {
        return -1;
    }
    char *argv_dhcp[] = { (char *)"ipconfig", (char *)"set", (char *)bsd, (char *)"DHCP", NULL };
    pid_t pid = 0;
    const int rc = posix_spawn(&pid, "/usr/sbin/ipconfig", NULL, NULL, argv_dhcp, environ);
    if (rc != 0) {
        return -1;
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


static int cmp_bss_rssi_desc(const void *a, const void *b) {
    const wifi_scan_bss_t *ba = (const wifi_scan_bss_t *)a;
    const wifi_scan_bss_t *bb = (const wifi_scan_bss_t *)b;
    if (ba->rssi > bb->rssi) return -1;
    if (ba->rssi < bb->rssi) return 1;
    return 0;
}

static void format_sec_str(uint32_t m, char *buf, size_t cap) {
    if ((m & AIC_SEC_WPA2_PSK) && (m & AIC_SEC_WPA3_SAE)) {
        snprintf(buf, cap, "WPA2/WPA3");
    } else if (m & AIC_SEC_WPA3_SAE) {
        snprintf(buf, cap, "WPA3-SAE");
    } else if ((m & AIC_SEC_WPA2_PSK) && (m & AIC_SEC_WPA_PSK)) {
        snprintf(buf, cap, "WPA/WPA2");
    } else if (m & AIC_SEC_WPA2_PSK) {
        snprintf(buf, cap, (m & AIC_SEC_SHA256) ? "WPA2-SHA256" : "WPA2-PSK");
    } else if (m & AIC_SEC_WPA_PSK) {
        snprintf(buf, cap, "WPA-PSK");
    } else if (m & AIC_SEC_8021X) {
        snprintf(buf, cap, "802.1X");
    } else if (m & AIC_SEC_PRIVACY) {
        snprintf(buf, cap, "WEP/ENC");
    } else {
        snprintf(buf, cap, "OPEN");
    }
}

static int run_scan_and_wait(io_connect_t conn,
                             const uint8_t *ssid,
                             uint8_t ssid_len,
                             const uint16_t *freqs,
                             int n_freqs,
                             wifi_scan_list_t *out_list,
                             char *err_buf,
                             size_t err_cap) {
    kern_return_t kr = wifi_start_scan(conn, ssid, ssid_len, freqs, n_freqs);
    if (kr != KERN_SUCCESS) {
        set_err(err_buf, err_cap, "START_SCAN failed: 0x%08x", kr);
        fprintf(stderr, "error: START_SCAN failed: 0x%08x\n", kr);
        return -1;
    }

    for (int i = 0; i < 3000; ++i) {
        usleep(2000);
        kr = wifi_get_scan_results(conn, out_list);
        if (kr != KERN_SUCCESS) {
            set_err(err_buf, err_cap, "GET_SCAN_RESULTS failed: 0x%08x", kr);
            fprintf(stderr, "error: GET_SCAN_RESULTS failed: 0x%08x\n", kr);
            return -1;
        }
        if (out_list->scan_done || !out_list->scanning) {
            break;
        }
    }

    if (out_list->count > 1U) {
        qsort(out_list->bss, out_list->count, sizeof(wifi_scan_bss_t), cmp_bss_rssi_desc);
    }
    return 0;
}

static int cmd_status(io_connect_t conn, io_service_t svc) {
    wifi_status_t st;
    const kern_return_t kr = wifi_get_status(conn, &st);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "error: GET_STATUS failed: 0x%08x\n", kr);
        return 1;
    }
    char bsd[32];
    wifi_ifname(svc, bsd, sizeof(bsd));

    char ssid_str[33] = {0};
    if (st.ssid_len > 0U && st.ssid_len <= 32U) {
        memcpy(ssid_str, st.ssid, st.ssid_len);
    }

    printf("Interface:   %s (VIF %u)\n", bsd, st.vif_idx);
    printf("MAC:         %02x:%02x:%02x:%02x:%02x:%02x\n",
           st.mac_addr[0], st.mac_addr[1], st.mac_addr[2],
           st.mac_addr[3], st.mac_addr[4], st.mac_addr[5]);
    printf("Firmware:    %s\n", (char *)st.fw_version);
    printf("Chip/LMAC:   0x%08x / 0x%08x (5GHz=%s)\n",
           st.chip_id, st.lmac_version, st.is_5g_supported ? "yes" : "no");
    printf("State:       lmac=%u associated=%u link_up=%u assoc_status=%u disc_reason=%u\n",
           st.lmac_ready, st.associated, st.link_up, st.assoc_status, st.disconnect_reason);
    if (st.associated) {
        printf("Connected:   SSID=\"%s\" BSSID=%02x:%02x:%02x:%02x:%02x:%02x freq=%u MHz (sta_idx=%u)\n",
               ssid_str,
               st.ap_bssid[0], st.ap_bssid[1], st.ap_bssid[2],
               st.ap_bssid[3], st.ap_bssid[4], st.ap_bssid[5],
               st.ap_center_freq, st.ap_sta_idx);
    }
    printf("Counters:    TX=%llu RX=%llu EAPOL_RX=%llu (queued=%u)\n",
           st.tx_packets, st.rx_packets, st.eapol_rx_total, st.eapol_rx_queued);
    return 0;
}

static int cmd_scan(io_connect_t conn) {
    wifi_scan_list_t list;
    char err[160] = {0};
    if (run_scan_and_wait(conn, NULL, 0U, NULL, 0, &list, err, sizeof(err)) != 0) {
        return 1;
    }

    printf("Scan %s: found %u BSS\n", list.scan_done ? "complete" : "partial", list.count);
    printf("%-32s  %-17s  %-5s  %-4s  %s\n", "SSID", "BSSID", "FREQ", "RSSI", "SECURITY");
    for (uint16_t i = 0U; i < list.count; ++i) {
        const wifi_scan_bss_t *b = &list.bss[i];
        char ssid_str[33] = "<hidden>";
        if (b->ssid_len > 0U && b->ssid_len <= 32U) {
            memcpy(ssid_str, b->ssid, b->ssid_len);
            ssid_str[b->ssid_len] = '\0';
        }
        char sec_str[20];
        format_sec_str(b->sec_mask, sec_str, sizeof(sec_str));
        printf("%-32s  %02x:%02x:%02x:%02x:%02x:%02x  %4u   %4d  %s\n",
               ssid_str,
               b->bssid[0], b->bssid[1], b->bssid[2], b->bssid[3], b->bssid[4], b->bssid[5],
               b->freq, (int)b->rssi, sec_str);
    }
    return 0;
}

/* one per dongle, named like its profile (band, band-N): "5", "2.4", anything else (or none) = auto */
static char g_band_path[PATH_MAX] = WIFI_CONF_DIR "/band";
#define WIFI_BAND_PATH g_band_path
static const char *band_pref(void) {
    char v[8] = "";
    FILE *f = fopen(WIFI_BAND_PATH, "r");
    if (f) { (void)fscanf(f, "%7s", v); fclose(f); }
    return strcmp(v, "5") == 0 ? "5" : strcmp(v, "2.4") == 0 ? "2.4" : "auto";
}

/* one per dongle (powersave, powersave-N): "on" turns the chip's power save on, anything else = off */
static char g_ps_path[PATH_MAX] = WIFI_CONF_DIR "/powersave";
/* one per dongle (chans, chans-N): the channels of the last scan that found the SSID, "freq freq ...\nSSID",
   so a replugged dongle's fresh worker does the 0.2 s known-channel scan */
static char g_chans_path[PATH_MAX] = WIFI_CONF_DIR "/chans";
static bool ps_pref(void) {
    char v[8] = "";
    FILE *f = fopen(g_ps_path, "r");
    if (f) { (void)fscanf(f, "%7s", v); fclose(f); }
    return strcmp(v, "on") == 0;
}
static void apply_power_save(void) {
    const bool on = ps_pref();
    const int r = wifi_set_power_save(on);
    if (r && r != -EOPNOTSUPP) fprintf(stderr, "warn: power save %s failed (%d)\n", on ? "on" : "off", r);
}

/* one per dongle (macrandom, macrandom-N): "off" keeps the dongle's own address, anything else (or none)
   connects with a random address per network, like Windows "MAC Randomization" */
static char g_mr_path[PATH_MAX] = WIFI_CONF_DIR "/macrandom";
static bool mr_pref(void) {
    char v[8] = "";
    FILE *f = fopen(g_mr_path, "r");
    if (f) { (void)fscanf(f, "%7s", v); fclose(f); }
    return strcmp(v, "off") != 0;
}
/* shared by all dongles; link() so two workers creating it at once agree on one */
static bool mac_secret(uint8_t s[32]) {
    const char *path = WIFI_CONF_DIR "/macsecret";
    char hex[65] = "";
    FILE *f = fopen(path, "r");
    if (!f) {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s.%d", path, (int)getpid());
        (void)mkdir(WIFI_CONF_DIR, 0755);
        arc4random_buf(s, 32);
        FILE *w = fopen(tmp, "w");
        if (w) {
            (void)fchmod(fileno(w), 0600);
            for (int i = 0; i < 32; i++) fprintf(w, "%02x", s[i]);
            fclose(w);
            (void)link(tmp, path);
            (void)unlink(tmp);
        }
        f = fopen(path, "r");
    }
    const bool ok = f && fscanf(f, "%64[0-9a-f]", hex) == 1 && strlen(hex) == 64;
    if (f) fclose(f);
    for (int i = 0; ok && i < 32; i++) (void)sscanf(hex + 2 * i, "%2hhx", &s[i]);
    return ok;
}
static void apply_mac(const char *ssid, size_t ssid_len) {
    uint8_t s[32], m[6];
    if (!wifi_has_set_mac()) return;
    const bool rnd = mr_pref() && mac_secret(s);
    if (rnd) rtl_random_mac(s, wifi_slot() < 0 ? 0 : wifi_slot(), (const uint8_t *)ssid, ssid_len, m);
    const int r = wifi_set_mac(rnd ? m : NULL);
    if (r) fprintf(stderr, "warn: station address change failed (%d), keeping the current one\n", r);
}

/* each slot runs its own worker: write and rename so two commands never interleave */
static bool write_pref(const char *path, const char *v) {
    (void)mkdir(WIFI_CONF_DIR, 0755);
    char tmp[PATH_MAX + 16];
    snprintf(tmp, sizeof(tmp), "%s.%d", path, (int)getpid());
    FILE *f = fopen(tmp, "w");
    bool ok = f != NULL;
    if (f) {
        ok = fprintf(f, "%s\n", v) > 0;
        ok = fclose(f) == 0 && ok;
    }
    ok = ok && rename(tmp, path) == 0;
    if (!ok) (void)unlink(tmp);
    return ok;
}

/* the channels this SSID was last seen on, so a rescan takes ~0.2 s instead of ~3 s */
static char     known_ssid[33];
static uint16_t known_freqs[8];
static int      n_known;
/* reconnect to the BSS of the last successful join without scanning; cleared on any failure.
   A roam puts its target here and drops the link. */
static wifi_scan_bss_t last_bss;
static bool have_last;
static ft_state_t g_ft; /* RTL FT-PSK (wifi_has_ft): the PMK-R0 a roam within the mobility domain reuses */
static uint8_t ft_prev[6]; /* the BSS roam_check left, for the reassociation's current AP field */
static bool ft_roam, ft_off; /* ft_off: a first FT association failed, so plain PSK from now on */
/* shortcut: SAE failing once on a WPA2/WPA3 AP means WPA2-PSK there until the daemon restarts */
static bool sae_off;

/* auto: 5 GHz unless it is >15 dB weaker or below -75 dBm; a chosen band wins while above -80 dBm */
static int band_score(const wifi_scan_bss_t *b, const char *pref) {
    const bool is5 = b->freq >= 5000U;
    if (strcmp(pref, "auto") == 0) return b->rssi + ((is5 && b->rssi > -75) ? 15 : 0);
    return b->rssi + (((pref[0] == '5') == is5 && b->rssi > -80) ? 100 : 0);
}

/* one per dongle (roam, roam-N): Windows "Roaming Sensitivity Level". Below the level's signal the worker
   rescans the known channels and moves to a same-SSID BSS that scores ROAM_MARGIN dB better. */
static char g_roam_path[PATH_MAX] = WIFI_CONF_DIR "/roam";
static const char *const roam_names[] = { "VeryHigh", "High", "Middle", "Low", "VeryLow", "Disable" };
#define ROAM_MARGIN 8
static int roam_level(void) { /* index into roam_names, VeryHigh when unset */
    char v[16] = "";
    FILE *f = fopen(g_roam_path, "r");
    if (f) { (void)fscanf(f, "%15s", v); fclose(f); }
    for (int i = 0; i < 6; i++) if (strcmp(v, roam_names[i]) == 0) return i;
    return 0;
}
/* true when it dropped the link to move to a better BSS: the caller reconnects to last_bss without a scan */
static bool roam_check(io_connect_t conn, const wifi_status_t *st) {
    static uint64_t next_ms;
    static int wait_ms = 15000;
    uint16_t hf[8];
    uint8_t hb[6];
    bool btm; /* 11v: the AP asked us to move (and the driver already said yes), so no threshold or margin */
    const int nh = wifi_roam_hint(hf, hb, &btm);
    for (int i = 0; i < nh; i++) { /* 11k/11v channels join the known ones */
        int k = 0;
        while (k < n_known && known_freqs[k] != hf[i]) k++;
        if (k == n_known && n_known < 8) known_freqs[n_known++] = hf[i];
    }
    const int rssi = wifi_get_rssi();
    const uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ULL;
    const int lvl = rssi < -60 ? roam_level() : 5;
    if (n_known == 0) return false;
    if (!btm && (rssi == 0 || lvl == 5 || rssi >= -60 - 5 * lvl)) {
        wait_ms = 15000; /* signal is fine again: the next dip scans soon */
        next_ms = 0;
        return false;
    }
    if (!btm && now < next_ms) return false;
    wifi_scan_list_t list;
    if (run_scan_and_wait(conn, (const uint8_t *)known_ssid, (uint8_t)strlen(known_ssid), known_freqs, n_known,
                          &list, NULL, 0U) != 0) {
        next_ms = now + (uint64_t)wait_ms;
        return false;
    }
    const char *pref = band_pref();
    wifi_scan_bss_t cur = { .freq = st->ap_center_freq, .rssi = (int8_t)rssi };
    const wifi_scan_bss_t *best = NULL;
    bool pinned = false; /* the AP's BTM target was seen */
    const size_t ssid_len = strlen(known_ssid);
    for (uint16_t i = 0U; i < list.count; ++i) {
        const wifi_scan_bss_t *b = &list.bss[i];
        if (b->ssid_len != ssid_len || memcmp(b->ssid, known_ssid, ssid_len) != 0) continue;
        if (memcmp(b->bssid, st->ap_bssid, 6) == 0) { cur.rssi = b->rssi; continue; } /* same scan, fair compare */
        if ((last_bss.sec_mask & AIC_SEC_WPA2_PSK) && !(b->sec_mask & AIC_SEC_WPA2_PSK)) continue; /* last_bss = now */
        if (pinned) continue;
        if (btm && memcmp(b->bssid, hb, 6) == 0) pinned = true;
        if (pinned || !best || band_score(b, pref) > band_score(best, pref)) best = b;
    }
    if (!best || (!btm && band_score(best, pref) < band_score(&cur, pref) + ROAM_MARGIN)) {
        next_ms = now + (uint64_t)wait_ms;
        if (wait_ms < 240000) wait_ms *= 2; /* one AP and a weak spot: don't keep going off channel */
        return false;
    }
    printf("roam: %d dBm on %u MHz -> %02x:%02x:%02x:%02x:%02x:%02x %d dBm on %u MHz (%s)\n",
           (int)cur.rssi, cur.freq, best->bssid[0], best->bssid[1], best->bssid[2], best->bssid[3],
           best->bssid[4], best->bssid[5], (int)best->rssi, best->freq, btm ? "BSS transition request" : roam_names[lvl]);
    last_bss = *best;
    have_last = true;
    memcpy(ft_prev, st->ap_bssid, 6);
    ft_roam = true;
    wait_ms = 15000;
    next_ms = now + 15000; /* settle on the new AP before judging it */
    (void)wifi_disconnect(conn, 3U);
    return true;
}

static int install_keys(io_connect_t conn, const aic_wpa2_ctx_t *c, char *err_buf, size_t err_cap) {
    uint8_t hw_idx = 0U;
    kern_return_t kr = wifi_add_key(conn, 0U, true, c->pairwise_cipher, &c->ptk[32], 16U, &hw_idx);
    if (kr != KERN_SUCCESS) {
        set_err(err_buf, err_cap, "Install PTK failed: 0x%08x", kr);
        fprintf(stderr, "error: install PTK failed: 0x%08x\n", kr);
        return 1;
    }
    printf("      Installed PTK (hw_key_idx=%u)\n", hw_idx);
    if (c->has_gtk) {
        kr = wifi_add_key(conn, c->gtk_idx, false, c->group_cipher, c->gtk, c->gtk_len, &hw_idx);
        if (kr != KERN_SUCCESS) {
            set_err(err_buf, err_cap, "Install GTK failed: 0x%08x", kr);
            fprintf(stderr, "error: install GTK failed: 0x%08x\n", kr);
            return 1;
        }
        printf("      Installed GTK idx=%u (hw_key_idx=%u)\n", c->gtk_idx, hw_idx);
    }
    return 0;
}

/* RTL with PMF: the IGTK from an accepted M3 or group M1, so mlme can check BIP on broadcast deauth/disassoc.
   Sent again on every group handshake: mlme keeps the replay counter of a key it already holds. */
static void install_igtk(io_connect_t conn, const aic_wpa2_ctx_t *c, const uint8_t *eth, size_t len) {
    uint8_t k[22], hw_idx = 0U;
    const int id = wifi_has_ft() ? rtl_igtk(c, eth, len, k) : 0;
    if (id && wifi_add_key(conn, (uint8_t)id, false, AIC_CIPHER_BIP_CMAC_128, k, sizeof(k), &hw_idx) == KERN_SUCCESS) {
        printf("      Installed IGTK idx=%d\n", id);
    }
}

static int perform_connect(io_connect_t conn,
                           io_service_t svc,
                           const char *ssid_arg,
                           const char *passphrase,
                           bool run_dhcp,
                           aic_wpa2_ctx_t *out_wpa_ctx,
                           bool *out_is_open,
                           char *err_buf,
                           size_t err_cap) {
    if (err_buf && err_cap > 0U) {
        err_buf[0] = '\0';
    }
    const size_t ssid_len = strlen(ssid_arg);
    if (ssid_len == 0U || ssid_len > 32U) {
        set_err(err_buf, err_cap, "Invalid SSID length");
        fprintf(stderr, "error: invalid SSID length\n");
        return 1;
    }
    apply_mac(ssid_arg, ssid_len); /* before scanning: the probes and the join use the same address */
    const bool roaming = ft_roam;
    ft_roam = false;

    wifi_status_t st;
    if (wifi_get_status(conn, &st) != KERN_SUCCESS || !st.lmac_ready) {
        set_err(err_buf, err_cap, "LMAC firmware not ready");
        fprintf(stderr, "error: LMAC not ready\n");
        return 1;
    }

    /* A full scan (38 channels, DFS ones passive) takes ~3 s; rescan only the channels this SSID was last
       seen on (~0.2 s) and fall back to the full scan when it is not there. */
    if (n_known == 0) {
        char line[128], name[40];
        FILE *f = fopen(g_chans_path, "r");
        if (f && fgets(line, sizeof(line), f) && fgets(name, sizeof(name), f)) {
            name[strcspn(name, "\n")] = '\0';
            char *p = line, *end;
            for (long v; n_known < 8 && (v = strtol(p, &end, 10)) > 0 && v < 8000; p = end)
                known_freqs[n_known++] = (uint16_t)v;
            snprintf(known_ssid, sizeof(known_ssid), "%s", name);
        }
        if (f) fclose(f);
    }
    const bool fast = n_known > 0 && strcmp(known_ssid, ssid_arg) == 0;
    wifi_scan_list_t list;
    const wifi_scan_bss_t *target = NULL;
    const char *pref = band_pref();
    const bool last_band_ok = strcmp(pref, "auto") == 0 || (pref[0] == '5') == (last_bss.freq >= 5000U);
    /* with a passphrase only a WPA2 BSS will do: a same-named open AP must not get the traffic */
    const bool sec_ok = !passphrase || (last_bss.sec_mask & AIC_SEC_WPA2_PSK) != 0U;
    if (fast && have_last && last_band_ok && sec_ok && !getenv("AICD_ALWAYS_SCAN")) {
        printf("[1/4] Reusing last BSS for \"%s\" (no scan)...\n", ssid_arg);
        target = &last_bss;
    }
    have_last = false;
    for (int pass = fast ? 0 : 1; pass < 2 && !target; ++pass) {
        printf("[1/4] Scanning for \"%s\"%s...\n", ssid_arg, pass == 0 ? " (known channels)" : "");
        if (run_scan_and_wait(conn, (const uint8_t *)ssid_arg, (uint8_t)ssid_len,
                              pass == 0 ? known_freqs : NULL, pass == 0 ? n_known : 0,
                              &list, err_buf, err_cap) != 0) {
            return 1;
        }
        int best = -1000;
        n_known = 0;
        for (uint16_t i = 0U; i < list.count; ++i) {
            const wifi_scan_bss_t *b = &list.bss[i];
            if (b->ssid_len != ssid_len || memcmp(b->ssid, ssid_arg, ssid_len) != 0) continue;
            if (passphrase && !(b->sec_mask & AIC_SEC_WPA2_PSK)) continue;
            const int score = band_score(b, pref);
            if (score > best) { best = score; target = b; }
            bool dup = false;
            for (int k = 0; k < n_known; ++k) dup |= known_freqs[k] == b->freq;
            if (!dup && n_known < 8) known_freqs[n_known++] = b->freq;
        }
        snprintf(known_ssid, sizeof(known_ssid), "%s", ssid_arg);
        if (target) {
            char v[128];
            int len = 0;
            for (int k = 0; k < n_known; ++k) len += snprintf(v + len, sizeof(v) - (size_t)len, "%u ", known_freqs[k]);
            snprintf(v + len, sizeof(v) - (size_t)len, "\n%s", ssid_arg);
            (void)write_pref(g_chans_path, v);
        }
    }
    if (!target) {
        set_err(err_buf, err_cap, "Network \"%s\" not found", ssid_arg);
        fprintf(stderr, "error: AP \"%s\" not found in %u scan results\n", ssid_arg, list.count);
        return 1;
    }

    char sec_str[20];
    format_sec_str(target->sec_mask, sec_str, sizeof(sec_str));
    printf("      Found BSSID=%02x:%02x:%02x:%02x:%02x:%02x freq=%u MHz rssi=%d dBm sec=%s\n",
           target->bssid[0], target->bssid[1], target->bssid[2],
           target->bssid[3], target->bssid[4], target->bssid[5],
           target->freq, (int)target->rssi, sec_str);

    const bool is_open = (target->sec_mask & (AIC_SEC_PRIVACY | AIC_SEC_WPA_PSK | AIC_SEC_WPA2_PSK | AIC_SEC_WPA3_SAE | AIC_SEC_8021X)) == 0U;
    const bool has_wpa2 = (target->sec_mask & AIC_SEC_WPA2_PSK) != 0U;
    /* WPA3-SAE (with PMF) when the driver connects through ft_connect (RTL); WPA2-PSK after SAE failed once */
    const bool try_sae = (target->sec_mask & AIC_SEC_WPA3_SAE) && wifi_has_ft() && !(sae_off && has_wpa2);

    if (!is_open && !has_wpa2 && !try_sae) {
        set_err(err_buf, err_cap, "Unsupported security: %s (needs OPEN or WPA2-PSK)", sec_str);
        fprintf(stderr, "error: security mode '%s' is not supported (requires OPEN or WPA2-PSK/Mixed)\n",
                sec_str);
        return 1;
    }

    uint8_t pmk[32] = {0};
    uint8_t rsn_ie[22] = {0};
    size_t rsn_ie_len = 0U;
    if (!is_open) {
        if (!passphrase || strlen(passphrase) < 8U) {
            set_err(err_buf, err_cap, "Passphrase required (8..63 chars) for %s", sec_str);
            fprintf(stderr, "error: valid 8..63 char passphrase required for %s\n", sec_str);
            return 1;
        }
        if (aic_wpa2_derive_pmk(passphrase, strlen(passphrase),
                                target->ssid, target->ssid_len, pmk) != 0) {
            set_err(err_buf, err_cap, "PBKDF2 passphrase derivation failed");
            fprintf(stderr, "error: PBKDF2 passphrase derivation failed\n");
            return 1;
        }
        const uint8_t grp = (target->group_cipher != AIC_CIPHER_INVALID) ? target->group_cipher : AIC_CIPHER_CCMP;
        rsn_ie_len = aic_build_wpa2_rsn_ie(rsn_ie, grp, false);
    }

    /* FT-PSK when the driver has it: the driver says unsupported, before authenticating, when the AP has no FT */
    const bool try_ft = !is_open && !try_sae && wifi_has_ft() && !ft_off;
    const bool ft_reassoc = try_ft && roaming && g_ft.ok && target == &last_bss && memcmp(g_ft.sta, st.mac_addr, 6) == 0;
    g_ft.ok = false; /* a failed FT roam must not be retried: the next attempt authenticates in full */
    struct wifi_ft ft = { .arg = &g_ft, .reassoc_ie = ft_reassoc_ie };
    uint8_t ft_auth[40 + 5 + 2 + 82 + 2 + 48];
    if (try_ft) {
        rsn_ie[19] = 4U; /* AKM 00-0f-ac:4, FT-PSK */
        memcpy(ft.md, g_ft.md, 3U);
    }
    sae_t sae;
    struct wifi_ft sae_ft = { .sae = sae_step, .arg = &sae };
    if (try_sae) {
        if (sae_init(&sae, st.mac_addr, target->bssid, target->ssid, target->ssid_len, passphrase, strlen(passphrase)) != 0) {
            set_err(err_buf, err_cap, "SAE password element not found");
            fprintf(stderr, "error: SAE password element derivation failed\n");
            return 1;
        }
        rsn_ie[19] = 8U;    /* AKM 00-0f-ac:8, SAE */
        rsn_ie[20] |= 0x80U; /* MFPC: WPA3 needs PMF */
        sae_off = has_wpa2; /* cleared once SAE associates */
    }
    if (ft_reassoc) {
        ft.auth_ie = ft_auth;
        ft.auth_len = ft_auth_ie(&g_ft, target->bssid, ft_auth);
        memcpy(ft.prev_bssid, ft_prev, 6U);
    }

    printf("[2/4] Associating via SM_CONNECT_REQ...\n");
    wifi_connect_req_t creq;
    wifi_connect_req_t cresp;
    memset(&cresp, 0, sizeof(cresp)); /* read in the error message even when wifi_connect fails early */
    memset(&creq, 0, sizeof(creq));
    creq.ssid_len = target->ssid_len;
    memcpy(creq.ssid, target->ssid, target->ssid_len);
    memcpy(creq.bssid, target->bssid, AIC_MAC_ADDR_LEN);
    creq.band      = target->band;
    creq.freq      = target->freq;
    creq.auth_type = 0U;
    if (!is_open) {
        creq.flags               = AIC_CONTROL_PORT_HOST | AIC_WPA_WPA2_IN_USE;
        creq.ctrl_port_ethertype = htons(AIC_EAPOL_ETHERTYPE);
        creq.ie_len              = (uint16_t)rsn_ie_len;
        memcpy(creq.ie_buf, rsn_ie, rsn_ie_len);
    }

    kern_return_t kr = try_sae ? wifi_connect_ft(conn, &creq, &cresp, &sae_ft)
                     : try_ft ? wifi_connect_ft(conn, &creq, &cresp, &ft) : kIOReturnUnsupported;
    const bool use_ft = try_ft && kr != kIOReturnUnsupported;
    if (!use_ft && !try_sae) {
        rsn_ie[19] = creq.ie_buf[19] = 2U;
        kr = wifi_connect(conn, &creq, &cresp);
    } else if (!ft_reassoc) {
        /* shortcut: any failure of a first FT association (also a timeout) means plain PSK until the daemon restarts */
        ft_off = true;
    }
    if (kr != KERN_SUCCESS || cresp.out_status != 0U) {
        set_err(err_buf, err_cap, "SM_CONNECT_REQ failed (status=%u)", cresp.out_status);
        fprintf(stderr, "error: SM_CONNECT_REQ failed kr=0x%08x fw_status=%u\n", kr, cresp.out_status);
        return 1;
    }

    bool assoc_ok = false;
    for (int i = 0; i < 3000; ++i) {
        usleep(2000);
        if (wifi_get_status(conn, &st) == KERN_SUCCESS) {
            if (st.associated) {
                assoc_ok = true;
                break;
            }
            if (st.assoc_status != 0xFFFFU && st.assoc_status != 0U) {
                set_err(err_buf, err_cap, "Association rejected (status=%u)", st.assoc_status);
                fprintf(stderr, "error: association rejected status_code=%u\n", st.assoc_status);
                return 1;
            }
        }
    }
    if (!assoc_ok) {
        set_err(err_buf, err_cap, "Timed out waiting for association");
        fprintf(stderr, "error: timed out waiting for SM_CONNECT_IND\n");
        return 1;
    }
    const bool h2e = try_sae && sae.h2e; /* read before the wipe below */
    if (try_sae) {
        memcpy(pmk, sae.pmk, sizeof(pmk));
        sae_off = false;
    }
    memset(&sae, 0, sizeof(sae));
    printf("      Associated! ap_sta_idx=%u bssid=%02x:%02x:%02x:%02x:%02x:%02x freq=%u\n",
           st.ap_sta_idx, st.ap_bssid[0], st.ap_bssid[1], st.ap_bssid[2],
           st.ap_bssid[3], st.ap_bssid[4], st.ap_bssid[5], st.ap_center_freq);

    aic_wpa2_ctx_t local_ctx;
    aic_wpa2_ctx_t *wpa_ctx = out_wpa_ctx ? out_wpa_ctx : &local_ctx;
    if (!is_open && use_ft && ft_reassoc) {
        printf("[3/4] FT reassociation: keys from the PMK-R0, no 4-way handshake\n");
        const uint8_t pw = (target->pairwise_cipher != AIC_CIPHER_INVALID) ? target->pairwise_cipher : AIC_CIPHER_CCMP;
        const uint8_t grp = (target->group_cipher != AIC_CIPHER_INVALID) ? target->group_cipher : AIC_CIPHER_CCMP;
        /* shortcut: no M2 key data, so a PTK rekey by 4-way after an FT roam fails and reconnects; rare on PSK APs */
        aic_wpa2_ctx_init(wpa_ctx, st.mac_addr, st.ap_bssid, g_ft.pmk_r1, NULL, 0U, pw, grp);
        wpa_ctx->derive_ptk = ft_ptk;
        if (ft_finish(&g_ft, &ft, wpa_ctx) != 0) {
            set_err(err_buf, err_cap, "FT reassociation response did not check out");
            fprintf(stderr, "ft: reassociation response MIC, nonces or GTK wrong\n");
            (void)wifi_disconnect(conn, 3U);
            return 1;
        }
        if (install_keys(conn, wpa_ctx, err_buf, err_cap) != 0) {
            return 1;
        }
    } else if (!is_open) {
        printf("[3/4] Running WPA2-PSK 4-Way Handshake%s...\n", use_ft ? " (FT-PSK)" : try_sae ? (h2e ? " (WPA3-SAE H2E)" : " (WPA3-SAE)") : "");
        const uint8_t pw = (target->pairwise_cipher != AIC_CIPHER_INVALID) ? target->pairwise_cipher : AIC_CIPHER_CCMP;
        const uint8_t grp = (target->group_cipher != AIC_CIPHER_INVALID) ? target->group_cipher : AIC_CIPHER_CCMP;
        uint8_t kd[255];
        int kd_len = (int)rsn_ie_len;
        memcpy(kd, rsn_ie, rsn_ie_len);
        if (h2e) { /* M2 repeats the RSNXE the association request carried (mlme: SAE H2E) */
            static const uint8_t rsnxe[3] = { 244U, 1U, 0x20U };
            memcpy(&kd[kd_len], rsnxe, sizeof(rsnxe));
            kd_len += (int)sizeof(rsnxe);
        }
        if (use_ft) {
            kd_len = ft_initial(&g_ft, pmk, target->ssid, target->ssid_len, st.mac_addr, rsn_ie, &ft, kd, sizeof(kd));
            if (kd_len < 0) {
                set_err(err_buf, err_cap, "FT association response unusable");
                fprintf(stderr, "ft: association response has no usable FTE, using plain WPA2-PSK from now on\n");
                (void)wifi_disconnect(conn, 3U);
                return 1;
            }
        }
        aic_wpa2_ctx_init(wpa_ctx, st.mac_addr, st.ap_bssid, use_ft ? g_ft.pmk_r1 : pmk, kd, (uint8_t)kd_len, pw, grp);
        if (use_ft) {
            wpa_ctx->derive_ptk = ft_ptk;
        }

        bool keys_installed = false;
        bool replied = false; /* msg2 sent: AP silence after it means its MIC (i.e. the PSK) was wrong */
        for (int i = 0; i < 3000 && !keys_installed; ++i) {
            wifi_eapol_frame_t rx_frame;
            if (wifi_poll_eapol(conn, &rx_frame) == KERN_SUCCESS && rx_frame.has_frame) {
                uint8_t reply_eth[WIFI_EAPOL_MAX_FRAME];
                size_t reply_len = 0U;
                bool keys_ready = false;
                bool gtk_rekey  = false;
                const int hrc = aic_wpa2_handle_rx_eapol(wpa_ctx,
                                                         rx_frame.data,
                                                         rx_frame.len,
                                                         reply_eth,
                                                         sizeof(reply_eth),
                                                         &reply_len,
                                                         &keys_ready,
                                                         &gtk_rekey);
                if (hrc < 0) { /* a bad MIC is dropped (0): -1 is a local crypto or key-unwrap failure */
                    set_err(err_buf, err_cap, "4-Way Handshake failed");
                    fprintf(stderr, "error: EAPOL key derivation/unwrap failure\n");
                    (void)wifi_disconnect(conn, 3U);
                    return 1;
                }
                if (hrc == 1 && reply_len > 0U) {
                    kr = wifi_send_eapol(conn, reply_eth, reply_len);
                    replied = true;
                    if (kr != KERN_SUCCESS) {
                        set_err(err_buf, err_cap, "SEND_EAPOL failed: 0x%08x", kr);
                        fprintf(stderr, "error: SEND_EAPOL failed: 0x%08x\n", kr);
                        return 1;
                    }
                }
                if (keys_ready) {
                    if (install_keys(conn, wpa_ctx, err_buf, err_cap) != 0) {
                        return 1;
                    }
                    install_igtk(conn, wpa_ctx, rx_frame.data, rx_frame.len);
                    keys_installed = true;
                }
            } else {
                usleep(2000);
            }
        }

        if (!keys_installed) {
            set_err(err_buf, err_cap, replied ? "Wrong password" : "4-Way Handshake timed out (no reply from AP)");
            fprintf(stderr, "error: timed out waiting for 4-way handshake\n");
            (void)wifi_disconnect(conn, 3U);
            return 1;
        }
    } else {
        printf("[3/4] Open network (no 4-way handshake needed).\n");
    }

    char bsd[32];
    wifi_ifname(svc, bsd, sizeof(bsd));
    printf("[4/4] Opening LMAC control port & raising link on %s...\n", bsd);
    kr = wifi_set_port_link(conn, true, true);
    if (kr != KERN_SUCCESS) {
        set_err(err_buf, err_cap, "SET_PORT_LINK failed: 0x%08x", kr);
        fprintf(stderr, "error: SET_PORT_LINK failed: 0x%08x\n", kr);
        return 1;
    }

    if (run_dhcp) {
        const int drc = trigger_dhcp(bsd);
        printf("      DHCP trigger on %s: rc=%d\n", bsd, drc);
    }

    if (out_is_open) {
        *out_is_open = is_open;
    }
    g_ft.ok = use_ft;
    ft_off &= !use_ft;
    if (use_ft) printf("ft: %s, mobility domain %02x%02x\n", ft_reassoc ? "roamed" : "keys held", g_ft.md[1], g_ft.md[0]);
    if (target != &last_bss) last_bss = *target;
    have_last = true;
    return 0;
}

static int save_profile(const char *ssid, const char *pass) {
    const size_t slen = strlen(ssid);
    if (slen == 0U || slen > 32U || strchr(ssid, '\n') || strchr(ssid, '\r')) {
        fprintf(stderr, "error: invalid SSID\n");
        return 1;
    }
    if (pass && (strlen(pass) < 8U || strlen(pass) > 63U || strchr(pass, '\n') || strchr(pass, '\r'))) {
        fprintf(stderr, "error: passphrase must be 8..63 chars\n");
        return 1;
    }

    (void)mkdir(WIFI_CONF_DIR, 0755);
    /* write a temp file and rename it, so a crash or full disk never leaves a truncated profile */
    char tmp[sizeof(g_conf_path) + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", WIFI_CONF_PATH);
    const int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "error: failed to write %s: %s (try sudo?)\n", WIFI_CONF_PATH, strerror(errno));
        return 1;
    }
    (void)fchmod(fd, 0600);

    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return 1;
    }
    fprintf(fp, "ssid=%s\n", ssid);
    if (pass) {
        fprintf(fp, "psk=%s\n", pass);
    }
    const bool wrote = fflush(fp) == 0 && fsync(fd) == 0;
    if (fclose(fp) != 0 || !wrote || rename(tmp, WIFI_CONF_PATH) != 0) {
        fprintf(stderr, "error: failed to write %s: %s\n", WIFI_CONF_PATH, strerror(errno));
        (void)unlink(tmp);
        return 1;
    }
    printf("Saved Wi-Fi profile to %s (mode 0600)\n", WIFI_CONF_PATH);
    return 0;
}

static bool load_profile(char *ssid_out, size_t ssid_cap, char *pass_out, size_t pass_cap, bool *has_pass) {
    *has_pass = false;
    memset(ssid_out, 0, ssid_cap);
    memset(pass_out, 0, pass_cap);

    FILE *fp = fopen(WIFI_CONF_PATH, "r");
    if (!fp) {
        return false;
    }
    char line[128];
    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t l = strlen(line);
        while (l > 0U && (line[l - 1U] == '\n' || line[l - 1U] == '\r')) {
            line[--l] = '\0';
        }
        if (strncmp(line, "ssid=", 5U) == 0) {
            snprintf(ssid_out, ssid_cap, "%s", line + 5U);
        } else if (strncmp(line, "psk=", 4U) == 0) {
            snprintf(pass_out, pass_cap, "%s", line + 4U);
            *has_pass = (pass_out[0] != '\0');
        }
    }
    fclose(fp);
    return (ssid_out[0] != '\0');
}

/* ---------- Daemon IPC State & Helpers ---------- */

typedef enum {
    CMD_NONE = 0,
    CMD_SCAN,
    CMD_CONNECT,
    CMD_DISCONNECT,
    CMD_FORGET,
    CMD_RECONNECT,
    CMD_POWERSAVE /* the driver is only called from the main loop */
} aic_daemon_cmd_kind_t;

typedef struct {
    aic_daemon_cmd_kind_t kind;
    char                  ssid[36];
    char                  pass[72];
    bool                  has_pass;
    bool                  save_profile;
    bool                  done;
    uint32_t              seq; /* a reply for an older, timed-out command must not finish this one */
    char                  json_reply[AIC_IPC_BUF_SIZE];
} aic_daemon_pending_cmd_t;

static pthread_mutex_t g_state_lock     = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_req_lock       = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_req_wait_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_req_done_cond  = PTHREAD_COND_INITIALIZER;

static int             g_wake_pipe[2]   = { -1, -1 };
static gid_t           g_admin_gid      = 80U;
static int             g_ctrl_listen_fd = -1;

static wifi_status_t g_snap_status;
static char              g_snap_bsd[32]        = "unknown";
static bool              g_snap_present        = false;
static bool              g_snap_connecting     = false;
static bool              g_snap_auto_paused    = false;
static char              g_snap_saved_ssid[36] = "";
static char              g_snap_last_error[160]= "";

static bool              g_has_active_target   = false;
static char              g_active_ssid[36]     = "";
static char              g_active_pass[72]     = "";
static bool              g_active_has_pass     = false;

static aic_daemon_pending_cmd_t g_pending_cmd;

static void wake_daemon_loop(void) {
    if (g_wake_pipe[1] >= 0) {
        const char b = 1;
        (void)write(g_wake_pipe[1], &b, 1);
    }
}

static void drain_wake_pipe(void) {
    if (g_wake_pipe[0] < 0) {
        return;
    }
    char buf[64];
    while (read(g_wake_pipe[0], buf, sizeof(buf)) > 0) {
    }
}

static bool sleep_with_wake_ms(int timeout_ms) {
    if (g_wake_pipe[0] < 0) {
        usleep((useconds_t)timeout_ms * 1000U);
        return false;
    }
    struct pollfd pfd;
    pfd.fd      = g_wake_pipe[0];
    pfd.events  = POLLIN;
    pfd.revents = 0;
    const int rc = poll(&pfd, 1, timeout_ms);
    if (rc > 0 && (pfd.revents & POLLIN)) {
        return true;
    }
    return false;
}

static void sync_saved_ssid_snapshot(void) {
    char ssid[36] = {0};
    char pass[72] = {0};
    bool has_p = false;
    const bool ok = load_profile(ssid, sizeof(ssid), pass, sizeof(pass), &has_p);
    memset(pass, 0, sizeof(pass));

    pthread_mutex_lock(&g_state_lock);
    if (ok) {
        snprintf(g_snap_saved_ssid, sizeof(g_snap_saved_ssid), "%s", ssid);
    } else {
        g_snap_saved_ssid[0] = '\0';
    }
    pthread_mutex_unlock(&g_state_lock);
}

static void refresh_snapshot(io_connect_t conn, io_service_t svc) {
    wifi_status_t st;
    memset(&st, 0, sizeof(st));
    char bsd[32] = "unknown";
    bool present = false;

    if (conn != IO_OBJECT_NULL && svc != IO_OBJECT_NULL && wifi_get_status(conn, &st) == KERN_SUCCESS) {
        present = true;
        wifi_ifname(svc, bsd, sizeof(bsd));
    }

    pthread_mutex_lock(&g_state_lock);
    g_snap_present = present;
    if (present) {
        g_snap_status = st;
        snprintf(g_snap_bsd, sizeof(g_snap_bsd), "%s", bsd);
    } else {
        memset(&g_snap_status, 0, sizeof(g_snap_status));
        snprintf(g_snap_bsd, sizeof(g_snap_bsd), "unknown");
    }
    pthread_mutex_unlock(&g_state_lock);
}

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
} str_builder_t;

static void sb_appendf(str_builder_t *sb, const char *fmt, ...) {
    if (!sb || !sb->buf || sb->len >= sb->cap) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    const int n = vsnprintf(sb->buf + sb->len, sb->cap - sb->len, fmt, ap);
    va_end(ap);
    if (n > 0) {
        const size_t add = (size_t)n;
        sb->len = (sb->len + add < sb->cap) ? (sb->len + add) : (sb->cap - 1U);
    }
}

static void sb_append_json_str(str_builder_t *sb, const char *s) {
    sb_appendf(sb, "\"");
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; ++p) {
            const unsigned char c = *p;
            if (c == '"' || c == '\\') {
                sb_appendf(sb, "\\%c", (char)c);
            } else if (c == '\n') {
                sb_appendf(sb, "\\n");
            } else if (c == '\r') {
                sb_appendf(sb, "\\r");
            } else if (c == '\t') {
                sb_appendf(sb, "\\t");
            } else if (c < 0x20U) {
                sb_appendf(sb, "\\u%04x", (unsigned int)c);
            } else {
                sb_appendf(sb, "%c", (char)c);
            }
        }
    }
    sb_appendf(sb, "\"");
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_decode_str(const char *hex, char *out, size_t out_cap) {
    if (!hex || !out || out_cap == 0U) {
        return -1;
    }
    const size_t hlen = strlen(hex);
    if ((hlen % 2U) != 0U || (hlen / 2U) >= out_cap) {
        return -1;
    }
    for (size_t i = 0U; i < hlen; i += 2U) {
        const int hi = hex_nibble(hex[i]);
        const int lo = hex_nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        const unsigned char b = (unsigned char)((hi << 4) | lo);
        if (b == '\0') {
            return -1;
        }
        out[i / 2U] = (char)b;
    }
    out[hlen / 2U] = '\0';
    return 0;
}

static void build_status_json(char *out, size_t cap) {
    wifi_status_t st;
    char bsd[32];
    bool present;
    bool connecting;
    bool auto_paused;
    char saved_ssid[36];
    char last_error[160];

    pthread_mutex_lock(&g_state_lock);
    st          = g_snap_status;
    present     = g_snap_present;
    connecting  = g_snap_connecting;
    auto_paused = g_snap_auto_paused;
    snprintf(bsd, sizeof(bsd), "%s", g_snap_bsd);
    snprintf(saved_ssid, sizeof(saved_ssid), "%s", g_snap_saved_ssid);
    snprintf(last_error, sizeof(last_error), "%s", g_snap_last_error);
    pthread_mutex_unlock(&g_state_lock);

    char ssid_str[33] = {0};
    if (st.ssid_len > 0U && st.ssid_len <= 32U) {
        memcpy(ssid_str, st.ssid, st.ssid_len);
    }
    char mac_str[20];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             st.mac_addr[0], st.mac_addr[1], st.mac_addr[2],
             st.mac_addr[3], st.mac_addr[4], st.mac_addr[5]);
    char bssid_str[20];
    snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             st.ap_bssid[0], st.ap_bssid[1], st.ap_bssid[2],
             st.ap_bssid[3], st.ap_bssid[4], st.ap_bssid[5]);

    str_builder_t sb = { out, cap, 0U };
    sb_appendf(&sb, "{\"ok\":true,\"present\":%s", present ? "true" : "false");
    sb_appendf(&sb, ",\"bsd\":");       sb_append_json_str(&sb, bsd);
    sb_appendf(&sb, ",\"mac\":");       sb_append_json_str(&sb, mac_str);
    sb_appendf(&sb, ",\"fw\":");        sb_append_json_str(&sb, (const char *)st.fw_version);
    sb_appendf(&sb, ",\"chip\":");      sb_append_json_str(&sb, wifi_chip_name());
    sb_appendf(&sb, ",\"chip_id\":\"0x%08x\",\"lmac_version\":\"0x%08x\"", st.chip_id, st.lmac_version);
    sb_appendf(&sb, ",\"is_5g\":%s,\"lmac_ready\":%s,\"associated\":%s,\"link_up\":%s",
               st.is_5g_supported ? "true" : "false",
               st.lmac_ready ? "true" : "false",
               st.associated ? "true" : "false",
               st.link_up ? "true" : "false");
    sb_appendf(&sb, ",\"assoc_status\":%u,\"disc_reason\":%u", st.assoc_status, st.disconnect_reason);
    sb_appendf(&sb, ",\"ssid\":");      sb_append_json_str(&sb, ssid_str);
    sb_appendf(&sb, ",\"bssid\":");     sb_append_json_str(&sb, bssid_str);
    sb_appendf(&sb, ",\"freq\":%u,\"sta_idx\":%u", st.ap_center_freq, st.ap_sta_idx);
    sb_appendf(&sb, ",\"tx_packets\":%llu,\"rx_packets\":%llu,\"eapol_rx_total\":%llu,\"eapol_rx_queued\":%u",
               st.tx_packets, st.rx_packets, st.eapol_rx_total, st.eapol_rx_queued);
    sb_appendf(&sb, ",\"connecting\":%s,\"auto_paused\":%s",
               connecting ? "true" : "false",
               auto_paused ? "true" : "false");
    sb_appendf(&sb, ",\"saved_ssid\":"); sb_append_json_str(&sb, saved_ssid);
    sb_appendf(&sb, ",\"last_error\":"); sb_append_json_str(&sb, last_error);
    sb_appendf(&sb, ",\"band_pref\":\"%s\"", band_pref());
    if (wifi_has_power_save()) sb_appendf(&sb, ",\"power_save\":%s", ps_pref() ? "true" : "false");
    if (wifi_has_set_mac()) sb_appendf(&sb, ",\"mac_random\":%s", mr_pref() ? "true" : "false");
    if (wifi_has_rssi()) sb_appendf(&sb, ",\"roam\":\"%s\"", roam_names[roam_level()]);
    sb_appendf(&sb, "}\n");
}

static void build_scan_json(const wifi_scan_list_t *list, char *out, size_t cap) {
    str_builder_t sb = { out, cap, 0U };
    sb_appendf(&sb, "{\"ok\":true,\"scan_done\":%s,\"bss\":[", list->scan_done ? "true" : "false");
    for (uint16_t i = 0U; i < list->count; ++i) {
        const wifi_scan_bss_t *b = &list->bss[i];
        char ssid_str[33] = {0};
        const bool hidden = (b->ssid_len == 0U || b->ssid_len > 32U);
        if (!hidden) {
            memcpy(ssid_str, b->ssid, b->ssid_len);
        }
        char bssid_str[20];
        snprintf(bssid_str, sizeof(bssid_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 b->bssid[0], b->bssid[1], b->bssid[2], b->bssid[3], b->bssid[4], b->bssid[5]);
        char sec_str[20];
        format_sec_str(b->sec_mask, sec_str, sizeof(sec_str));
        const bool is_open = (b->sec_mask & (AIC_SEC_PRIVACY | AIC_SEC_WPA_PSK | AIC_SEC_WPA2_PSK | AIC_SEC_WPA3_SAE | AIC_SEC_8021X)) == 0U;

        sb_appendf(&sb, "%s{\"ssid\":", (i > 0U) ? "," : "");
        sb_append_json_str(&sb, hidden ? "" : ssid_str);
        sb_appendf(&sb, ",\"hidden\":%s,\"bssid\":", hidden ? "true" : "false");
        sb_append_json_str(&sb, bssid_str);
        sb_appendf(&sb, ",\"freq\":%u,\"rssi\":%d,\"sec\":", b->freq, (int)b->rssi);
        sb_append_json_str(&sb, sec_str);
        sb_appendf(&sb, ",\"open\":%s}", is_open ? "true" : "false");
    }
    sb_appendf(&sb, "]}\n");
}

static void build_err_json(const char *msg, char *out, size_t cap) {
    str_builder_t sb = { out, cap, 0U };
    sb_appendf(&sb, "{\"ok\":false,\"error\":");
    sb_append_json_str(&sb, msg ? msg : "unknown error");
    sb_appendf(&sb, "}\n");
}

static void finish_pending_cmd_locked(uint32_t seq, const char *json_msg);

static void execute_pending_scan(io_connect_t conn, uint32_t seq) {
    static char reply[AIC_IPC_BUF_SIZE]; /* only the daemon loop thread scans */
    wifi_scan_list_t list;
    char err[160] = {0};
    if (conn == IO_OBJECT_NULL) {
        build_err_json("Adapter not connected", reply, sizeof(reply));
    } else if (run_scan_and_wait(conn, NULL, 0U, NULL, 0, &list, err, sizeof(err)) != 0) {
        build_err_json(err[0] ? err : "Scan failed", reply, sizeof(reply));
    } else {
        build_scan_json(&list, reply, sizeof(reply));
    }
    finish_pending_cmd_locked(seq, reply);
}

static bool dispatch_daemon_cmd_sync(const aic_daemon_pending_cmd_t *req, char *reply_out, size_t reply_cap) {
    pthread_mutex_lock(&g_req_lock);

    pthread_mutex_lock(&g_req_wait_lock);
    static uint32_t next_seq;
    g_pending_cmd = *req;
    g_pending_cmd.done = false;
    g_pending_cmd.seq = ++next_seq;
    wake_daemon_loop();

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 25;
    int wrc = 0;
    while (!g_pending_cmd.done && g_keep_running && wrc == 0) {
        wrc = pthread_cond_timedwait(&g_req_done_cond, &g_req_wait_lock, &ts);
    }
    if (g_pending_cmd.done) {
        snprintf(reply_out, reply_cap, "%s", g_pending_cmd.json_reply);
    } else {
        build_err_json("Daemon request timed out", reply_out, reply_cap);
    }
    const bool ok = g_pending_cmd.done;
    g_pending_cmd.kind = CMD_NONE;
    pthread_mutex_unlock(&g_req_wait_lock);

    pthread_mutex_unlock(&g_req_lock);
    return ok;
}

static void finish_pending_cmd_locked(uint32_t seq, const char *json_msg) {
    pthread_mutex_lock(&g_req_wait_lock);
    if (g_pending_cmd.seq == seq && g_pending_cmd.kind != CMD_NONE && !g_pending_cmd.done) {
        snprintf(g_pending_cmd.json_reply, sizeof(g_pending_cmd.json_reply), "%s", json_msg);
        g_pending_cmd.done = true;
        pthread_cond_signal(&g_req_done_cond);
    }
    pthread_mutex_unlock(&g_req_wait_lock);
}

static bool peer_is_authorized(int cfd) {
    struct xucred uc;
    socklen_t len = sizeof(uc);
    memset(&uc, 0, sizeof(uc));
    if (getsockopt(cfd, SOL_LOCAL, LOCAL_PEERCRED, &uc, &len) != 0 || uc.cr_version != XUCRED_VERSION) {
        return false;
    }
    if (uc.cr_uid == 0U) {
        return true;
    }
    const short ngroups = (uc.cr_ngroups > NGROUPS) ? NGROUPS : uc.cr_ngroups;
    for (short i = 0; i < ngroups; ++i) {
        if (uc.cr_groups[i] == g_admin_gid) {
            return true;
        }
    }
    return false;
}

static void handle_ipc_client(int cfd) {
    if (!peer_is_authorized(cfd)) {
        const char *deny = "{\"ok\":false,\"error\":\"Unauthorized peer\"}\n";
        (void)write(cfd, deny, strlen(deny));
        return;
    }

    char req_line[512] = ""; /* a client that closes before sending anything must not leave garbage */
    size_t used = 0U;
    while (used + 1U < sizeof(req_line)) {
        const ssize_t n = read(cfd, req_line + used, sizeof(req_line) - 1U - used);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
        req_line[used] = '\0';
        if (strchr(req_line, '\n') != NULL) {
            break;
        }
    }
    while (used > 0U && (req_line[used - 1U] == '\n' || req_line[used - 1U] == '\r')) {
        req_line[--used] = '\0';
    }
    if (strcmp(req_line, "STATUS") != 0) /* command word only: CONNECT_HEX carries the passphrase */
        fprintf(stderr, "usbwifid: slot %d command %.*s\n", wifi_slot(), (int)strcspn(req_line, " "), req_line);

    char reply[AIC_IPC_BUF_SIZE];
    if (strcmp(req_line, "STATUS") == 0) {
        build_status_json(reply, sizeof(reply));
    } else if (strcmp(req_line, "SCAN") == 0) {
        aic_daemon_pending_cmd_t req;
        memset(&req, 0, sizeof(req));
        req.kind = CMD_SCAN;
        (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
    } else if (strcmp(req_line, "DISCONNECT") == 0) {
        aic_daemon_pending_cmd_t req;
        memset(&req, 0, sizeof(req));
        req.kind = CMD_DISCONNECT;
        (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
    } else if (strcmp(req_line, "FORGET") == 0) {
        aic_daemon_pending_cmd_t req;
        memset(&req, 0, sizeof(req));
        req.kind = CMD_FORGET;
        (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
    } else if (strcmp(req_line, "RECONNECT") == 0) {
        aic_daemon_pending_cmd_t req;
        memset(&req, 0, sizeof(req));
        req.kind = CMD_RECONNECT;
        (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
    } else if (strncmp(req_line, "BAND ", 5U) == 0) { /* takes effect at the next connect */
        const char *v = req_line + 5U;
        if (strcmp(v, "auto") != 0 && strcmp(v, "5") != 0 && strcmp(v, "2.4") != 0) {
            build_err_json("Band must be auto, 5 or 2.4", reply, sizeof(reply));
        } else {
            if (!write_pref(WIFI_BAND_PATH, v)) build_err_json(strerror(errno), reply, sizeof(reply));
            else snprintf(reply, sizeof(reply), "{\"ok\":true}\n");
        }
    } else if (strncmp(req_line, "MACRANDOM ", 10U) == 0) { /* takes effect at the next connect */
        const char *v = req_line + 10U;
        if (strcmp(v, "on") != 0 && strcmp(v, "off") != 0) build_err_json("MAC randomization must be on or off", reply, sizeof(reply));
        else if (!write_pref(g_mr_path, v)) build_err_json(strerror(errno), reply, sizeof(reply));
        else snprintf(reply, sizeof(reply), "{\"ok\":true}\n");
    } else if (strncmp(req_line, "ROAM ", 5U) == 0) { /* read on each check, no restart needed */
        const char *v = req_line + 5U;
        int i = 0;
        while (i < 6 && strcmp(v, roam_names[i]) != 0) i++;
        if (i == 6) build_err_json("Roaming level must be VeryHigh, High, Middle, Low, VeryLow or Disable", reply, sizeof(reply));
        else if (!write_pref(g_roam_path, v)) build_err_json(strerror(errno), reply, sizeof(reply));
        else snprintf(reply, sizeof(reply), "{\"ok\":true}\n");
    } else if (strncmp(req_line, "POWERSAVE ", 10U) == 0) { /* saved, then applied by the main loop */
        const char *v = req_line + 10U;
        if (strcmp(v, "on") != 0 && strcmp(v, "off") != 0) {
            build_err_json("Power save must be on or off", reply, sizeof(reply));
        } else if (!write_pref(g_ps_path, v)) {
            build_err_json(strerror(errno), reply, sizeof(reply));
        } else {
            aic_daemon_pending_cmd_t req;
            memset(&req, 0, sizeof(req));
            req.kind = CMD_POWERSAVE;
            (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
        }
    } else if (strncmp(req_line, "CONNECT_HEX ", 12U) == 0) {
        char *p = req_line + 12U;
        char *sp1 = strchr(p, ' ');
        char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        if (!sp1 || !sp2) {
            build_err_json("Malformed CONNECT_HEX syntax", reply, sizeof(reply));
        } else {
            *sp1 = '\0';
            *sp2 = '\0';
            const char *ssid_hex = p;
            const char *pass_hex = sp1 + 1;
            const int save_flag  = atoi(sp2 + 1);

            aic_daemon_pending_cmd_t req;
            memset(&req, 0, sizeof(req));
            req.kind         = CMD_CONNECT;
            req.save_profile = (save_flag != 0);
            if (hex_decode_str(ssid_hex, req.ssid, sizeof(req.ssid)) != 0 || req.ssid[0] == '\0') {
                build_err_json("Invalid SSID", reply, sizeof(reply));
            } else if (strcmp(pass_hex, "-") != 0) {
                if (hex_decode_str(pass_hex, req.pass, sizeof(req.pass)) != 0 ||
                    strlen(req.pass) < 8U || strlen(req.pass) > 63U) {
                    build_err_json("Passphrase must be 8..63 chars", reply, sizeof(reply));
                } else {
                    req.has_pass = true;
                    (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
                }
            } else {
                req.has_pass = false;
                (void)dispatch_daemon_cmd_sync(&req, reply, sizeof(reply));
            }
            memset(req.pass, 0, sizeof(req.pass));
        }
    } else {
        build_err_json("Unknown command", reply, sizeof(reply));
    }

    const size_t rlen = strlen(reply);
    size_t sent = 0U;
    while (sent < rlen) {
        const ssize_t w = write(cfd, reply + sent, rlen - sent);
        if (w <= 0) {
            break;
        }
        sent += (size_t)w;
    }
}

static void *ipc_client_thread(void *arg) {
    const int cfd = (int)(intptr_t)arg;
    handle_ipc_client(cfd);
    close(cfd);
    return NULL;
}

/* one thread per client: a SCAN or CONNECT holds its client for seconds, and the app's STATUS polls
   behind it would time out and show the adapter as unplugged */
static void *control_socket_thread(void *arg) {
    (void)arg;
    while (g_keep_running && g_ctrl_listen_fd >= 0) {
        struct pollfd pfd;
        pfd.fd      = g_ctrl_listen_fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;
        const int prc = poll(&pfd, 1, 500);
        if (prc <= 0) {
            continue;
        }
        if (pfd.revents & POLLIN) {
            const int cfd = accept(g_ctrl_listen_fd, NULL, NULL);
            pthread_t t;
            const struct timeval rto = { .tv_sec = 5 }; /* a client that never sends its line */
            if (cfd >= 0) {
                (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto));
                if (pthread_create(&t, NULL, ipc_client_thread, (void *)(intptr_t)cfd) == 0) {
                    pthread_detach(t);
                } else {
                    handle_ipc_client(cfd);
                    close(cfd);
                }
            }
        }
    }
    return NULL;
}

static int setup_control_socket(void) {
    const struct group *grp = getgrnam("admin");
    g_admin_gid = grp ? grp->gr_gid : 20U;

    (void)unlink(WIFI_SOCK_PATH);
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "warning: control socket() failed: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", WIFI_SOCK_PATH);

    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "warning: bind(%s) failed: %s\n", WIFI_SOCK_PATH, strerror(errno));
        close(fd);
        return -1;
    }
    (void)chown(WIFI_SOCK_PATH, 0, g_admin_gid);
    (void)chmod(WIFI_SOCK_PATH, 0660);

    if (listen(fd, 8) != 0) {
        fprintf(stderr, "warning: listen(%s) failed: %s\n", WIFI_SOCK_PATH, strerror(errno));
        close(fd);
        (void)unlink(WIFI_SOCK_PATH);
        return -1;
    }
    return fd;
}

/* Returns true if broken out due to a pending control command instead of disconnect. */
static bool run_rekey_loop(io_connect_t conn,
                           io_service_t svc,
                           aic_wpa2_ctx_t *wpa_ctx,
                           bool is_open,
                           bool daemon_mode) {
    while (g_keep_running) {
        if (daemon_mode && sleep_with_wake_ms(250)) {
            drain_wake_pipe();
            aic_daemon_cmd_kind_t k = CMD_NONE;
            pthread_mutex_lock(&g_req_wait_lock);
            k = g_pending_cmd.done ? CMD_NONE : g_pending_cmd.kind;
            const uint32_t seq = g_pending_cmd.seq;
            pthread_mutex_unlock(&g_req_wait_lock);

            if (k == CMD_SCAN) {
                execute_pending_scan(conn, seq);
                continue;
            }
            if (k == CMD_POWERSAVE) {
                apply_power_save();
                finish_pending_cmd_locked(seq, "{\"ok\":true}\n");
                continue;
            }
            if (k == CMD_RECONNECT) { /* already up: leaving here would stop rekey handling until the link drops */
                pthread_mutex_lock(&g_state_lock);
                g_snap_auto_paused = false;
                g_snap_last_error[0] = '\0';
                pthread_mutex_unlock(&g_state_lock);
                finish_pending_cmd_locked(seq, "{\"ok\":true}\n");
                continue;
            }
            if (k == CMD_CONNECT || k == CMD_DISCONNECT || k == CMD_FORGET) {
                return true;
            }
        }

        wifi_status_t st;
        if (wifi_get_status(conn, &st) != KERN_SUCCESS || !st.lmac_ready || !st.associated) {
            fprintf(stderr, "notice: Wi-Fi link lost/disconnected (reason=%u)\n", st.disconnect_reason);
            break;
        }
        if (daemon_mode) {
            refresh_snapshot(conn, svc);
            if (roam_check(conn, &st)) break;
        }

        if (!is_open) {
            wifi_eapol_frame_t rx_frame;
            if (wifi_poll_eapol(conn, &rx_frame) == KERN_SUCCESS && rx_frame.has_frame) {
                uint8_t reply_eth[WIFI_EAPOL_MAX_FRAME];
                size_t reply_len = 0U;
                bool keys_ready = false;
                bool gtk_rekey  = false;
                if (aic_wpa2_handle_rx_eapol(wpa_ctx,
                                             rx_frame.data,
                                             rx_frame.len,
                                             reply_eth,
                                             sizeof(reply_eth),
                                             &reply_len,
                                             &keys_ready,
                                             &gtk_rekey) == 1) {
                    (void)wifi_send_eapol(conn, reply_eth, reply_len);
                    if (keys_ready) { /* the AP renewed the PTK with a fresh 4-way handshake */
                        uint8_t hw_idx = 0U;
                        (void)wifi_add_key(conn, 0U, true, wpa_ctx->pairwise_cipher, &wpa_ctx->ptk[32], 16U, &hw_idx);
                    }
                    if (gtk_rekey && wpa_ctx->has_gtk) {
                        uint8_t hw_idx = 0U;
                        (void)wifi_add_key(conn, wpa_ctx->gtk_idx, false, wpa_ctx->group_cipher,
                                         wpa_ctx->gtk, wpa_ctx->gtk_len, &hw_idx);
                    }
                    install_igtk(conn, wpa_ctx, rx_frame.data, rx_frame.len);
                }
            }
        }

        if (!daemon_mode) {
            usleep(250000);
        }
    }
    return false;
}

static bool handle_daemon_pending_command(io_connect_t conn,
                                          io_service_t svc,
                                          aic_wpa2_ctx_t *wpa_ctx,
                                          bool *is_open_out,
                                          bool *connected_now) {
    aic_daemon_pending_cmd_t local;
    pthread_mutex_lock(&g_req_wait_lock);
    if (g_pending_cmd.done || g_pending_cmd.kind == CMD_NONE) {
        pthread_mutex_unlock(&g_req_wait_lock);
        return false;
    }
    local = g_pending_cmd;
    pthread_mutex_unlock(&g_req_wait_lock);

    char reply[AIC_IPC_BUF_SIZE];
    if (local.kind == CMD_SCAN) {
        execute_pending_scan(conn, local.seq);
    } else if (local.kind == CMD_DISCONNECT) {
        pthread_mutex_lock(&g_state_lock);
        g_snap_auto_paused = true;
        g_snap_last_error[0] = '\0';
        pthread_mutex_unlock(&g_state_lock);
        g_has_active_target = false;
        memset(g_active_pass, 0, sizeof(g_active_pass));

        if (conn != IO_OBJECT_NULL) {
            (void)wifi_disconnect(conn, 3U);
            refresh_snapshot(conn, svc);
        }
        *connected_now = false;
        finish_pending_cmd_locked(local.seq, "{\"ok\":true}\n");
    } else if (local.kind == CMD_FORGET) {
        (void)unlink(WIFI_CONF_PATH);
        sync_saved_ssid_snapshot();
        g_has_active_target = false;
        memset(g_active_pass, 0, sizeof(g_active_pass));

        pthread_mutex_lock(&g_state_lock);
        g_snap_auto_paused = false;
        g_snap_last_error[0] = '\0';
        pthread_mutex_unlock(&g_state_lock);

        if (conn != IO_OBJECT_NULL) {
            (void)wifi_disconnect(conn, 3U);
            refresh_snapshot(conn, svc);
        }
        *connected_now = false;
        finish_pending_cmd_locked(local.seq, "{\"ok\":true}\n");
    } else if (local.kind == CMD_POWERSAVE) {
        if (conn != IO_OBJECT_NULL) apply_power_save();
        finish_pending_cmd_locked(local.seq, "{\"ok\":true}\n");
    } else if (local.kind == CMD_RECONNECT) {
        pthread_mutex_lock(&g_state_lock);
        g_snap_auto_paused = false;
        g_snap_last_error[0] = '\0';
        pthread_mutex_unlock(&g_state_lock);
        finish_pending_cmd_locked(local.seq, "{\"ok\":true}\n");
    } else if (local.kind == CMD_CONNECT) {
        snprintf(g_active_ssid, sizeof(g_active_ssid), "%s", local.ssid);
        if (local.has_pass) {
            snprintf(g_active_pass, sizeof(g_active_pass), "%s", local.pass);
        } else {
            g_active_pass[0] = '\0';
        }
        g_active_has_pass   = local.has_pass;
        g_has_active_target = true;

        if (conn == IO_OBJECT_NULL) {
            build_err_json("Adapter not connected", reply, sizeof(reply));
            finish_pending_cmd_locked(local.seq, reply);
            return true;
        }

        wifi_status_t st;
        if (wifi_get_status(conn, &st) == KERN_SUCCESS && st.associated) {
            (void)wifi_disconnect(conn, 3U);
            usleep(150000);
        }

        pthread_mutex_lock(&g_state_lock);
        g_snap_auto_paused   = false;
        g_snap_connecting    = true;
        g_snap_last_error[0] = '\0';
        pthread_mutex_unlock(&g_state_lock);

        char err[160] = {0};
        const int rc = perform_connect(conn,
                                       svc,
                                       local.ssid,
                                       local.has_pass ? local.pass : NULL,
                                       true,
                                       wpa_ctx,
                                       is_open_out,
                                       err,
                                       sizeof(err));
        refresh_snapshot(conn, svc);

        pthread_mutex_lock(&g_state_lock);
        g_snap_connecting = false;
        if (rc != 0) {
            snprintf(g_snap_last_error, sizeof(g_snap_last_error), "%s", err[0] ? err : "Connection failed");
        } else {
            g_snap_last_error[0] = '\0';
        }
        pthread_mutex_unlock(&g_state_lock);

        if (rc == 0) {
            if (local.save_profile) { /* only after success, so a mistyped password never becomes the auto-join profile */
                (void)save_profile(local.ssid, local.has_pass ? local.pass : NULL);
                sync_saved_ssid_snapshot();
            }
            *connected_now = true;
            finish_pending_cmd_locked(local.seq, "{\"ok\":true}\n");
        } else {
            if (strcmp(err, "Wrong password") == 0) g_has_active_target = false; /* retrying cannot help */
            build_err_json(err[0] ? err : "Connection failed", reply, sizeof(reply));
            finish_pending_cmd_locked(local.seq, reply);
        }
    }
    return true;
}

/* System sleep: an associated dongle keeps receiving frames and wakes the Mac over USB within seconds
   (pmset log: "Wake ... due to USB2_wake"). Drop the WiFi link before sleep, rejoin on wake. */
static volatile bool g_sys_sleeping = false;
static io_connect_t  g_pm_root      = IO_OBJECT_NULL;

static void on_power(void *ref, io_service_t svc, natural_t msg, void *arg) {
    (void)ref; (void)svc;
    if (msg == kIOMessageCanSystemSleep) {
        IOAllowPowerChange(g_pm_root, (long)arg);
    } else if (msg == kIOMessageSystemWillSleep) {
        g_sys_sleeping = true;
        fprintf(stderr, "notice: system sleep, dropping Wi-Fi link\n");
        (void)wifi_disconnect(IO_OBJECT_NULL, 3U);
        IOAllowPowerChange(g_pm_root, (long)arg);
    } else if (msg == kIOMessageSystemHasPoweredOn && g_sys_sleeping) {
        g_sys_sleeping = false;
        fprintf(stderr, "notice: system wake, rejoining Wi-Fi\n");
        wifi_system_woke();
        wake_daemon_loop();
    }
}

static void *power_thread(void *arg) {
    (void)arg;
    IONotificationPortRef port = NULL;
    io_object_t notifier = IO_OBJECT_NULL;
    g_pm_root = IORegisterForSystemPower(NULL, &port, on_power, &notifier);
    if (g_pm_root == IO_OBJECT_NULL) {
        fprintf(stderr, "warning: IORegisterForSystemPower failed; dongle may wake the Mac from sleep\n");
        return NULL;
    }
    CFRunLoopAddSource(CFRunLoopGetCurrent(), IONotificationPortGetRunLoopSource(port), kCFRunLoopDefaultMode);
    CFRunLoopRun();
    return NULL;
}

/* First bind in a worker: take this dongle's slot paths, its network service and socket, then tell the
   supervisor (fd 3) so it starts the next worker for the next dongle. */
static pthread_t g_ctrl_thread;
static bool      g_ctrl_thread_started = false;

static void worker_bound(void) {
    const int slot = wifi_slot() < 0 ? 0 : wifi_slot();
    if (slot > 0) {
        snprintf(g_conf_path, sizeof(g_conf_path), WIFI_CONF_DIR "/wifi-%d.conf", slot);
        snprintf(g_band_path, sizeof(g_band_path), WIFI_CONF_DIR "/band-%d", slot);
        snprintf(g_ps_path, sizeof(g_ps_path), WIFI_CONF_DIR "/powersave-%d", slot);
        snprintf(g_mr_path, sizeof(g_mr_path), WIFI_CONF_DIR "/macrandom-%d", slot);
        snprintf(g_roam_path, sizeof(g_roam_path), WIFI_CONF_DIR "/roam-%d", slot);
        snprintf(g_chans_path, sizeof(g_chans_path), WIFI_CONF_DIR "/chans-%d", slot);
    }
    snprintf(g_sock_path, sizeof(g_sock_path), WIFI_RUN_DIR "/%d.sock", slot);

    char self[PATH_MAX], netsvc[PATH_MAX], name[32];
    uint32_t n = sizeof(self);
    if (_NSGetExecutablePath(self, &n) == 0) {
        char *slash = strrchr(self, '/');
        snprintf(netsvc, sizeof(netsvc), "%.*s/usbwifi_netsvc", slash ? (int)(slash - self) : 0, self);
        if (slot == 0) snprintf(name, sizeof(name), "USB Wi-Fi");
        else snprintf(name, sizeof(name), "USB Wi-Fi %d", slot + 1);
        char *av[] = { netsvc, "install", name, wifi_if_host, NULL };
        pid_t pid;
        if (access(netsvc, X_OK) == 0 && posix_spawn(&pid, netsvc, NULL, NULL, av, environ) == 0) {
            int st;
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
        }
    }

    g_ctrl_listen_fd = setup_control_socket();
    if (g_ctrl_listen_fd >= 0 && pthread_create(&g_ctrl_thread, NULL, control_socket_thread, NULL) == 0)
        g_ctrl_thread_started = true;
    if (fcntl(3, F_GETFD) != -1) {
        const uint8_t b = (uint8_t)slot;
        (void)write(3, &b, 1);
        close(3);
    }
    sync_saved_ssid_snapshot();
    printf("usbwifid: slot %d up on %s (profile=%s, sock=%s)\n", slot, wifi_if_host, WIFI_CONF_PATH,
           WIFI_SOCK_PATH);
}

static int run_worker(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigterm);
    signal(SIGTERM, on_sigterm);

    if (pipe(g_wake_pipe) == 0) {
        (void)fcntl(g_wake_pipe[0], F_SETFL, O_NONBLOCK);
        (void)fcntl(g_wake_pipe[1], F_SETFL, O_NONBLOCK);
    }

    pthread_t pm_thread;
    if (pthread_create(&pm_thread, NULL, power_thread, NULL) == 0) pthread_detach(pm_thread);

    int connect_fails = 0;
    while (g_keep_running) {
        io_connect_t conn = IO_OBJECT_NULL;
        io_service_t svc  = IO_OBJECT_NULL;
        if (wifi_open(&conn, &svc, true, NULL) == 0 && !g_ctrl_thread_started) worker_bound();
        else if (!g_ctrl_thread_started) {
            /* wifi_open already waits up to 1 s for an RTL8852BU; an AIC8800D80 is only seen once per pass */
            if (sleep_with_wake_ms(500)) drain_wake_pipe();
            continue; /* no free dongle yet */
        }
        sync_saved_ssid_snapshot();
        if (conn == IO_OBJECT_NULL) {
            refresh_snapshot(IO_OBJECT_NULL, IO_OBJECT_NULL);
            aic_wpa2_ctx_t dummy_ctx;
            bool dummy_open = false;
            bool dummy_conn = false;
            if (sleep_with_wake_ms(1500)) {
                drain_wake_pipe();
                (void)handle_daemon_pending_command(IO_OBJECT_NULL, IO_OBJECT_NULL, &dummy_ctx, &dummy_open, &dummy_conn);
            }
            continue;
        }

        refresh_snapshot(conn, svc);
        apply_power_save(); /* every open starts with it off */
        wifi_status_t st;
        if (wifi_get_status(conn, &st) != KERN_SUCCESS || !st.lmac_ready) {
            IOServiceClose(conn);
            IOObjectRelease(svc);
            if (sleep_with_wake_ms(800)) {
                drain_wake_pipe();
                aic_wpa2_ctx_t dummy_ctx;
                bool dummy_open = false;
                bool dummy_conn = false;
                (void)handle_daemon_pending_command(IO_OBJECT_NULL, IO_OBJECT_NULL, &dummy_ctx, &dummy_open, &dummy_conn);
            }
            continue;
        }

        /* Process any queued socket command before auto-connect */
        aic_wpa2_ctx_t wpa_ctx;
        bool is_open = false;
        bool connected_now = false;
        drain_wake_pipe();
        if (handle_daemon_pending_command(conn, svc, &wpa_ctx, &is_open, &connected_now)) {
            if (connected_now) {
                (void)run_rekey_loop(conn, svc, &wpa_ctx, is_open, true);
            }
            IOServiceClose(conn);
            IOObjectRelease(svc);
            continue;
        }

        bool auto_paused = false;
        pthread_mutex_lock(&g_state_lock);
        auto_paused = g_snap_auto_paused || g_sys_sleeping;
        pthread_mutex_unlock(&g_state_lock);

        char target_ssid[36] = {0};
        char target_pass[72] = {0};
        bool target_has_pass = false;
        bool have_target = false;

        if (!auto_paused) {
            if (g_has_active_target && g_active_ssid[0] != '\0') {
                snprintf(target_ssid, sizeof(target_ssid), "%s", g_active_ssid);
                if (g_active_has_pass) {
                    snprintf(target_pass, sizeof(target_pass), "%s", g_active_pass);
                }
                target_has_pass = g_active_has_pass;
                have_target = true;
            } else {
                have_target = load_profile(target_ssid, sizeof(target_ssid),
                                           target_pass, sizeof(target_pass), &target_has_pass);
            }
        }

        if (!auto_paused && have_target && (!st.associated || !st.link_up)) {
            pthread_mutex_lock(&g_state_lock);
            g_snap_connecting = true;
            pthread_mutex_unlock(&g_state_lock);

            char err[160] = {0};
            const int rc = perform_connect(conn,
                                           svc,
                                           target_ssid,
                                           target_has_pass ? target_pass : NULL,
                                           true,
                                           &wpa_ctx,
                                           &is_open,
                                           err,
                                           sizeof(err));
            memset(target_pass, 0, sizeof(target_pass));
            refresh_snapshot(conn, svc);

            pthread_mutex_lock(&g_state_lock);
            /* still connecting through the 0.5 s first retry, so the app doesn't auto-scan into it */
            g_snap_connecting = rc != 0 && connect_fails == 0;
            if (rc != 0 && err[0] != '\0') {
                snprintf(g_snap_last_error, sizeof(g_snap_last_error), "%s", err);
            } else if (rc == 0) {
                g_snap_last_error[0] = '\0';
            }
            pthread_mutex_unlock(&g_state_lock);

            /* the first retry comes fast: right after a replug the AP often rejects the association once */
            if (rc == 0) {
                connect_fails = 0;
                (void)run_rekey_loop(conn, svc, &wpa_ctx, is_open, true);
            } else if (sleep_with_wake_ms(connect_fails++ ? 3000 : 500)) {
                drain_wake_pipe();
                (void)handle_daemon_pending_command(conn, svc, &wpa_ctx, &is_open, &connected_now);
                if (connected_now) {
                    (void)run_rekey_loop(conn, svc, &wpa_ctx, is_open, true);
                }
            }
        } else {
            memset(target_pass, 0, sizeof(target_pass));
            if (sleep_with_wake_ms(1000)) {
                drain_wake_pipe();
                (void)handle_daemon_pending_command(conn, svc, &wpa_ctx, &is_open, &connected_now);
                if (connected_now) {
                    (void)run_rekey_loop(conn, svc, &wpa_ctx, is_open, true);
                }
            }
        }

        IOServiceClose(conn);
        IOObjectRelease(svc);
    }
    /* deauth before exit: a warm AIC firmware and the AP otherwise keep the old association, so the next
       start's first connect is rejected (status 1) or its LMAC commands time out under the stale traffic */
    (void)wifi_disconnect(IO_OBJECT_NULL, 3U);

    if (g_ctrl_thread_started) {
        pthread_join(g_ctrl_thread, NULL);
    }
    if (g_ctrl_listen_fd >= 0) {
        close(g_ctrl_listen_fd);
        (void)unlink(WIFI_SOCK_PATH);
    }
    if (g_wake_pipe[0] >= 0) close(g_wake_pipe[0]);
    if (g_wake_pipe[1] >= 0) close(g_wake_pipe[1]);
    return 0;
}

/* ---------- Supervisor: one worker per dongle ---------- */
static void unpeer_slot(int slot) {
    char host[16];
    snprintf(host, sizeof(host), "feth%d", 80 + 2 * slot);
    if (if_nametoindex(host) == 0) return;
    char *np[] = { "ifconfig", host, "-peer", NULL }, *dn[] = { "ifconfig", host, "down", NULL };
    pid_t pid;
    int st;
    if (posix_spawn(&pid, "/sbin/ifconfig", NULL, NULL, np, environ) == 0) waitpid(pid, &st, 0);
    if (posix_spawn(&pid, "/sbin/ifconfig", NULL, NULL, dn, environ) == 0) waitpid(pid, &st, 0);
}

static int run_daemon(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sigterm);
    signal(SIGTERM, on_sigterm);

    (void)mkdir(WIFI_RUN_DIR, 0755);
    DIR *d = opendir(WIFI_RUN_DIR); /* sockets left by a previous run */
    for (struct dirent *e; d && (e = readdir(d));) {
        char p[PATH_MAX];
        if (e->d_name[0] == '.') continue;
        snprintf(p, sizeof(p), WIFI_RUN_DIR "/%s", e->d_name);
        (void)unlink(p);
    }
    if (d) closedir(d);
    (void)unlink("/var/run/usbwifi.sock"); /* pre-multi-dongle socket */
    /* a worker that died hard may have left its link peered: Network UI would show it live */
    for (int s = 0; s < WIFI_MAX_SLOTS; s++) unpeer_slot(s);

    struct stat fw_st;
    pthread_t fw_thread;
    if (stat(AIC_FWLOAD_DIR, &fw_st) == 0 && S_ISDIR(fw_st.st_mode) &&
        pthread_create(&fw_thread, NULL, fwload_thread, NULL) == 0)
        pthread_detach(fw_thread);

    char self[PATH_MAX];
    uint32_t sn = sizeof(self);
    if (_NSGetExecutablePath(self, &sn) != 0) return 1;
    char *av[] = { self, "--worker", NULL };
    printf("usbwifid daemon starting\n");

    /* fd: the bind notify pipe until the worker reports its slot, then -1 */
    struct { pid_t pid; int fd; int slot; } w[WIFI_MAX_SLOTS + 1] = {0};
    time_t last_spawn = 0;
    while (g_keep_running) {
        int searching = -1, free_i = -1;
        for (int i = 0; i <= WIFI_MAX_SLOTS; i++) {
            if (w[i].pid > 0 && w[i].fd >= 0) searching = i;
            if (w[i].pid == 0 && free_i < 0) free_i = i;
        }
        /* throttle: a worker that keeps crashing before it binds is respawned at most every 2 s */
        if (searching < 0 && free_i >= 0 && time(NULL) - last_spawn >= 2) {
            int p[2];
            posix_spawn_file_actions_t fa;
            if (pipe(p) == 0) {
                (void)fcntl(p[0], F_SETFD, FD_CLOEXEC);
                (void)fcntl(p[1], F_SETFD, FD_CLOEXEC);
                posix_spawn_file_actions_init(&fa);
                posix_spawn_file_actions_adddup2(&fa, p[1], 3);
                if (posix_spawn(&w[free_i].pid, self, &fa, NULL, av, environ) == 0) {
                    w[free_i].fd = p[0];
                    w[free_i].slot = -1;
                    searching = free_i;
                } else {
                    w[free_i].pid = 0;
                    close(p[0]);
                }
                posix_spawn_file_actions_destroy(&fa);
                close(p[1]);
            }
            last_spawn = time(NULL);
        }

        struct pollfd pfd = { .fd = searching >= 0 ? w[searching].fd : -1, .events = POLLIN };
        if (poll(&pfd, 1, 1000) > 0) {
            uint8_t b;
            if (read(pfd.fd, &b, 1) == 1) w[searching].slot = b;
            close(pfd.fd);
            w[searching].fd = -1; /* bound (or died before binding: reaped below) */
        }
        for (int i = 0; i <= WIFI_MAX_SLOTS; i++) {
            int st;
            if (w[i].pid <= 0 || waitpid(w[i].pid, &st, WNOHANG) != w[i].pid) continue;
            if (w[i].fd >= 0) close(w[i].fd);
            if (w[i].slot >= 0) {
                char sock[64];
                printf("usbwifid: slot %d worker exited (%d)\n", w[i].slot, st);
                unpeer_slot(w[i].slot);
                snprintf(sock, sizeof(sock), WIFI_RUN_DIR "/%d.sock", w[i].slot);
                (void)unlink(sock);
            }
            w[i].pid = 0;
            w[i].fd = -1;
            w[i].slot = -1;
        }
    }

    for (int i = 0; i <= WIFI_MAX_SLOTS; i++)
        if (w[i].pid > 0) kill(w[i].pid, SIGTERM);
    for (int i = 0; i <= WIFI_MAX_SLOTS; i++) {
        int st;
        if (w[i].pid > 0) while (waitpid(w[i].pid, &st, 0) < 0 && errno == EINTR) {}
    }
    if (g_fwload_pid > 0) kill(g_fwload_pid, SIGTERM);
    printf("usbwifid daemon stopping.\n");
    return 0;
}

/* ---------- Non-root IPC query helper for CLI ---------- */
static int query_daemon_socket(const char *cmd_line, char *out, size_t out_cap) {
    const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", WIFI_SOCK_PATH);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    const size_t clen = strlen(cmd_line);
    if (write(fd, cmd_line, clen) != (ssize_t)clen || write(fd, "\n", 1) != 1) {
        close(fd);
        return -1;
    }
    size_t used = 0U;
    while (used + 1U < out_cap) {
        const ssize_t n = read(fd, out + used, out_cap - 1U - used);
        if (n <= 0) {
            break;
        }
        used += (size_t)n;
        if (memchr(out, '\n', used) != NULL) {
            break;
        }
    }
    out[used] = '\0';
    close(fd);
    return (used > 0U) ? 0 : -1;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  sudo %s status\n"
            "  sudo %s scan\n"
            "  sudo %s connect <SSID> [passphrase] [--no-dhcp] [--stay]\n"
            "  sudo %s save <SSID> [passphrase]    (save auto-connect profile to wifi.conf)\n"
            "  sudo %s disconnect\n"
            "  %s cd-eject                         (switch a Realtek driver CD to Wi-Fi; as the console user)\n"
            "  sudo %s fwload [--once|--daemon] --fw-dir <dir> ...  (AIC8800D80 firmware loader)\n"
            "  sudo %s --daemon\n",
            prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return (argc < 2) ? 2 : 0;
    }

    if (strcmp(argv[1], "--daemon") == 0) {
        return run_daemon();
    }
    if (strcmp(argv[1], "--worker") == 0) {
        return run_worker();
    }
    if (strcmp(argv[1], "fwload") == 0) {
        return aic_fwload_main(argc - 1, argv + 1);
    }
    if (strcmp(argv[1], "cd-eject") == 0) {
        /* run by the com.usbwifi.cdswitch LaunchAgent, which launchd starts when a Realtek driver CD
           is plugged in; taking the IOKit event keeps launchd from relaunching the job for it */
        xpc_set_event_stream_handler("com.apple.iokit.matching", dispatch_get_global_queue(QOS_CLASS_UTILITY, 0),
                                     ^(xpc_object_t e) { (void)e; });
        return lkpi_usb_eject_cd(30000) ? 1 : 0;
    }
    if (strcmp(argv[1], "save") == 0 && argc >= 3) {
        const char *pass = (argc >= 4) ? argv[3] : NULL;
        return save_profile(argv[2], pass);
    }

    io_connect_t conn = IO_OBJECT_NULL;
    io_service_t svc  = IO_OBJECT_NULL;
    kern_return_t open_kr = KERN_FAILURE;
    if (wifi_open(&conn, &svc, false, &open_kr) != 0) {
        if (open_kr == kIOReturnNotPrivileged && strcmp(argv[1], "status") == 0) {
            char json[AIC_IPC_BUF_SIZE];
            if (query_daemon_socket("STATUS", json, sizeof(json)) == 0) {
                printf("%s", json);
                return 0;
            }
        }
        return 1;
    }

    int rc = 0;
    if (strcmp(argv[1], "status") == 0) {
        rc = cmd_status(conn, svc);
    } else if (strcmp(argv[1], "scan") == 0) {
        rc = cmd_scan(conn);
    } else if (strcmp(argv[1], "connect") == 0 && argc >= 3) {
        const char *ssid = argv[2];
        const char *pass = NULL;
        bool stay = false;
        bool run_dhcp = true;
        for (int i = 3; i < argc; ++i) {
            if (strcmp(argv[i], "--stay") == 0) {
                stay = true;
            } else if (strcmp(argv[i], "--no-dhcp") == 0) {
                run_dhcp = false;
            } else if (!pass) {
                pass = argv[i];
            }
        }
        aic_wpa2_ctx_t wpa_ctx;
        bool is_open = false;
        rc = perform_connect(conn, svc, ssid, pass, run_dhcp, &wpa_ctx, &is_open, NULL, 0U);
        if (rc == 0 && stay) {
            signal(SIGINT, on_sigterm);
            signal(SIGTERM, on_sigterm);
            printf("Supplicant staying resident for GTK rekeying (Ctrl+C to exit)...\n");
            (void)run_rekey_loop(conn, svc, &wpa_ctx, is_open, false);
        }
    } else if (strcmp(argv[1], "disconnect") == 0) {
        const kern_return_t kr = wifi_disconnect(conn, 3U);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr, "error: DISCONNECT failed: 0x%08x\n", kr);
            rc = 1;
        } else {
            printf("Disconnected.\n");
        }
    } else {
        print_usage(argv[0]);
        rc = 2;
    }

    IOServiceClose(conn);
    IOObjectRelease(svc);
    return rc;
}
