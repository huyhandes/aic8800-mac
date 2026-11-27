/* drv_rtw89.c - Realtek RTL8852BU chip driver (see wifi_drv.h): the upstream Linux rtw89 driver on the
 * src/lkpi mac80211 shim, reached through its station API (rtwd.h). */
#include "wifi_drv.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "rtwd.h"

static const struct wifi_drv_events *ev;

static void on_bss(const uint8_t *mgmt, size_t len, uint16_t freq, int8_t rssi) { ev->bss(mgmt, len, freq, rssi); }
static void on_scan_done(bool aborted) { ev->scan_done(aborted); }
static void on_rx(const uint8_t *eth, size_t len, bool is_eapol) { ev->rx(eth, len, is_eapol); }
static void on_disconnected(uint16_t reason) { ev->disconnected(reason); }
static const struct rtwd_cb cb = { on_bss, on_scan_done, on_rx, on_disconnected };

/* rtwd reports an unplug only through rtwd_gone() */
static void *gone_watch(void *arg) {
	(void)arg;
	while (!rtwd_gone())
		usleep(500000);
	ev->gone();
	return NULL;
}

static int rtw_open(const struct wifi_drv_events *events, struct wifi_drv_info *info, int timeout_ms) {
	ev = events;
	int rc = rtwd_open(&cb, info->mac, timeout_ms);
	if (rc)
		return -ENODEV; /* rtwd_open fails the same way for "not plugged" and "probe hiccup": retry both */
	pthread_t t;
	if (pthread_create(&t, NULL, gone_watch, NULL) == 0)
		pthread_detach(t);
	info->band_5g = true;
	snprintf(info->chip, sizeof(info->chip), "%s", rtwd_chip());
	snprintf(info->fw_version, sizeof(info->fw_version), "%s", rtwd_chip());
	return 0;
}

static int rtw_scan(const uint8_t *ssid, uint8_t ssid_len, const uint16_t *freqs, int n) {
	return rtwd_scan(ssid_len ? ssid : NULL, ssid_len, freqs, n);
}

/* synchronous: auth + assoc are done when rtwd_connect returns */
static int rtw_connect(const struct wifi_connect_params *p) {
	int rc = rtwd_connect(p->bssid, p->freq, p->ssid, p->ssid_len, p->ie_len ? p->ie : NULL, p->ie_len);
	struct wifi_drv_assoc a = { .status = rc ? 1 : 0, .freq = p->freq, .band = p->band, .qos = true };
	memcpy(a.bssid, p->bssid, 6);
	if (rc)
		fprintf(stderr, "rtw89: connect failed: %d\n", rc);
	ev->assoc(&a); /* any non-zero status reads as "rejected" upstream */
	return 0;
}

/* RTL8852BU loses MAC power state across system sleep (rtw89 "mac preinit fail" -60 after wake);
   restart like an unplug so the supervisor re-binds and reloads firmware.
   shortcut: full ~3 s re-probe on every wake, upgrade to rtw89 suspend/resume ops if wake latency matters */
static void rtw_woke(void) { ev->gone(); }

const struct wifi_drv wifi_drv_rtw89 = {
	.name = "rtw89",
	.open = rtw_open,
	.scan = rtw_scan,
	.connect = rtw_connect,
	.disconnect = rtwd_disconnect,
	.add_key = rtwd_add_key,
	.set_authorized = rtwd_set_authorized,
	.tx = rtwd_tx_eth,
	.system_woke = rtw_woke,
};
