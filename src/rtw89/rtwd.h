// SPDX-License-Identifier: BSD-3-Clause
/* Station API over the ported rtw89 driver (src/lkpi + third_party/rtw89).
 * Callbacks run on driver threads: copy what you need and return quickly.
 * Never call rtwd_* from a callback: scan_done and disconnected can run with the driver's locks held. */
#ifndef RTWD_H
#define RTWD_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct rtwd_cb {
	/* a beacon or probe response: the whole 802.11 frame without FCS */
	void (*bss)(const uint8_t *mgmt, size_t len, uint16_t freq, int8_t rssi);
	void (*scan_done)(bool aborted);
	/* an Ethernet II frame from the AP */
	void (*rx)(const uint8_t *eth, size_t len, bool is_eapol);
	/* the link went away (deauth, disassoc, beacon loss or unplug) */
	void (*disconnected)(uint16_t reason);
};

/* binds the first supported dongle, loads firmware, starts the radio; country: ISO alpha2 picking
   the chip's TX-power table */
int rtwd_open(const struct rtwd_cb *cb, uint8_t mac[6], int timeout_ms, const char *country);
/* console-user half of plug-in: switch any Realtek driver CD (0bda:1a2b) to Wi-Fi mode; 0 once none is left */
int lkpi_usb_eject_cd(int timeout_ms);
bool rtwd_gone(void);
const char *rtwd_chip(void);
/* ssid_len 0 = wildcard; freqs NULL/n 0 = every allowed channel */
int rtwd_scan(const uint8_t *ssid, uint8_t ssid_len, const uint16_t *freqs, int n);
struct wifi_ft;
/* blocks until associated or failed; the BSS must be in the last scan. ft: 802.11r, see wifi_drv.h, or NULL */
int rtwd_connect(const uint8_t bssid[6], uint16_t freq, const uint8_t *ssid, uint8_t ssid_len,
		 const uint8_t *rsn_ie, size_t rsn_len, struct wifi_ft *ft);
void rtwd_disconnect(uint16_t reason);
/* LED: 0 slow blink (not connected), 1 fast blink (connecting), 2 on (connected); safe from callbacks */
void rtwd_led(int mode);
/* cipher_suite: 00-0F-AC selector as one big-endian u32, e.g. 0x000FAC04 (CCMP-128) */
int rtwd_add_key(bool pairwise, uint8_t idx, uint32_t cipher_suite, const uint8_t *key, uint8_t len);
int rtwd_set_authorized(bool on);
int rtwd_tx_eth(const uint8_t *eth, size_t len);
/* rtw89 LPS while associated (vif->cfg.ps); kept across connects */
int rtwd_power_save(bool on);
/* station address, only while not connected or scanning; -EBUSY otherwise */
int rtwd_set_mac(const uint8_t mac[6]);
/* the current AP's signal in dBm, 0 when not connected or no sample yet */
int rtwd_rssi(void);
/* channels from the AP's last 11k neighbor report or 11v BSS transition request (btm: the AP asked us to
   move, bssid = its preferred target); 0 when none since the last call */
int rtwd_roam_hint(uint16_t freqs[8], uint8_t bssid[6], bool *btm);
#endif
