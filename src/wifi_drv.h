// SPDX-License-Identifier: BSD-3-Clause
/* The contract between the station core (usbwifi_core.c) and a USB Wi-Fi chip driver.
 *
 * A driver binds one dongle per process, runs the radio and moves frames; the core owns everything
 * above that (scan list, connection state, WPA2 EAPOL queue, the feth/BPF network side, adapter slot).
 * To add a chip: implement struct wifi_drv in src/drv_<chip>.c and list it in wifi_drivers[]
 * (usbwifi_core.c). Firmware loading or USB mode switching that must run before the dongle shows its
 * Wi-Fi interface belongs in the driver's open().
 *
 * Events may run on driver threads: copy what you need and return quickly. A driver never calls
 * back into the core except through these events.
 */
#ifndef WIFI_DRV_H
#define WIFI_DRV_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* filled by open() */
struct wifi_drv_info {
	uint8_t mac[6];
	bool band_5g;            /* the radio can use 5 GHz */
	char chip[32];           /* shown to the user, e.g. "RTL8852BU" */
	char fw_version[64];
	uint32_t chip_id, fw_version_num, fw_features; /* diagnostics, 0 if unknown */
};

/* the outcome of connect(), reported once per connect() call */
struct wifi_drv_assoc {
	uint16_t status;         /* 802.11 status code, 0 = associated */
	uint8_t bssid[6];
	uint16_t freq;           /* MHz */
	uint8_t band, width;     /* wifi_ctl.h band / channel width codes */
	bool qos;
};

struct wifi_drv_events {
	/* a beacon or probe response: the whole 802.11 frame without FCS */
	void (*bss)(const uint8_t *mgmt, size_t len, uint16_t freq, int8_t rssi);
	void (*scan_done)(bool aborted);
	/* an Ethernet II frame from the AP, in order */
	void (*rx)(const uint8_t *eth, size_t len, bool is_eapol);
	void (*assoc)(const struct wifi_drv_assoc *a);
	/* the link went away (deauth, disassoc, beacon loss) */
	void (*disconnected)(uint16_t reason);
	/* the dongle is unplugged or wedged: the core exits so the supervisor starts a fresh worker */
	void (*gone)(void);
};

struct wifi_connect_params {
	uint8_t bssid[6];
	uint16_t freq;           /* MHz, 0 = any */
	uint8_t band;
	const uint8_t *ssid;
	uint8_t ssid_len;
	uint8_t auth_type;       /* 0 = open system, 3 = SAE */
	uint32_t flags;          /* wifi_ctl.h connect flags */
	uint16_t ctrl_port_ethertype;
	const uint8_t *ie;       /* RSN IE to put in the association request, or NULL */
	size_t ie_len;
};

struct wifi_drv {
	const char *name;
	/* bind the first supported dongle no other process holds and bring the radio up; 0 or -errno.
	   Returns quickly with -ENODEV when nothing is plugged: the core retries. */
	int (*open)(const struct wifi_drv_events *ev, struct wifi_drv_info *info, int timeout_ms);
	/* ssid_len 0 = wildcard; n_freqs 0 = every allowed channel. Results come as bss() + scan_done(). */
	int (*scan)(const uint8_t *ssid, uint8_t ssid_len, const uint16_t *freqs, int n_freqs);
	/* starts authentication + association; >0 = immediate 802.11 status (rejected), <0 = -errno.
	   On 0 the result comes as assoc(), which may already have run when this returns. */
	int (*connect)(const struct wifi_connect_params *p);
	void (*disconnect)(uint16_t reason);
	/* cipher: 00-0F-AC suite selector as one big-endian u32, e.g. 0x000FAC04 = CCMP-128 */
	int (*add_key)(bool pairwise, uint8_t idx, uint32_t cipher, const uint8_t *key, uint8_t len);
	/* open or close the 802.1X controlled port after the 4-way handshake */
	int (*set_authorized)(bool on);
	int (*tx)(const uint8_t *eth, size_t len);
	/* optional (NULL = nothing to do) */
	void (*system_woke)(void);
};

extern const struct wifi_drv wifi_drv_aic8800, wifi_drv_rtw89;

/* provided by the core: call before libusb_open() of a dongle you may bind. -EBUSY = another worker
   drives it, skip it without opening (on macOS, opening + claiming a dongle another process drives
   "seizes" it and disturbs that process's transfers). The lock is held until the next call,
   wifi_usb_unlock(), or process exit. */
struct libusb_device;
int wifi_usb_lock(struct libusb_device *dev);
void wifi_usb_unlock(void);
#endif
