/*
 * usbwifi_core.h - what usbwifid calls to drive one USB Wi-Fi dongle: the station core
 * (usbwifi_core.c) over a chip driver (wifi_drv.h). The calls keep the shape of the IOKit user
 * client the yokitea aic8800_wifi tool used, so the conn/svc handles are placeholders.
 */
#ifndef USBWIFI_CORE_H
#define USBWIFI_CORE_H

#include <IOKit/IOKitLib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "wifi_ctl.h"

/* One process drives one dongle. Each dongle gets a slot N, fixed by its MAC address, that picks its
   host-visible interface feth(80+2N) (gets DHCP) and the peer feth(81+2N) (the driver's BPF endpoint). */
#define WIFI_MAX_SLOTS 16
#define WIFI_CONF_DIR "/Library/Application Support/USB Wifi"
#ifndef WIFI_RUN_DIR /* tests point it at a scratch dir */
#define WIFI_RUN_DIR  "/var/run/usbwifi" /* <slot>.sock control sockets, usb-<location> dongle locks */
#endif
extern char wifi_if_host[16], wifi_if_peer[16];
int wifi_slot(void); /* -1 until a dongle is bound */

/* binds the first free supported dongle on the first call; 0 once one is up */
int  wifi_open(io_connect_t *out_conn, io_service_t *out_svc, bool quiet, kern_return_t *out_kr);
void wifi_ifname(io_service_t svc, char *buf, size_t cap);

kern_return_t wifi_get_status(io_connect_t conn, wifi_status_t *out);
/* freqs/n_freqs: restrict the scan to these channels (n_freqs == 0: all channels) */
kern_return_t wifi_start_scan(io_connect_t conn, const uint8_t *ssid, uint8_t ssid_len,
                              const uint16_t *freqs, int n_freqs);
kern_return_t wifi_get_scan_results(io_connect_t conn, wifi_scan_list_t *out);
kern_return_t wifi_connect(io_connect_t conn, const wifi_connect_req_t *in_req, wifi_connect_req_t *out_resp);
struct wifi_ft;
bool wifi_has_ft(void); /* the driver does 802.11r FT-PSK (RTL only) */
/* wifi_connect with FT (wifi_drv.h struct wifi_ft); kIOReturnUnsupported when the AP or driver has no FT */
kern_return_t wifi_connect_ft(io_connect_t conn, const wifi_connect_req_t *in_req, wifi_connect_req_t *out_resp,
                              struct wifi_ft *ft);
kern_return_t wifi_disconnect(io_connect_t conn, uint16_t reason);
kern_return_t wifi_poll_eapol(io_connect_t conn, wifi_eapol_frame_t *out);
kern_return_t wifi_send_eapol(io_connect_t conn, const uint8_t *eth, size_t len);
const char *wifi_chip_name(void); /* "" until an adapter is up */
void wifi_system_woke(void);
bool wifi_has_power_save(void);
int  wifi_set_power_save(bool on); /* -EOPNOTSUPP when the driver has none */
bool wifi_has_set_mac(void);
bool wifi_has_rssi(void);
int  wifi_get_rssi(void);
int  wifi_roam_hint(uint16_t freqs[8], uint8_t bssid[6], bool *btm); /* 11k/11v, 0 = none */ /* dBm of the current AP, 0 = unknown or unsupported */
int  wifi_set_mac(const uint8_t *mac); /* NULL = the dongle's own; only while not connected */
kern_return_t wifi_add_key(io_connect_t conn, uint8_t key_idx, bool pairwise, uint8_t cipher,
                           const uint8_t *key, uint8_t key_len, uint8_t *out_hw_idx);
kern_return_t wifi_set_port_link(io_connect_t conn, bool open_port, bool link_up);

/* placeholder handles: one process drives one dongle */
#define IOServiceClose(c)  ((void)(c), KERN_SUCCESS)
#define IOObjectRelease(o) ((void)(o), KERN_SUCCESS)

#endif
