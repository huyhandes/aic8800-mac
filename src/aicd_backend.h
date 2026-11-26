/*
 * aicd_backend.h - userspace replacement for AIC8800WiFi.kext.
 * Exposes the same uc_* calls the yokitea aic8800_wifi tool used over IOKit,
 * implemented in-process over libusb (USB) + feth/BPF (network side).
 */
#ifndef AICD_BACKEND_H
#define AICD_BACKEND_H

#include <IOKit/IOKitLib.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "aic8800_wifi_ctl.h"

/* Host-visible interface (gets DHCP) and its peer (driver's BPF endpoint). */
#define AICD_IF_HOST "feth80"
#define AICD_IF_PEER "feth81"

int  open_wifi_client(io_connect_t *out_conn, io_service_t *out_svc, bool quiet, kern_return_t *out_kr);
void get_bsd_name(io_service_t svc, char *buf, size_t cap);

kern_return_t uc_get_status(io_connect_t conn, aic_wifi_status_t *out);
kern_return_t uc_start_scan(io_connect_t conn, const uint8_t *ssid, uint8_t ssid_len);
kern_return_t uc_get_scan_results(io_connect_t conn, aic_wifi_scan_list_t *out);
kern_return_t uc_connect(io_connect_t conn, const aic_wifi_connect_req_t *in_req, aic_wifi_connect_req_t *out_resp);
kern_return_t uc_disconnect(io_connect_t conn, uint16_t reason);
kern_return_t uc_poll_eapol(io_connect_t conn, aic_wifi_eapol_frame_t *out);
kern_return_t uc_send_eapol(io_connect_t conn, const uint8_t *eth, size_t len);
kern_return_t uc_add_key(io_connect_t conn, uint8_t key_idx, bool pairwise, uint8_t cipher,
                         const uint8_t *key, uint8_t key_len, uint8_t *out_hw_idx);
kern_return_t uc_set_port_link(io_connect_t conn, bool open_port, bool link_up);

/* Fake handles: the tool calls these on conn/svc; the backend is a process singleton. */
#define IOServiceClose(c)  ((void)(c), KERN_SUCCESS)
#define IOObjectRelease(o) ((void)(o), KERN_SUCCESS)

#endif
