/*
 * wifi_ctl.h - Station core types and 802.11 IE helpers: scan list, connect request, status,
 * cipher and security codes, Beacon/ProbeResp and RSN IE parsing.
 *
 * From yokitea AIC8800WiFi.kext (BSD-3, see third_party/yokitea/LICENSE); chip-independent.
 * The cipher, band and connect flag values equal the AIC8800 LMAC ones (drv_aic8800.c asserts it),
 * so that driver passes them to firmware unchanged. Other drivers take the 00-0F-AC suite
 * from wifi_drv.h and the frequency.
 */

#ifndef WIFI_CTL_H
#define WIFI_CTL_H

#include <CommonCrypto/CommonHMAC.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define WIFI_CTL_VERSION        1U

#define WIFI_MAX_SCAN_BSS       64U
#define WIFI_EAPOL_RING_CAP     16U
#define WIFI_EAPOL_MAX_FRAME    1600U
#define WIFI_CONNECT_IE_MAX     256U

#define WIFI_ADDR_LEN           6U
#define WIFI_SSID_LEN           32U
#define WIFI_KEY_LEN            32U

enum wifi_cipher {
    WIFI_CIPHER_WEP40        = 0U,
    WIFI_CIPHER_TKIP         = 1U,
    WIFI_CIPHER_CCMP         = 2U,
    WIFI_CIPHER_WEP104       = 3U,
    WIFI_CIPHER_BIP_CMAC_128 = 5U,
    WIFI_CIPHER_GCMP_128     = 6U,
    WIFI_CIPHER_GCMP_256     = 7U,
    WIFI_CIPHER_CCMP_256     = 8U,
    WIFI_CIPHER_INVALID      = 0xFFU,
};

/* Security capability bitmask extracted from Beacon/ProbeResp IEs */
enum wifi_sec_bits {
    WIFI_SEC_OPEN      = 0U,
    WIFI_SEC_PRIVACY   = (1U << 0U),
    WIFI_SEC_WPA_PSK   = (1U << 1U),
    WIFI_SEC_WPA2_PSK  = (1U << 2U),
    WIFI_SEC_WPA3_SAE  = (1U << 3U),
    WIFI_SEC_CCMP      = (1U << 4U),
    WIFI_SEC_TKIP      = (1U << 5U),
    WIFI_SEC_SHA256    = (1U << 6U),
    WIFI_SEC_MFP_REQ   = (1U << 7U),
    WIFI_SEC_8021X     = (1U << 8U),
};

#define WIFI_BAND_2G4               0U
#define WIFI_BAND_5G                1U

/* wifi_connect_req_t.flags */
#define WIFI_CONN_CONTROL_PORT_HOST (1U << 0U)  /* EAPOL goes through the host */
#define WIFI_CONN_WPA_WPA2_IN_USE   (1U << 3U)

typedef struct {
    uint32_t version;
    uint8_t  lmac_ready;
    uint8_t  scanning;
    uint8_t  scan_done;
    uint8_t  associated;

    uint8_t  link_up;
    uint8_t  is_5g_supported;
    uint8_t  vif_idx;
    uint8_t  ap_sta_idx;

    uint8_t  ap_qos;
    uint8_t  ap_band;
    uint8_t  ap_width;
    uint8_t  ssid_len;

    uint16_t ap_center_freq;
    uint16_t assoc_status;

    uint16_t disconnect_reason;
    uint16_t scan_count;

    uint32_t chip_id;
    uint32_t lmac_version;
    uint32_t fw_features;
    uint32_t eapol_rx_queued;

    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t eapol_rx_total;

    uint8_t  mac_addr[WIFI_ADDR_LEN];
    uint8_t  ap_bssid[WIFI_ADDR_LEN];
    uint8_t  ssid[WIFI_SSID_LEN];
    uint8_t  fw_version[64];
} wifi_status_t;

typedef struct {
    uint8_t  bssid[WIFI_ADDR_LEN];
    uint8_t  ssid_len;
    uint8_t  band;
    uint16_t freq;
    uint16_t cap_info;
    int8_t   rssi;
    uint8_t  pairwise_cipher;
    uint8_t  group_cipher;
    uint8_t  reserved;
    uint32_t sec_mask;
    uint8_t  ssid[WIFI_SSID_LEN];
    uint16_t rsn_capab;
    uint16_t pad;
} wifi_scan_bss_t; /* 56 bytes */

typedef struct {
    uint16_t            count;
    uint8_t             scanning;
    uint8_t             scan_done;
    uint32_t            reserved;
    wifi_scan_bss_t bss[WIFI_MAX_SCAN_BSS];
} wifi_scan_list_t; /* 8 + 64*56 = 3592 bytes */

typedef struct {
    uint8_t  ssid_len;
    uint8_t  auth_type; /* 0 = OPEN_SYSTEM, 3 = SAE */
    uint8_t  band;
    uint8_t  reserved;
    uint16_t freq;
    uint16_t ie_len;
    uint32_t flags;               /* WIFI_CONN_* */
    uint16_t ctrl_port_ethertype; /* network byte order (htons(0x888E)) */
    uint8_t  bssid[WIFI_ADDR_LEN];
    uint8_t  ssid[WIFI_SSID_LEN];
    uint8_t  ie_buf[WIFI_CONNECT_IE_MAX];
    uint8_t  out_status;
    uint8_t  pad[3];
} wifi_connect_req_t;

typedef struct {
    uint16_t len;
    uint8_t  has_frame;
    uint8_t  reserved;
    uint8_t  data[WIFI_EAPOL_MAX_FRAME];
} wifi_eapol_frame_t;

_Static_assert(sizeof(wifi_scan_bss_t) == 56U, "scan_bss packed 56B");
_Static_assert(sizeof(wifi_scan_list_t) <= 4096U, "scan_list fits 4096B");

static inline uint16_t wifi_get_le16(const uint8_t *b) {
    return (uint16_t)(b[0] | (b[1] << 8U));
}

/* WIFI_CIPHER_* of an RSN (00-0F-AC) or WPA (00-50-F2) cipher suite selector */
static inline uint8_t wifi_cipher_from_suite(const uint8_t suite[4]) {
    if ((suite[0] == 0x00U && suite[1] == 0x0FU && suite[2] == 0xACU) ||
        (suite[0] == 0x00U && suite[1] == 0x50U && suite[2] == 0xF2U)) {
        switch (suite[3]) {
            case 1U:  return WIFI_CIPHER_WEP40;
            case 2U:  return WIFI_CIPHER_TKIP;
            case 4U:  return WIFI_CIPHER_CCMP;
            case 5U:  return WIFI_CIPHER_WEP104;
            case 6U:  return WIFI_CIPHER_BIP_CMAC_128;
            case 8U:  return WIFI_CIPHER_GCMP_128;
            case 9U:  return WIFI_CIPHER_GCMP_256;
            case 10U: return WIFI_CIPHER_CCMP_256;
            default:  return WIFI_CIPHER_INVALID;
        }
    }
    return WIFI_CIPHER_INVALID;
}

/*
 * Parse an IEEE 802.11 RSN IE body (excluding Tag ID & Length bytes) into security mask/ciphers.
 */
static inline void wifi_parse_rsn_ie_body(const uint8_t *body,
                                          size_t body_len,
                                          wifi_scan_bss_t *out) {
    if (!body || !out || body_len < 2U) {
        return;
    }
    size_t pos = 2U; /* skip 2-byte Version (0x0001) */
    if (pos + 4U > body_len) {
        return;
    }
    out->group_cipher = wifi_cipher_from_suite(&body[pos]);
    pos += 4U;

    if (pos + 2U > body_len) {
        return;
    }
    const uint16_t pw_cnt = wifi_get_le16(&body[pos]);
    pos += 2U;
    if ((size_t)pw_cnt * 4U > body_len - pos) {
        return;
    }
    uint8_t best_pw = WIFI_CIPHER_INVALID;
    for (uint16_t i = 0U; i < pw_cnt; ++i) {
        const uint8_t c = wifi_cipher_from_suite(&body[pos + (size_t)i * 4U]);
        if (c == WIFI_CIPHER_CCMP) {
            out->sec_mask |= WIFI_SEC_CCMP;
            best_pw = WIFI_CIPHER_CCMP;
        } else if (c == WIFI_CIPHER_TKIP) {
            out->sec_mask |= WIFI_SEC_TKIP;
            if (best_pw == WIFI_CIPHER_INVALID) {
                best_pw = WIFI_CIPHER_TKIP;
            }
        }
    }
    if (best_pw != WIFI_CIPHER_INVALID) {
        out->pairwise_cipher = best_pw;
    }
    pos += (size_t)pw_cnt * 4U;

    if (pos + 2U > body_len) {
        return;
    }
    const uint16_t akm_cnt = wifi_get_le16(&body[pos]);
    pos += 2U;
    if ((size_t)akm_cnt * 4U > body_len - pos) {
        return;
    }
    for (uint16_t i = 0U; i < akm_cnt; ++i) {
        const uint8_t *akm = &body[pos + (size_t)i * 4U];
        if (akm[0] == 0x00U && akm[1] == 0x0FU && akm[2] == 0xACU) {
            if (akm[3] == 2U) {
                out->sec_mask |= WIFI_SEC_WPA2_PSK;
            } else if (akm[3] == 6U) {
                out->sec_mask |= (WIFI_SEC_WPA2_PSK | WIFI_SEC_SHA256);
            } else if (akm[3] == 8U) {
                out->sec_mask |= (WIFI_SEC_WPA3_SAE | WIFI_SEC_SHA256);
            } else if (akm[3] == 1U || akm[3] == 5U) {
                out->sec_mask |= WIFI_SEC_8021X;
            }
        }
    }
    pos += (size_t)akm_cnt * 4U;

    if (pos + 2U <= body_len) {
        out->rsn_capab = wifi_get_le16(&body[pos]);
        if ((out->rsn_capab & 0x0040U) != 0U) {
            out->sec_mask |= WIFI_SEC_MFP_REQ;
        }
    }
}

/*
 * Parse an IEEE 802.11 Beacon/ProbeResp (from the 24-byte mgmt header on) heard on freq.
 */
static inline int wifi_parse_bss(const uint8_t *mgmt,
                                 size_t frame_len,
                                 uint16_t freq,
                                 int8_t rssi,
                                 wifi_scan_bss_t *out) {
    /* 24B 802.11 mgmt header + 12B fixed beacon/probe-resp body = 36B minimum */
    if (!mgmt || !out || frame_len < 36U) {
        return -1;
    }

    memset(out, 0, sizeof(*out));
    memcpy(out->bssid, &mgmt[16], WIFI_ADDR_LEN);
    out->freq     = freq;
    out->band     = freq > 4000U ? WIFI_BAND_5G : WIFI_BAND_2G4;
    out->rssi     = rssi;
    out->cap_info = wifi_get_le16(&mgmt[34]);
    out->pairwise_cipher = WIFI_CIPHER_INVALID;
    out->group_cipher    = WIFI_CIPHER_INVALID;
    if ((out->cap_info & 0x0010U) != 0U) {
        out->sec_mask |= WIFI_SEC_PRIVACY;
    }

    size_t pos = 36U;
    while (pos + 2U <= frame_len) {
        const uint8_t tag = mgmt[pos];
        const uint8_t len = mgmt[pos + 1U];
        pos += 2U;
        if ((size_t)len > frame_len - pos) {
            break;
        }
        const uint8_t *val = &mgmt[pos];

        if (tag == 0U) { /* SSID */
            const uint8_t cpy = (len <= WIFI_SSID_LEN) ? len : (uint8_t)WIFI_SSID_LEN;
            out->ssid_len = cpy;
            if (cpy > 0U) {
                memcpy(out->ssid, val, cpy);
            }
        } else if (tag == 48U) { /* RSN IE */
            wifi_parse_rsn_ie_body(val, len, out);
        } else if (tag == 221U && len >= 4U &&
                   val[0] == 0x00U && val[1] == 0x50U && val[2] == 0xF2U && val[3] == 0x01U) {
            /* Legacy WPA Vendor IE */
            out->sec_mask |= WIFI_SEC_WPA_PSK;
            if (out->pairwise_cipher == WIFI_CIPHER_INVALID) {
                out->pairwise_cipher = WIFI_CIPHER_TKIP;
            }
        }

        pos += (size_t)len;
    }

    return 0;
}

/*
 * Build standard 22-byte RSN IE (Tag 48) for WPA2-PSK Association Request.
 */
static inline size_t wifi_build_wpa2_rsn_ie(uint8_t out_ie[22],
                                            uint8_t group_cipher,
                                            bool use_akm_sha256) {
    uint8_t grp_suite = 4U; /* CCMP */
    if (group_cipher == WIFI_CIPHER_TKIP) {
        grp_suite = 2U;
    } else if (group_cipher == WIFI_CIPHER_WEP40) {
        grp_suite = 1U;
    } else if (group_cipher == WIFI_CIPHER_WEP104) {
        grp_suite = 5U;
    }

    out_ie[0]  = 48U;   /* EID: RSN */
    out_ie[1]  = 20U;   /* Length */
    out_ie[2]  = 0x01U; /* Version LO */
    out_ie[3]  = 0x00U; /* Version HI */
    out_ie[4]  = 0x00U; /* Group Cipher OUI */
    out_ie[5]  = 0x0FU;
    out_ie[6]  = 0xACU;
    out_ie[7]  = grp_suite;
    out_ie[8]  = 0x01U; /* Pairwise Count = 1 */
    out_ie[9]  = 0x00U;
    out_ie[10] = 0x00U; /* Pairwise Cipher: CCMP */
    out_ie[11] = 0x0FU;
    out_ie[12] = 0xACU;
    out_ie[13] = 0x04U;
    out_ie[14] = 0x01U; /* AKM Count = 1 */
    out_ie[15] = 0x00U;
    out_ie[16] = 0x00U; /* AKM: PSK (02) or PSK-SHA256 (06) */
    out_ie[17] = 0x0FU;
    out_ie[18] = 0xACU;
    out_ie[19] = use_akm_sha256 ? 0x06U : 0x02U;
    out_ie[20] = 0x00U; /* RSN Capabilities */
    out_ie[21] = 0x00U;
    return 22U;
}

/* MAC randomization: a per-network station address, stable across connects, different per dongle (slot)
   and unlinkable without the secret. Locally administered unicast. */
static inline void wifi_random_mac(const uint8_t secret[32], int slot, const uint8_t *ssid, size_t ssid_len,
                                   uint8_t mac[6]) {
    uint8_t d[CC_SHA256_DIGEST_LENGTH], in[1 + 32];
    const size_t n = ssid_len > 32U ? 32U : ssid_len;
    in[0] = (uint8_t)slot;
    memcpy(in + 1, ssid, n);
    CCHmac(kCCHmacAlgSHA256, secret, 32U, in, 1U + n, d);
    memcpy(mac, d, 6);
    mac[0] = (uint8_t)((mac[0] & 0xfcU) | 0x02U);
}

#endif /* WIFI_CTL_H */
