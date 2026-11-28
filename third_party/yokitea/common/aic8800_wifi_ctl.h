/*
 * aic8800_wifi_ctl.h - AIC8800 LMAC TX queue / TID defaults, cipher codes and SCANU_START_REQ builder.
 * The chip-independent station types and IE parsers are in src/wifi_ctl.h.
 */

#ifndef AIC8800_WIFI_CTL_H
#define AIC8800_WIFI_CTL_H

#include "aic8800_abi.h"
#include "aic8800_framing.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Firmware AC / TID defaults for STA data & EAPOL frames (rwnx_txq.h) */
#define AIC_RWNX_HWQ_BE             1U
#define AIC_STA_DEFAULT_TID         0U
#define AIC_STA_NONQOS_TID          0xFFU

/* LMAC mac_cipher_suite enum (lmac_mac.h:150-178) */
enum aic_mac_cipher_suite {
    AIC_CIPHER_WEP40        = 0U,
    AIC_CIPHER_TKIP         = 1U,
    AIC_CIPHER_CCMP         = 2U,
    AIC_CIPHER_WEP104       = 3U,
    AIC_CIPHER_WPI_SMS4     = 4U,
    AIC_CIPHER_BIP_CMAC_128 = 5U,
    AIC_CIPHER_GCMP_128     = 6U,
    AIC_CIPHER_GCMP_256     = 7U,
    AIC_CIPHER_CCMP_256     = 8U,
    AIC_CIPHER_BIP_GMAC_128 = 9U,
    AIC_CIPHER_BIP_GMAC_256 = 10U,
    AIC_CIPHER_BIP_CMAC_256 = 11U,
    AIC_CIPHER_INVALID      = 0xFFU,
};

/*
 * Build SCANU_START_REQ matching Linux rwnx_send_scanu_req (<= 42 channels).
 */
static inline void aic_build_scanu_start_req(aic_scanu_start_req_t *req,
                                             uint8_t vif_idx,
                                             bool include_5g,
                                             const uint8_t *ssid,
                                             uint8_t ssid_len,
                                             bool no_cck) {
    static const uint16_t kChan2g4Freqs[13] = {
        2412, 2417, 2422, 2427, 2432, 2437, 2442,
        2447, 2452, 2457, 2462, 2467, 2472
    };
    static const uint16_t kChan5gFreqs[25] = {
        5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320,
        5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640, 5660, 5680, 5700, 5720,
        5745, 5765, 5785, 5805, 5825
    };

    memset(req, 0, sizeof(*req));
    req->vif_idx = vif_idx;
    memset(req->bssid.array, 0xFF, AIC_MAC_ADDR_LEN);
    req->no_cck = no_cck ? 1U : 0U;

    /* Active wildcard scan if ssid_len == 0, directed probe if ssid_len > 0 */
    req->ssid_cnt = 1U;
    if (ssid && ssid_len > 0U) {
        const uint8_t cpy = (ssid_len <= AIC_MAC_SSID_LEN) ? ssid_len : (uint8_t)AIC_MAC_SSID_LEN;
        req->ssid[0].length = cpy;
        memcpy(req->ssid[0].array, ssid, cpy);
    } else {
        req->ssid[0].length = 0U;
    }

    uint8_t idx = 0U;
    for (uint8_t i = 0U; i < 13U && idx < AIC_SCAN_CHANNEL_MAX; ++i) {
        req->chan[idx].freq     = kChan2g4Freqs[i];
        req->chan[idx].band     = AIC_PHY_BAND_2G4;
        req->chan[idx].tx_power = 20;
        req->chan[idx].flags    = (i >= 11U) ? AIC_CHAN_NO_IR : 0U;
        idx++;
    }
    if (include_5g) {
        for (uint8_t i = 0U; i < 25U && idx < AIC_SCAN_CHANNEL_MAX; ++i) {
            const uint16_t f = kChan5gFreqs[i];
            const bool is_dfs = ((f >= 5260U && f <= 5320U) || (f >= 5500U && f <= 5720U));
            req->chan[idx].freq     = f;
            req->chan[idx].band     = AIC_PHY_BAND_5G;
            req->chan[idx].tx_power = 20;
            req->chan[idx].flags    = is_dfs ? (uint8_t)(AIC_CHAN_NO_IR | AIC_CHAN_RADAR) : 0U;
            idx++;
        }
    }
    req->chan_cnt = idx;
}

#ifdef __cplusplus
}
#endif

#endif /* AIC8800_WIFI_CTL_H */
