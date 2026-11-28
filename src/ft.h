/* SPDX-License-Identifier: BSD-3-Clause */
/* 802.11r FT-PSK, chip-independent. The daemon uses it only with a driver that has the optional
   wifi_drv op ft_connect (wifi_has_ft()). */
#ifndef FT_H
#define FT_H

#include "wpa2.h"
#include "wifi_drv.h"

/*
 * 802.11r FT-PSK key hierarchy and FTE MIC, IEEE 802.11-2016 12.7.1.7.3-5 and 13.8.4-5. XXKey = the PMK.
 * Elements are whole (ID, length, body). The FTE body is MIC control (2) MIC (16) ANonce (32) SNonce (32)
 * then subelements: 1 R1KH-ID, 2 GTK, 3 R0KH-ID.
 */
static inline void ft_pmk_r0(const uint8_t pmk[32], const uint8_t *ssid, uint8_t ssid_len, const uint8_t mdid[2],
                                 const uint8_t *r0kh, uint8_t r0kh_len, const uint8_t sta[6],
                                 uint8_t pmk_r0[32], uint8_t r0_name[16]) {
    uint8_t c[1 + 32 + 2 + 1 + 48 + 6], k[48], n[6 + 16], h[CC_SHA256_DIGEST_LENGTH];
    size_t p = 0U;
    c[p++] = ssid_len;
    memcpy(c + p, ssid, ssid_len);
    p += ssid_len;
    memcpy(c + p, mdid, 2U);
    p += 2U;
    c[p++] = r0kh_len;
    memcpy(c + p, r0kh, r0kh_len);
    p += r0kh_len;
    memcpy(c + p, sta, 6U);
    p += 6U;
    wpa_kdf_sha256(pmk, 32U, "FT-R0", c, p, k, 384U);
    memcpy(pmk_r0, k, 32U);
    memcpy(n, "FT-R0N", 6U);
    memcpy(n + 6, k + 32, 16U); /* PMK-R0Name-Salt */
    CC_SHA256(n, sizeof(n), h);
    memcpy(r0_name, h, 16U);
}

static inline void ft_pmk_r1(const uint8_t pmk_r0[32], const uint8_t r0_name[16], const uint8_t r1kh[6],
                                 const uint8_t sta[6], uint8_t pmk_r1[32], uint8_t r1_name[16]) {
    uint8_t n[6 + 16 + 12], h[CC_SHA256_DIGEST_LENGTH];
    memcpy(n, "FT-R1N", 6U);
    memcpy(n + 6, r0_name, 16U);
    memcpy(n + 22, r1kh, 6U);
    memcpy(n + 28, sta, 6U);
    wpa_kdf_sha256(pmk_r0, 32U, "FT-R1", n + 22, 12U, pmk_r1, 256U);
    CC_SHA256(n, sizeof(n), h);
    memcpy(r1_name, h, 16U);
}

static inline void ft_ptk(const uint8_t pmk_r1[32], const uint8_t snonce[32], const uint8_t anonce[32],
                              const uint8_t bssid[6], const uint8_t sta[6], uint8_t ptk[64]) {
    uint8_t c[76];
    memcpy(c, snonce, 32U);
    memcpy(c + 32, anonce, 32U);
    memcpy(c + 64, bssid, 6U);
    memcpy(c + 70, sta, 6U);
    memset(ptk, 0, 64U);
    wpa_kdf_sha256(pmk_r1, 32U, "FT-PTK", c, sizeof(c), ptk, 384U);
}

/* CMAC(KCK, STA || AP || seq || RSNE || MDE || FTE with its MIC zeroed): seq 5 reassoc request, 6 response */
static inline int ft_mic(const uint8_t kck[16], const uint8_t sta[6], const uint8_t ap[6], uint8_t seq,
                             const uint8_t *rsne, const uint8_t *mde, const uint8_t *fte, uint8_t mic[16]) {
    uint8_t b[13 + 3 * 257];
    size_t p = 13U;
    if (!rsne || !mde || !fte || fte[1] < 82U) {
        return -1;
    }
    memcpy(b, sta, 6U);
    memcpy(b + 6, ap, 6U);
    b[12] = seq;
    const uint8_t *e[3] = { rsne, mde, fte };
    for (int i = 0; i < 3; ++i) {
        memcpy(b + p, e[i], e[i][1] + 2U);
        p += e[i][1] + 2U;
    }
    memset(b + p - fte[1] - 2U + 4U, 0, 16U);
    aes128_cmac(kck, b, p, mic);
    return 0;
}

/* the FTE subelement with this ID (whole), or NULL */
static inline const uint8_t *ft_sub(const uint8_t *fte, uint8_t id) {
    for (size_t p = 2U + 82U; fte[1] >= 82U && p + 2U <= fte[1] + 2U && p + 2U + fte[p + 1U] <= fte[1] + 2U;
         p += 2U + fte[p + 1U]) {
        if (fte[p] == id) {
            return fte + p;
        }
    }
    return NULL;
}

/* GTK subelement: key info (2, key ID in bits 0-1), key length (1), RSC (8), AES key wrapped key */
static inline int ft_gtk(const uint8_t kek[16], const uint8_t *sub, uint8_t *idx, uint8_t gtk[WPA2_KEY_LEN],
                             uint8_t *len) {
    uint8_t plain[64];
    size_t plain_len = sizeof(plain);
    if (!sub || sub[1] < 11U + 24U || sub[1] > 11U + 8U + sizeof(plain) || (sub[1] - 11U) % 8U != 0U ||
        sub[4] == 0U || sub[4] > WPA2_KEY_LEN) {
        return -1;
    }
    if (CCSymmetricKeyUnwrap(kCCWRAPAES, CCrfc3394_iv, CCrfc3394_ivLen, kek, 16U, sub + 13, sub[1] - 11U, plain,
                             &plain_len) != kCCSuccess || plain_len < sub[4]) {
        return -1;
    }
    *idx = sub[2] & 3U;
    *len = sub[4];
    memcpy(gtk, plain, sub[4]);
    return 0;
}

/* ---- the daemon side of FT-PSK: the station's part of 802.11-2016 13.8 ---- */
typedef struct {
    bool ok; /* the keys below are from an FT-PSK association that completed: a roam in md can use them */
    uint8_t md[3], sta[6], r0kh[48], r0kh_len, pmk_r0[32], r0_name[16], rsne[22];
    uint8_t ap[6], snonce[32], anonce[32], r1kh[6], pmk_r1[32], ptk[64]; /* the association in progress */
} ft_state_t;

/* the element with this ID (whole), or NULL */
static inline const uint8_t *ft_ie(const uint8_t *ies, size_t len, uint8_t id) {
    for (size_t p = 0U; p + 2U <= len && p + 2U + ies[p + 1U] <= len; p += 2U + ies[p + 1U]) {
        if (ies[p] == id) {
            return ies + p;
        }
    }
    return NULL;
}

/* rsne (the 22-byte PSK form from wifi_build_wpa2_rsn_ie, AKM 4) with one PMKID */
static inline uint8_t *ft_put_rsne(uint8_t *o, const uint8_t rsne[22], const uint8_t pmkid[16]) {
    memcpy(o, rsne, 22U);
    o[1] = 38U;
    o[22] = 1U;
    o[23] = 0U;
    memcpy(o + 24, pmkid, 16U);
    return o + 40;
}

static inline uint8_t *ft_put_mde(uint8_t *o, const uint8_t md[3]) {
    o[0] = 54U;
    o[1] = 3U;
    memcpy(o + 2, md, 3U);
    return o + 5;
}

/* FTE: MIC control (element count), MIC, ANonce, SNonce, then R1KH-ID when r1kh and the R0KH-ID */
static inline uint8_t *ft_put_fte(uint8_t *o, const ft_state_t *s, uint8_t count, const uint8_t *r1kh) {
    uint8_t *e = o + 2;
    memset(e, 0, 82U);
    e[1] = count;
    if (count) {
        memcpy(e + 18, s->anonce, 32U);
    }
    memcpy(e + 50, s->snonce, 32U);
    e += 82;
    if (r1kh) {
        e[0] = 1U;
        e[1] = 6U;
        memcpy(e + 2, r1kh, 6U);
        e += 8;
    }
    e[0] = 3U;
    e[1] = s->r0kh_len;
    memcpy(e + 2, s->r0kh, s->r0kh_len);
    e += 2U + s->r0kh_len;
    o[0] = 55U;
    o[1] = (uint8_t)(e - o - 2);
    return e;
}

/* the R1KH-ID and R0KH-ID subelements of an FTE, checked */
static inline int ft_khs(const uint8_t *fte, uint8_t r1kh[6], ft_state_t *s) {
    const uint8_t *r1 = fte ? ft_sub(fte, 1U) : NULL, *r0 = fte ? ft_sub(fte, 3U) : NULL;
    if (!r1 || r1[1] != 6U || !r0 || r0[1] < 1U || r0[1] > 48U) {
        return -1;
    }
    memcpy(r1kh, r1 + 2, 6U);
    s->r0kh_len = r0[1];
    memcpy(s->r0kh, r0 + 2, r0[1]);
    return 0;
}

/*
 * Initial mobility domain association (assoc request: RSNE with AKM 4, the AP's MDE): from the association
 * response derive PMK-R0 and PMK-R1 and build the 4-way M2 key data, RSNE with PMKR1Name, MDE, and the
 * response's FTE byte for byte. pmk_r1 is the PMK for the 4-way. Key data length, or -1.
 */
static inline int ft_initial(ft_state_t *s, const uint8_t pmk[32], const uint8_t *ssid, uint8_t ssid_len,
                             const uint8_t sta[6], const uint8_t rsne[22], const struct wifi_ft *ft,
                             uint8_t *kd, size_t cap) {
    const uint8_t *fte = ft_ie(ft->resp, ft->resp_len, 55U);
    uint8_t r1kh[6], r1_name[16];
    if (!fte || fte[1] < 82U || ft_khs(fte, r1kh, s) != 0 || 40U + 5U + fte[1] + 2U > cap) {
        return -1;
    }
    s->ok = false;
    memcpy(s->md, ft->md, 3U);
    memcpy(s->sta, sta, 6U);
    memcpy(s->rsne, rsne, 22U);
    ft_pmk_r0(pmk, ssid, ssid_len, s->md, s->r0kh, s->r0kh_len, sta, s->pmk_r0, s->r0_name);
    ft_pmk_r1(s->pmk_r0, s->r0_name, r1kh, sta, s->pmk_r1, r1_name);
    uint8_t *o = ft_put_mde(ft_put_rsne(kd, rsne, r1_name), s->md);
    memcpy(o, fte, fte[1] + 2U);
    return (int)(o - kd) + fte[1] + 2;
}

/* FT roam, step 1: the FT authentication request's RSNE (PMKR0Name), MDE and FTE (SNonce, R0KH-ID) */
static inline size_t ft_auth_ie(ft_state_t *s, const uint8_t ap[6], uint8_t out[40 + 5 + 2 + 82 + 2 + 48]) {
    memcpy(s->ap, ap, 6U);
    arc4random_buf(s->snonce, 32U);
    return (size_t)(ft_put_fte(ft_put_mde(ft_put_rsne(out, s->rsne, s->r0_name), s->md), s, 0U, NULL) - out);
}

/* FT roam, step 2 (struct wifi_ft reassoc_ie): from the authentication response's ANonce and R1KH-ID
   derive PMK-R1 and the PTK, and build the reassociation request's RSNE, MDE and FTE with its MIC */
static inline int ft_reassoc_ie(void *arg, const uint8_t *ies, size_t len, uint8_t *out, size_t cap) {
    ft_state_t *s = arg;
    const uint8_t *fte = ft_ie(ies, len, 55U);
    uint8_t r1_name[16];
    if (!fte || fte[1] < 82U || memcmp(fte + 52, s->snonce, 32U) != 0 || ft_khs(fte, s->r1kh, s) != 0 ||
        cap < 40U + 5U + 2U + 82U + 8U + 2U + s->r0kh_len) {
        return -1;
    }
    memcpy(s->anonce, fte + 20, 32U);
    ft_pmk_r1(s->pmk_r0, s->r0_name, s->r1kh, s->sta, s->pmk_r1, r1_name);
    ft_ptk(s->pmk_r1, s->snonce, s->anonce, s->ap, s->sta, s->ptk);
    uint8_t *mde = ft_put_rsne(out, s->rsne, r1_name), *f = ft_put_mde(mde, s->md);
    uint8_t *end = ft_put_fte(f, s, 3U, s->r1kh);
    if (ft_mic(s->ptk, s->sta, s->ap, 5U, out, mde, f, f + 4) != 0) {
        return -1;
    }
    return (int)(end - out);
}

/* FT roam, step 3: check the reassociation response's MIC and nonces, then put the PTK and the GTK in c
   as a completed handshake, so the group key handshakes that follow work. 0, or -1 */
static inline int ft_finish(ft_state_t *s, const struct wifi_ft *ft, wpa2_ctx_t *c) {
    const uint8_t *rsne = ft_ie(ft->resp, ft->resp_len, 48U), *mde = ft_ie(ft->resp, ft->resp_len, 54U),
                  *fte = ft_ie(ft->resp, ft->resp_len, 55U);
    uint8_t mic[16];
    if (!fte || fte[1] < 82U || memcmp(fte + 20, s->anonce, 32U) != 0 || memcmp(fte + 52, s->snonce, 32U) != 0 ||
        ft_mic(s->ptk, s->sta, s->ap, 6U, rsne, mde, fte, mic) != 0 || memcmp(mic, fte + 4, 16U) != 0 ||
        ft_gtk(s->ptk + 16, ft_sub(fte, 2U), &c->gtk_idx, c->gtk, &c->gtk_len) != 0) {
        return -1;
    }
    memcpy(c->ptk, s->ptk, 64U);
    c->has_ptk = c->ptk_done = c->has_gtk = true;
    return 0;
}

#endif /* FT_H */
