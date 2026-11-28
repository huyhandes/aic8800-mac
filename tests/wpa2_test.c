/* SPDX-License-Identifier: BSD-3-Clause */
/* self-check of the EAPOL-Key state machine: SNonce reuse on a retransmitted M1, M1 never touching the
   live PTK, replay and forged-MIC drops, and no reinstall of a key we already hold (KRACK) */
#include <assert.h>
#include <stdio.h>
#include "ft.h"
#include "wifi_ctl.h"
#include "wpa3.h"
#include "lkpi/ccmp.h"

#define PW   WPA_KEY_INFO_PAIRWISE
#define ACK  WPA_KEY_INFO_ACK
#define MIC  WPA_KEY_INFO_MIC
#define SEC  WPA_KEY_INFO_SECURE
#define ENC  WPA_KEY_INFO_ENC_KEY_DATA

/* EAPOL-Key frame (HMAC-SHA1 MIC); ptk != NULL signs it with ptk's KCK and, with gtk_byte != 0,
   wraps a GTK KDE (16 x gtk_byte, key id 1) under ptk's KEK */
static size_t frame(uint8_t *f, uint16_t info, uint8_t replay, uint8_t anonce, const uint8_t *ptk, uint8_t gtk_byte)
{
	uint8_t kd[32] = { 0 };
	size_t kd_len = 0;
	if (gtk_byte) {
		uint8_t kde[24] = { 0xdd, 22, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00 };
		memset(kde + 8, gtk_byte, 16);
		kd_len = sizeof(kd);
		assert(CCSymmetricKeyWrap(kCCWRAPAES, CCrfc3394_iv, CCrfc3394_ivLen, ptk + 16, 16, kde, sizeof(kde),
					  kd, &kd_len) == kCCSuccess);
	}
	const size_t body = 95 + kd_len;
	memset(f, 0, 14 + 4 + body);
	f[12] = 0x88; f[13] = 0x8e;
	uint8_t *p = f + 14, *k = p + 4;
	info |= WPA_KEY_INFO_VER_HMAC_SHA1;
	p[0] = 2; p[1] = 3; p[2] = (uint8_t)(body >> 8); p[3] = (uint8_t)body;
	k[0] = 2; k[1] = (uint8_t)(info >> 8); k[2] = (uint8_t)info;
	k[12] = replay;
	memset(k + 13, anonce, 32);
	k[93] = 0; k[94] = (uint8_t)kd_len;
	memcpy(k + 95, kd, kd_len);
	if (ptk)
		assert(wpa2_compute_eapol_mic(WPA_KEY_INFO_VER_HMAC_SHA1, ptk, p, 4 + body, k + 77) == 0);
	return 14 + 4 + body;
}

/* 802.11r FT-PSK hierarchy, expected values from an independent Python hashlib/hmac implementation of
   IEEE 802.11-2016 12.7.1.7 (PMK 00..1f, SSID "test", MDID 0x1234, R0KH "nas1", STA ..01, R1KH ..02) */
static const uint8_t k_ft_pmk_r0[32] = { 0xbd, 0xf8, 0x35, 0xe6, 0xab, 0x10, 0x9d, 0x25, 0xaa, 0xbe, 0x86, 0xc8, 0x2c, 0x4d, 0xd9, 0xd9, 0xcb, 0x7a, 0x60, 0x81, 0xe5, 0x5f, 0x45, 0x6c, 0x41, 0x0f, 0xfa, 0x75, 0xc0, 0x25, 0x2f, 0x9d };
static const uint8_t k_ft_r0_name[16] = { 0x51, 0x07, 0x98, 0xa6, 0x2b, 0x76, 0x47, 0x64, 0x9f, 0x51, 0x7a, 0xe1, 0xe2, 0xfa, 0xec, 0x7d };
static const uint8_t k_ft_pmk_r1[32] = { 0xc9, 0xad, 0x62, 0x07, 0x6f, 0x68, 0x42, 0x58, 0x71, 0x58, 0xa6, 0x61, 0x94, 0xc3, 0xd2, 0x39, 0x5c, 0xc4, 0x37, 0x03, 0xbb, 0xe2, 0xd5, 0x46, 0x74, 0x8d, 0xfb, 0x61, 0xfb, 0x0d, 0x0a, 0x2c };
static const uint8_t k_ft_r1_name[16] = { 0x7b, 0xde, 0xb0, 0x35, 0x54, 0x01, 0x6e, 0xb9, 0x00, 0xfd, 0x94, 0xfe, 0x80, 0x40, 0xa0, 0xb9 };
static const uint8_t k_ft_ptk[48] = { 0xb4, 0x98, 0x50, 0x16, 0xe5, 0x86, 0xe8, 0xa7, 0xf5, 0xbe, 0xbb, 0xd4, 0xc0, 0x05, 0xb8, 0x17, 0x5d, 0x86, 0x18, 0x77, 0xf8, 0x5a, 0xf8, 0x07, 0xf2, 0x9e, 0x78, 0x70, 0x85, 0xdf, 0xce, 0x66, 0x7f, 0x24, 0x1c, 0xf0, 0xfb, 0x34, 0xca, 0x4f, 0x2d, 0x36, 0xa7, 0x93, 0xe4, 0xf2, 0x28, 0xa5 };

static void test_ft(void)
{
	static const uint8_t pmk[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
					 23, 24, 25, 26, 27, 28, 29, 30, 31 };
	static const uint8_t md[2] = { 0x34, 0x12 }, sta[6] = { 2, 0, 0, 0, 0, 1 }, r1kh[6] = { 2, 0, 0, 0, 0, 2 };
	uint8_t r0[32], r0n[16], r1[32], r1n[16], sn[32], an[32], ptk[64];
	ft_pmk_r0(pmk, (const uint8_t *)"test", 4, md, (const uint8_t *)"nas1", 4, sta, r0, r0n);
	assert(!memcmp(r0, k_ft_pmk_r0, 32) && !memcmp(r0n, k_ft_r0_name, 16));
	ft_pmk_r1(r0, r0n, r1kh, sta, r1, r1n);
	assert(!memcmp(r1, k_ft_pmk_r1, 32) && !memcmp(r1n, k_ft_r1_name, 16));
	memset(sn, 0x11, 32);
	memset(an, 0x22, 32);
	ft_ptk(r1, sn, an, r1kh, sta, ptk);
	assert(!memcmp(ptk, k_ft_ptk, 48));

	/* FTE with R1KH, GTK (wrapped under the KEK) and R0KH subelements: the MIC ignores its own field */
	uint8_t fte[2 + 82 + 8 + 2 + 11 + 24 + 6] = { 55, sizeof(fte) - 2, 0, 3 }, gtk[16], k[16], idx, len;
	const uint8_t rsne[4] = { 48, 2, 1, 0 }, mde[5] = { 54, 3, 0x34, 0x12, 1 };
	uint8_t *e = fte + 84, mic[16], mic2[16];
	size_t wl = 24;
	e[0] = 1; e[1] = 6; memcpy(e + 2, r1kh, 6); e += 8;
	e[0] = 2; e[1] = 11 + 24; e[2] = 1; e[4] = 16;
	memset(gtk, 0x5a, 16);
	assert(CCSymmetricKeyWrap(kCCWRAPAES, CCrfc3394_iv, CCrfc3394_ivLen, ptk + 16, 16, gtk, 16, e + 13, &wl) ==
	       kCCSuccess && wl == 24);
	e += 2 + 11 + 24;
	e[0] = 3; e[1] = 4; memcpy(e + 2, "nas1", 4);
	assert(ft_mic(ptk, sta, r1kh, 6, rsne, mde, fte, mic) == 0);
	memcpy(fte + 4, mic, 16);
	assert(ft_mic(ptk, sta, r1kh, 6, rsne, mde, fte, mic2) == 0 && !memcmp(mic, mic2, 16));
	assert(ft_mic(ptk, sta, r1kh, 5, rsne, mde, fte, mic2) == 0 && memcmp(mic, mic2, 16));
	assert(ft_sub(fte, 1) == fte + 84 && ft_sub(fte, 3)[2] == 'n' && !ft_sub(fte, 4));
	assert(ft_gtk(ptk + 16, ft_sub(fte, 2), &idx, k, &len) == 0 && idx == 1 && len == 16 && !memcmp(k, gtk, 16));
	assert(ft_gtk(ptk, ft_sub(fte, 2), &idx, k, &len) != 0); /* wrong KEK */
	fte[1] = 90; /* a subelement running past the FTE is not returned */
	assert(!ft_sub(fte, 3));
}

/* an AP's FTE: MIC field zero, ANonce 0x22, the SNonce, R1KH-ID, optionally a GTK wrapped under kek, R0KH-ID "nas1" */
static size_t ap_fte(uint8_t *o, const uint8_t sn[32], const uint8_t *kek)
{
	static const uint8_t r1kh[6] = { 2, 0, 0, 0, 0, 2 }, gtk[16] = { 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
								  0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a };
	uint8_t *e = o + 84;
	size_t wl = 24;
	memset(o, 0, 84);
	o[0] = 55;
	o[3] = 3;
	memset(o + 20, 0x22, 32);
	memcpy(o + 52, sn, 32);
	e[0] = 1; e[1] = 6; memcpy(e + 2, r1kh, 6); e += 8;
	if (kek) {
		memset(e, 0, 13);
		e[0] = 2; e[1] = 11 + 24; e[2] = 1; e[4] = 16;
		assert(CCSymmetricKeyWrap(kCCWRAPAES, CCrfc3394_iv, CCrfc3394_ivLen, kek, 16, gtk, 16, e + 13, &wl) ==
		       kCCSuccess);
		e += 2 + 11 + 24;
	}
	e[0] = 3; e[1] = 4; memcpy(e + 2, "nas1", 4); e += 6;
	o[1] = (uint8_t)(e - o - 2);
	return (size_t)(e - o);
}

/* the daemon's FT flow against a simulated AP: initial association key data, FT auth, reassociation, response */
static void test_ft_flow(void)
{
	static const uint8_t pmk[32] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
					 23, 24, 25, 26, 27, 28, 29, 30, 31 };
	static const uint8_t sta[6] = { 2, 0, 0, 0, 0, 1 }, ap[6] = { 2, 0, 0, 0, 0, 2 }, mde[5] = { 54, 3, 0x34, 0x12, 1 };
	ft_state_t s;
	struct wifi_ft ft = { .md = { 0x34, 0x12, 1 } };
	uint8_t rsne[22], kd[255], sn0[32] = { 0 }, ies[400], out[300], mic[16];
	memset(&s, 0, sizeof(s));
	assert(wifi_build_wpa2_rsn_ie(rsne, WIFI_CIPHER_CCMP, false) == 22);
	rsne[19] = 4;
	memcpy(ft.resp, mde, 5);
	ft.resp_len = 5 + ap_fte(ft.resp + 5, sn0, NULL);
	const int kl = ft_initial(&s, pmk, (const uint8_t *)"test", 4, sta, rsne, &ft, kd, sizeof(kd));
	assert(kl == 40 + 5 + (int)ft.resp_len - 5 && !memcmp(s.pmk_r0, k_ft_pmk_r0, 32) && !memcmp(s.pmk_r1, k_ft_pmk_r1, 32));
	assert(kd[1] == 38 && kd[19] == 4 && kd[22] == 1 && !memcmp(kd + 24, k_ft_r1_name, 16) && !memcmp(kd + 40, mde, 5));
	assert(!memcmp(kd + 45, ft.resp + 5, ft.resp_len - 5));
	ft.resp_len = 5; /* no FTE: no FT */
	assert(ft_initial(&s, pmk, (const uint8_t *)"test", 4, sta, rsne, &ft, kd, sizeof(kd)) < 0);

	/* FT auth request, with the SNonce made fixed so the PTK matches the vector */
	const size_t al = ft_auth_ie(&s, ap, out);
	memset(s.snonce, 0x11, 32);
	assert(al == 40 + 5 + 2 + 82 + 6 && !memcmp(out + 24, s.r0_name, 16) && !memcmp(out + 40, mde, 5));
	assert(out[45] == 55 && out[48] == 0 && ft_sub(out + 45, 3)[1] == 4 && !ft_sub(out + 45, 1));

	/* auth response, then the reassociation request it yields */
	memcpy(ies, kd, 45);
	size_t il = 45 + ap_fte(ies + 45, s.snonce, NULL);
	const int rl = ft_reassoc_ie(&s, ies, il, out, sizeof(out));
	assert(rl == 40 + 5 + 2 + 82 + 8 + 6 && !memcmp(s.ptk, k_ft_ptk, 48) && !memcmp(out + 24, k_ft_r1_name, 16));
	assert(out[48] == 3 && ft_mic(k_ft_ptk, sta, ap, 5, out, out + 40, out + 45, mic) == 0 && !memcmp(mic, out + 49, 16));
	ies[45 + 52] ^= 1; /* not our SNonce */
	assert(ft_reassoc_ie(&s, ies, il, out + 200, 100) < 0);

	/* reassociation response: MIC with seq 6, the GTK under the KEK */
	memcpy(ft.resp, out, 45);
	ft.resp_len = 45 + ap_fte(ft.resp + 45, s.snonce, k_ft_ptk + 16);
	assert(ft_mic(k_ft_ptk, sta, ap, 6, ft.resp, ft.resp + 40, ft.resp + 45, ft.resp + 49) == 0);
	wpa2_ctx_t c;
	memset(&c, 0, sizeof(c));
	assert(ft_finish(&s, &ft, &c) == 0 && c.has_ptk && c.has_gtk && c.gtk_idx == 1 && c.gtk[0] == 0x5a);
	assert(!memcmp(c.ptk, k_ft_ptk, 48));
	ft.resp[49] ^= 1;
	assert(ft_finish(&s, &ft, &c) != 0);
}


/* IEEE 802.11-2020 Annex J.10 (as in hostap common_module_tests.c sae_tests) */
static const uint8_t k_sae_addr1[6] = { 0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87 };
static const uint8_t k_sae_addr2[6] = { 0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c };
static const uint8_t k_sae_local_rand[] = {
    0x99, 0x24, 0x65, 0xfd, 0x3d, 0xaa, 0x3c, 0x60,
    0xaa, 0x65, 0x65, 0xb7, 0xf6, 0x2a, 0x2a, 0x7f,
    0x2e, 0x12, 0xdd, 0x12, 0xf1, 0x98, 0xfa, 0xf4,
    0xfb, 0xed, 0x89, 0xd7, 0xff, 0x1a, 0xce, 0x94
};
static const uint8_t k_sae_local_mask[] = {
    0x95, 0x07, 0xa9, 0x0f, 0x77, 0x7a, 0x04, 0x4d,
    0x6a, 0x08, 0x30, 0xb9, 0x1e, 0xa3, 0xd5, 0xdd,
    0x70, 0xbe, 0xce, 0x44, 0xe1, 0xac, 0xff, 0xb8,
    0x69, 0x83, 0xb5, 0xe1, 0xbf, 0x9f, 0xb3, 0x22
};
static const uint8_t k_sae_local_commit[] = {
    0x13, 0x00, 0x2e, 0x2c, 0x0f, 0x0d, 0xb5, 0x24,
    0x40, 0xad, 0x14, 0x6d, 0x96, 0x71, 0x14, 0xce,
    0x00, 0x5c, 0xe1, 0xea, 0xb0, 0xaa, 0x2c, 0x2e,
    0x5c, 0x28, 0x71, 0xb7, 0x74, 0xf6, 0xc2, 0x57,
    0x5c, 0x65, 0xd5, 0xad, 0x9e, 0x00, 0x82, 0x97,
    0x07, 0xaa, 0x36, 0xba, 0x8b, 0x85, 0x97, 0x38,
    0xfc, 0x96, 0x1d, 0x08, 0x24, 0x35, 0x05, 0xf4,
    0x7c, 0x03, 0x53, 0x76, 0xd7, 0xac, 0x4b, 0xc8,
    0xd7, 0xb9, 0x50, 0x83, 0xbf, 0x43, 0x82, 0x7d,
    0x0f, 0xc3, 0x1e, 0xd7, 0x78, 0xdd, 0x36, 0x71,
    0xfd, 0x21, 0xa4, 0x6d, 0x10, 0x91, 0xd6, 0x4b,
    0x6f, 0x9a, 0x1e, 0x12, 0x72, 0x62, 0x13, 0x25,
    0xdb, 0xe1
};
static const uint8_t k_sae_peer_commit[] = {
    0x13, 0x00, 0x59, 0x1b, 0x96, 0xf3, 0x39, 0x7f,
    0xb9, 0x45, 0x10, 0x08, 0x48, 0xe7, 0xb5, 0x50,
    0x54, 0x3b, 0x67, 0x20, 0xd8, 0x83, 0x37, 0xee,
    0x93, 0xfc, 0x49, 0xfd, 0x6d, 0xf7, 0xe0, 0x8b,
    0x52, 0x23, 0xe7, 0x1b, 0x9b, 0xb0, 0x48, 0xd3,
    0x87, 0x3f, 0x20, 0x55, 0x69, 0x53, 0xa9, 0x6c,
    0x91, 0x53, 0x6f, 0xd8, 0xee, 0x6c, 0xa9, 0xb4,
    0xa6, 0x8a, 0x14, 0x8b, 0x05, 0x6a, 0x90, 0x9b,
    0xe0, 0x3e, 0x83, 0xae, 0x20, 0x8f, 0x60, 0xf8,
    0xef, 0x55, 0x37, 0x85, 0x80, 0x74, 0xdb, 0x06,
    0x68, 0x70, 0x32, 0x39, 0x98, 0x62, 0x99, 0x9b,
    0x51, 0x1e, 0x0a, 0x15, 0x52, 0xa5, 0xfe, 0xa3,
    0x17, 0xc2
};
static const uint8_t k_sae_kck[] = {
    0x1e, 0x73, 0x3f, 0x6d, 0x9b, 0xd5, 0x32, 0x56,
    0x28, 0x73, 0x04, 0x33, 0x88, 0x31, 0xb0, 0x9a,
    0x39, 0x40, 0x6d, 0x12, 0x10, 0x17, 0x07, 0x3a,
    0x5c, 0x30, 0xdb, 0x36, 0xf3, 0x6c, 0xb8, 0x1a
};
static const uint8_t k_sae_pmk[] = {
    0x4e, 0x4d, 0xfa, 0xb1, 0xa2, 0xdd, 0x8a, 0xc1,
    0xa9, 0x17, 0x90, 0xf9, 0x53, 0xfa, 0xaa, 0x45,
    0x2a, 0xe5, 0xc6, 0x87, 0x3a, 0xb7, 0x5b, 0x63,
    0x60, 0x5b, 0xa6, 0x63, 0xf8, 0xa7, 0xfe, 0x59
};
static const uint8_t k_sae_pmkid[] = {
    0x87, 0x47, 0xa6, 0x00, 0xee, 0xa3, 0xf9, 0xf2,
    0x24, 0x75, 0xdf, 0x58, 0xca, 0x1e, 0x54, 0x98
};

/* hostap common_module_tests.c sae_tests: H2E PWE for group 19 (the password identifier is HKDF-Extract input
   right after the password, so it is passed appended) */
static const uint8_t k_h2e_addr1[6] = { 0x00, 0x09, 0x5b, 0x66, 0xec, 0x1e };
static const uint8_t k_h2e_addr2[6] = { 0x00, 0x0b, 0x6b, 0xd9, 0x02, 0x46 };
static const uint8_t k_h2e_pwe[64] = {
    0xc9, 0x30, 0x49, 0xb9, 0xe6, 0x40, 0x00, 0xf8, 0x48, 0x20, 0x16, 0x49, 0xe9, 0x99, 0xf2, 0xb5,
    0xc2, 0x2d, 0xea, 0x69, 0xb5, 0x63, 0x2c, 0x9d, 0xf4, 0xd6, 0x33, 0xb8, 0xaa, 0x1f, 0x6c, 0x1e,
    0x73, 0x63, 0x4e, 0x94, 0xb5, 0x3d, 0x82, 0xe7, 0x38, 0x3a, 0x8d, 0x25, 0x81, 0x99, 0xd9, 0xdc,
    0x1a, 0x5e, 0xe8, 0x26, 0x9d, 0x06, 0x03, 0x82, 0xcc, 0xbf, 0x33, 0xe6, 0x14, 0xff, 0x59, 0xa0
};

static void test_sae(void)
{
    static const char pw[] = "mekmitasdigoat";
    static const uint8_t ssid[] = "byteme";
    static sae_t a, b;
    uint8_t ta[512], tb[512], rx[512];
    int la, lb;
    assert(sae_init(&a, k_h2e_addr1, k_h2e_addr2, ssid, 6, "mekmitasdigoatpsk4internet", 26) == 0);
    sae_pt_put(&a.C, ta, &a.pwe_h2e);
    assert(!memcmp(ta, k_h2e_pwe, 64));

    /* J.10: our commit from the given rand and mask, then the keys from the peer's commit */
    assert(sae_init(&a, k_sae_addr1, k_sae_addr2, ssid, 6, pw, strlen(pw)) == 0);
    assert(sae_set_commit(&a, k_sae_local_rand, k_sae_local_mask) == 0);
    assert(!memcmp(a.own_c, k_sae_local_commit + 2, 96));
    assert(sae_process_commit(&a, k_sae_peer_commit, sizeof(k_sae_peer_commit)) == 0);
    assert(!memcmp(a.kck, k_sae_kck, 32) && !memcmp(a.pmk, k_sae_pmk, 32) && !memcmp(a.pmkid, k_sae_pmkid, 16));
    assert(sae_process_commit(&a, k_sae_local_commit, sizeof(k_sae_local_commit)) != 0); /* reflection */

    /* two stations through sae_step: commits cross, confirms cross, both accept with one PMK */
    assert(sae_init(&a, k_sae_addr1, k_sae_addr2, ssid, 6, pw, strlen(pw)) == 0);
    assert(sae_init(&b, k_sae_addr2, k_sae_addr1, ssid, 6, pw, strlen(pw)) == 0);
    la = sae_step(&a, NULL, 0, ta, sizeof(ta));
    lb = sae_step(&b, NULL, 0, tb, sizeof(tb));
    assert(la == 6 + 96 && lb == 6 + 96);
    memcpy(rx, tb, (size_t)lb);
    lb = sae_step(&b, ta, (size_t)la, tb, sizeof(tb)); /* b's confirm */
    la = sae_step(&a, rx, 6 + 96, ta, sizeof(ta));     /* a's confirm */
    assert(la == 38 && lb == 38 && !memcmp(a.pmk, b.pmk, 32) && !memcmp(a.pmkid, b.pmkid, 16));
    memcpy(rx, tb, 38);
    rx[10] ^= 1;
    assert(sae_step(&a, rx, 38, ta, sizeof(ta)) == -1); /* a forged confirm */
    rx[10] ^= 1;
    assert(sae_step(&a, rx, 38, ta, sizeof(ta)) == 0);
    assert(sae_step(&b, ta, 38, tb, sizeof(tb)) == 0);
    rx[0] = 1, rx[2] = 77;                               /* unsupported group */
    assert(sae_step(&b, rx, 6, tb, sizeof(tb)) == -1);

    /* H2E: status 126 commits, the token comes back in a container, then the same exchange */
    assert(sae_init(&a, k_sae_addr1, k_sae_addr2, ssid, 6, pw, strlen(pw)) == 0);
    assert(sae_init(&b, k_sae_addr2, k_sae_addr1, ssid, 6, pw, strlen(pw)) == 0);
    la = sae_step(&a, NULL, 1, ta, sizeof(ta));
    lb = sae_step(&b, NULL, 1, tb, sizeof(tb));
    assert(la == 6 + 96 && ta[2] == 126 && lb == 6 + 96);
    {
        const uint8_t tok[] = { 1, 0, 76, 0, 19, 0, 255, 4, 93, 0xaa, 0xbb, 0xcc };
        assert(sae_step(&a, tok, sizeof(tok), ta, sizeof(ta)) == 6 + 96 + 6);
        assert(!memcmp(ta + 6 + 96, tok + 6, 6));
        la = 6 + 96; /* b never asked for the token: hand it the plain commit */
    }
    memcpy(rx, tb, (size_t)lb);
    lb = sae_step(&b, ta, (size_t)la, tb, sizeof(tb));
    la = sae_step(&a, rx, 6 + 96, ta, sizeof(ta));
    assert(la == 38 && lb == 38 && !memcmp(a.pmk, b.pmk, 32));
    assert(sae_step(&a, tb, 38, ta, sizeof(ta)) == 0 && sae_step(&b, ta, 38, tb, sizeof(tb)) == 0);
    assert(sae_init(&a, k_sae_addr1, k_sae_addr2, ssid, 6, pw, strlen(pw)) == 0);
    assert(sae_step(&a, NULL, 1, ta, sizeof(ta)) > 0);
    rx[2] = 0;                                           /* an H&P commit answering an H2E one */
    assert(sae_step(&a, rx, 6 + 96, ta, sizeof(ta)) == -1);
}

/* IEEE 802.11-2020 M.6.4 CCMP data frame, then a management frame round trip */
static void test_ccmp(void)
{
	static const uint8_t tk[16] = { 0xc9, 0x7c, 0x1f, 0x67, 0xce, 0x37, 0x11, 0x85, 0x51, 0x4a, 0x8a, 0x19, 0xf2, 0xbd, 0xd5, 0x2f };
	static const uint8_t f[44] = { 0x08, 0x48, 0xc3, 0x2c, 0x0f, 0xd2, 0xe1, 0x28, 0xa5, 0x7c, 0x50, 0x30, 0xf1, 0x84, 0x44,
				       0x08, 0xab, 0xae, 0xa5, 0xb8, 0xfc, 0xba, 0x80, 0x33, 0xf8, 0xba, 0x1a, 0x55, 0xd0, 0x2f,
				       0x85, 0xae, 0x96, 0x7b, 0xb6, 0x2f, 0xb6, 0xcd, 0xa8, 0xeb, 0x7e, 0x78, 0xa0, 0x50 };
	static const uint8_t c[36] = { 0x0c, 0xe7, 0x00, 0x20, 0x76, 0x97, 0x03, 0xb5, 0xf3, 0xd0, 0xa2, 0xfe, 0x9a, 0x3d, 0xbf,
				       0x23, 0x42, 0xa6, 0x43, 0xe4, 0x32, 0x46, 0xe8, 0x0c, 0x3c, 0x04, 0xd0, 0x19, 0x78, 0x45,
				       0xce, 0x0b, 0x16, 0xf9, 0x76, 0x23 };
	uint8_t o[128], d[26] = { 0xc0, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 2, 0x10, 0, 0, 0, 0x60, 0, 2, 0 };
	uint64_t pn;

	assert(ccmp_encrypt(tk, 0xb5039776e70cULL, f, 20, o) == 60 && !memcmp(o + 24, c, 36));
	assert(ccmp_decrypt(tk, o, 60, &pn) == 44 && pn == 0xb5039776e70cULL && !memcmp(o + 24, f + 24, 20));
	assert(ccmp_encrypt(tk, 7, d, 2, o) == 42 && o[1] == 0x40); /* deauth */
	o[40] ^= 1;
	assert(ccmp_decrypt(tk, o, 42, &pn) == -1);
	ccmp_encrypt(tk, 7, d, 2, o); /* the failed decrypt left the body CTR-decrypted */
	assert(ccmp_decrypt(tk, o, 42, &pn) == 26 && pn == 7 && !memcmp(o, d, 26));
}

static void test_bip(void)
{
	/* RFC 4493 examples 1 and 2 */
	static const uint8_t ck[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	static const uint8_t m[16] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
	static const uint8_t t0[16] = { 0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46 };
	static const uint8_t t1[16] = { 0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c };
	/* IEEE 802.11 M.9.1: broadcast deauth, IGTK key ID 4, IPN 4 */
	static const uint8_t igtk[16] = { 0x4e, 0xa9, 0x54, 0x3e, 0x09, 0xcf, 0x2b, 0x1e, 0xca, 0x66, 0xff, 0xc5, 0x8b, 0xde, 0xcb, 0xcf };
	uint8_t f[44] = { 0xc0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0x09, 0, 2, 0,
			  76, 16, 4, 0, 4, 0, 0, 0, 0, 0, 0x48, 0xdf, 0xbf, 0xa7, 0xb8, 0x27, 0x88, 0x72 };
	uint8_t mac[16];

	aes_cmac(ck, m, 0, mac);
	assert(!memcmp(mac, t0, 16));
	aes_cmac(ck, m, 16, mac);
	assert(!memcmp(mac, t1, 16));
	assert(bip_verify(igtk, 4, f, sizeof(f)) == 4);
	f[1] |= 0x08; /* a retry still verifies */
	assert(bip_verify(igtk, 4, f, sizeof(f)) == 4);
	assert(bip_verify(igtk, 5, f, sizeof(f)) == -1);
	f[24] ^= 1; /* reason code changed */
	assert(bip_verify(igtk, 4, f, sizeof(f)) == -1);
	assert(bip_verify(igtk, 4, f, 26) == -1);

	/* wpa2_igtk: the IGTK KDE behind a GTK KDE in wrapped key data; none without EncryptedKeyData */
	uint8_t kde[56] = { 0xdd, 22, 0x00, 0x0f, 0xac, 0x01, 0x01, 0x00 }, e[14 + 4 + 95 + 64] = { 0 }, k[22];
	wpa2_ctx_t c = { 0 };
	size_t n = 64;
	memcpy(kde + 24, (const uint8_t[]){ 0xdd, 28, 0x00, 0x0f, 0xac, 0x09, 4, 0, 7, 0, 0, 0, 0, 0 }, 14);
	memcpy(kde + 38, igtk, 16);
	kde[54] = 0xdd; /* padding */
	memset(c.ptk + 16, 0x5a, 16);
	assert(CCSymmetricKeyWrap(kCCWRAPAES, CCrfc3394_iv, CCrfc3394_ivLen, c.ptk + 16, 16, kde, sizeof(kde), e + 113, &n) == kCCSuccess && n == 64);
	e[19] = WPA_KEY_INFO_ENC_KEY_DATA >> 8;
	e[18 + 94] = 64;
	assert(wpa2_igtk(&c, e, sizeof(e), k) == 4 && !memcmp(k, igtk, 16) && k[16] == 7 && !k[17]);
	e[19] = 0;
	assert(wpa2_igtk(&c, e, sizeof(e), k) == 0);
}

/* wifi_parse_bss: a WPA2-PSK/CCMP beacon on 5 GHz with MFP required; a truncated frame is rejected */
static void test_parse_bss(void)
{
	uint8_t b[36 + 6 + 22] = { 0 }, rsne[22];
	wifi_scan_bss_t s;
	memcpy(&b[16], "\x02\x00\x00\x00\x00\x07", 6);
	b[34] = 0x11; /* ESS, privacy */
	memcpy(&b[36], "\x00\x04home", 6);
	wifi_build_wpa2_rsn_ie(rsne, WIFI_CIPHER_CCMP, false);
	rsne[20] = 0x40; /* RSN capabilities: MFPR */
	memcpy(&b[42], rsne, 22);
	assert(wifi_parse_bss(b, sizeof(b), 5180, -40, &s) == 0);
	assert(s.band == WIFI_BAND_5G && s.freq == 5180 && s.rssi == -40 && s.bssid[5] == 7);
	assert(s.ssid_len == 4 && !memcmp(s.ssid, "home", 4));
	assert(s.pairwise_cipher == WIFI_CIPHER_CCMP && s.group_cipher == WIFI_CIPHER_CCMP);
	assert(s.sec_mask == (WIFI_SEC_PRIVACY | WIFI_SEC_CCMP | WIFI_SEC_WPA2_PSK | WIFI_SEC_MFP_REQ));
	assert(wifi_parse_bss(b, 35, 2412, -40, &s) == -1);
}

int main(void)
{
	test_parse_bss();
	static const uint8_t spa[6] = { 2 }, aa[6] = { 4 }, pmk[32] = { 1 }, zero[64] = { 0 };
	wpa2_ctx_t c;
	uint8_t f[256], out[512], sn[32], ptk[64];
	size_t ol;
	bool kr, gr;
#define RX(len) wpa2_handle_rx_eapol(&c, f, (len), out, sizeof(out), &ol, &kr, &gr)

	wpa2_ctx_init(&c, spa, aa, pmk, NULL, 0, WIFI_CIPHER_CCMP, WIFI_CIPHER_CCMP);
	assert(RX(frame(f, PW | ACK, 1, 0xaa, NULL, 0)) == 1);
	memcpy(sn, c.snonce, 32);
	assert(RX(frame(f, PW | ACK, 2, 0xaa, NULL, 0)) == 1); /* retransmitted M1 keeps the SNonce */
	assert(memcmp(sn, c.snonce, 32) == 0);
	assert(RX(frame(f, PW | ACK, 3, 0xbb, NULL, 0)) == 1); /* new ANonce renews it */
	assert(memcmp(sn, c.snonce, 32) != 0);
	assert(memcmp(c.ptk, zero, 64) == 0 && !c.has_ptk);   /* M1 alone never sets the PTK */

	/* M3: a forged MIC is dropped, not fatal; the real one makes tptk the PTK and brings the GTK */
	assert(RX(frame(f, PW | ACK | MIC | SEC | ENC, 4, 0xbb, zero, 0x11)) == 0);
	assert(RX(frame(f, PW | ACK | MIC | SEC | ENC, 4, 0xbb, c.tptk, 0x11)) == 1 && kr && c.has_gtk);
	assert(memcmp(c.ptk, c.tptk, 64) == 0 && c.gtk[0] == 0x11 && c.gtk_idx == 1);
	memcpy(ptk, c.ptk, 64);
	assert(RX(frame(f, PW | ACK | MIC | SEC | ENC, 4, 0xbb, ptk, 0x11)) == 0);      /* replayed M3 */
	assert(RX(frame(f, PW | ACK | MIC | SEC | ENC, 5, 0xbb, ptk, 0x11)) == 1 && !kr); /* resent M3: no reinstall */

	/* an M1 forged after the handshake leaves the live PTK alone */
	assert(RX(frame(f, PW | ACK, 0, 0xcc, NULL, 0)) == 1 && memcmp(c.ptk, ptk, 64) == 0);

	/* group M1: new GTK installs, the same GTK again does not, a replay or a bad MIC is dropped */
	assert(RX(frame(f, ACK | MIC | SEC | ENC, 6, 0, ptk, 0x22)) == 1 && gr && c.gtk[0] == 0x22);
	assert(RX(frame(f, ACK | MIC | SEC | ENC, 6, 0, ptk, 0x33)) == 0 && c.gtk[0] == 0x22);
	assert(RX(frame(f, ACK | MIC | SEC | ENC, 7, 0, ptk, 0x22)) == 1 && !gr);
	assert(RX(frame(f, ACK | MIC | SEC | ENC, 8, 0, zero, 0x44)) == 0 && c.gtk[0] == 0x22);
	assert(RX(frame(f, ACK | MIC | SEC | ENC, 9, 0, ptk, 0x44)) == 1 && gr && c.gtk[0] == 0x44);

	/* truncated frame: dropped */
	assert(RX(20) == 0);

	/* random MAC: locally administered unicast, stable per network, different per network and per dongle */
	uint8_t m1[6], m2[6], m3[6], m4[6];
	wifi_random_mac(pmk, 0, (const uint8_t *)"home", 4, m1);
	wifi_random_mac(pmk, 0, (const uint8_t *)"home", 4, m2);
	wifi_random_mac(pmk, 0, (const uint8_t *)"cafe", 4, m3);
	wifi_random_mac(pmk, 1, (const uint8_t *)"home", 4, m4);
	assert((m1[0] & 3) == 2 && !memcmp(m1, m2, 6) && memcmp(m1, m3, 6) && memcmp(m1, m4, 6));
	test_ft();
	test_ft_flow();
	test_sae();
	test_ccmp();
	test_bip();
	puts("wpa2_test ok");
	return 0;
}
