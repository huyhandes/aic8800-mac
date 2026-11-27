/* SPDX-License-Identifier: BSD-3-Clause */
/* self-check of the EAPOL-Key state machine: SNonce reuse on a retransmitted M1, M1 never touching the
   live PTK, replay and forged-MIC drops, and no reinstall of a key we already hold (KRACK) */
#include <assert.h>
#include <stdio.h>
#include "aic8800_wpa2.h"

#define PW   AIC_KEY_INFO_PAIRWISE
#define ACK  AIC_KEY_INFO_ACK
#define MIC  AIC_KEY_INFO_MIC
#define SEC  AIC_KEY_INFO_SECURE
#define ENC  AIC_KEY_INFO_ENC_KEY_DATA

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
	info |= AIC_KEY_INFO_VER_HMAC_SHA1;
	p[0] = 2; p[1] = 3; p[2] = (uint8_t)(body >> 8); p[3] = (uint8_t)body;
	k[0] = 2; k[1] = (uint8_t)(info >> 8); k[2] = (uint8_t)info;
	k[12] = replay;
	memset(k + 13, anonce, 32);
	k[93] = 0; k[94] = (uint8_t)kd_len;
	memcpy(k + 95, kd, kd_len);
	if (ptk)
		assert(aic_wpa2_compute_eapol_mic(AIC_KEY_INFO_VER_HMAC_SHA1, ptk, p, 4 + body, k + 77) == 0);
	return 14 + 4 + body;
}

int main(void)
{
	static const uint8_t spa[6] = { 2 }, aa[6] = { 4 }, pmk[32] = { 1 }, zero[64] = { 0 };
	aic_wpa2_ctx_t c;
	uint8_t f[256], out[512], sn[32], ptk[64];
	size_t ol;
	bool kr, gr;
#define RX(len) aic_wpa2_handle_rx_eapol(&c, f, (len), out, sizeof(out), &ol, &kr, &gr)

	aic_wpa2_ctx_init(&c, spa, aa, pmk, NULL, 0, AIC_CIPHER_CCMP, AIC_CIPHER_CCMP);
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
	puts("wpa2_test ok");
	return 0;
}
