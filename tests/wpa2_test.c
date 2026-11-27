/* SPDX-License-Identifier: BSD-3-Clause */
/* self-check: a retransmitted M1 keeps the SNonce (else the AP's M3 MIC fails); a new ANonce renews it */
#include <assert.h>
#include <stdio.h>
#include "aic8800_wpa2.h"

static size_t m1(uint8_t *f, uint8_t anonce_byte, uint8_t replay)
{
	memset(f, 0, 14 + 4 + 95);
	f[12] = 0x88; f[13] = 0x8e;
	uint8_t *p = f + 14, *k = p + 4;
	p[0] = 2; p[1] = 3; p[3] = 95;
	k[0] = 2; k[1] = 0x00; k[2] = 0x8a; /* ver 2, pairwise, ack */
	k[12] = replay;
	memset(k + 13, anonce_byte, 32);
	return 14 + 4 + 95;
}

int main(void)
{
	static const uint8_t spa[6] = { 2 }, aa[6] = { 4 }, pmk[32] = { 1 };
	aic_wpa2_ctx_t c;
	uint8_t f[256], out[512], sn[32];
	size_t ol;
	bool kr, gr;

	aic_wpa2_ctx_init(&c, spa, aa, pmk, NULL, 0, AIC_CIPHER_CCMP, AIC_CIPHER_CCMP);
	assert(aic_wpa2_handle_rx_eapol(&c, f, m1(f, 0xaa, 1), out, sizeof(out), &ol, &kr, &gr) == 1);
	memcpy(sn, c.snonce, 32);
	assert(aic_wpa2_handle_rx_eapol(&c, f, m1(f, 0xaa, 2), out, sizeof(out), &ol, &kr, &gr) == 1);
	assert(memcmp(sn, c.snonce, 32) == 0);
	assert(aic_wpa2_handle_rx_eapol(&c, f, m1(f, 0xbb, 3), out, sizeof(out), &ol, &kr, &gr) == 1);
	assert(memcmp(sn, c.snonce, 32) != 0);
	memcpy(sn, c.snonce, 32);
	c.ptk_done = true; /* after M3: same ANonce again is a new handshake */
	assert(aic_wpa2_handle_rx_eapol(&c, f, m1(f, 0xbb, 4), out, sizeof(out), &ol, &kr, &gr) == 1);
	assert(memcmp(sn, c.snonce, 32) != 0);
	puts("wpa2_test ok");
	return 0;
}
