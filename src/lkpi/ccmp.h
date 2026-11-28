/* SPDX-License-Identifier: BSD-3-Clause */
/* CCMP-128 (IEEE 802.11-2020 12.5.3) in software, for the protected management frames (PMF) the RTL8852B
   cannot encrypt itself (rtw8852b.c hw_mgmt_tx_encrypt = false). Frames have a 24-byte header (no QoS, no A4). */
#ifndef LKPI_CCMP_H
#define LKPI_CCMP_H

#include <CommonCrypto/CommonCryptor.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static inline void ccmp_aes(const uint8_t k[16], uint8_t b[16])
{
	size_t n;

	CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, k, 16, NULL, b, 16, b, 16, &n);
}

/* CTR-crypts d in place and returns the MIC over the plaintext (taken before when enc, after otherwise) */
static inline void ccmp_ccm(const uint8_t tk[16], const uint8_t *h, uint64_t pn, uint8_t *d, size_t n, bool enc,
			    uint8_t mic[8])
{
	const bool mgmt = (h[0] & 0x0c) == 0;
	uint8_t nonce[13], x[16], a[16], s[16];

	nonce[0] = mgmt ? 0x10 : 0; /* management flag, priority 0 */
	memcpy(nonce + 1, h + 10, 6);
	for (int i = 0; i < 6; i++)
		nonce[7 + i] = (uint8_t)(pn >> (40 - 8 * i));
	/* CBC-MAC: B0, then the AAD (FC without retry/pwrmgt/moredata, protected set, data subtype bits off,
	   A1 A2 A3, SC with the sequence number zeroed) behind its length */
	x[0] = 0x59;
	memcpy(x + 1, nonce, 13);
	x[14] = (uint8_t)(n >> 8), x[15] = (uint8_t)n;
	ccmp_aes(tk, x);
	{
		uint8_t aad[32] = { 0, 22, h[0] & (mgmt ? 0xff : 0x8f), (h[1] & 0xc7) | 0x40 };

		memcpy(aad + 4, h + 4, 18);
		aad[22] = h[22] & 0x0f;
		for (int b = 0; b < 2; b++) {
			for (int i = 0; i < 16; i++)
				x[i] ^= aad[16 * b + i];
			ccmp_aes(tk, x);
		}
	}
	a[0] = 0x01;
	memcpy(a + 1, nonce, 13);
	for (size_t o = 0, i = 1; o < n; o += 16, i++) {
		const size_t l = n - o < 16 ? n - o : 16;

		a[14] = (uint8_t)(i >> 8), a[15] = (uint8_t)i;
		memcpy(s, a, 16);
		ccmp_aes(tk, s);
		for (size_t j = 0; j < l; j++) {
			if (enc)
				x[j] ^= d[o + j];
			d[o + j] ^= s[j];
			if (!enc)
				x[j] ^= d[o + j];
		}
		ccmp_aes(tk, x);
	}
	a[14] = a[15] = 0;
	memcpy(s, a, 16);
	ccmp_aes(tk, s);
	for (int i = 0; i < 8; i++)
		mic[i] = x[i] ^ s[i];
}

/* f: 24-byte header and n body bytes; out (n + 40 bytes): the protected frame. Returns its length. */
static inline size_t ccmp_encrypt(const uint8_t tk[16], uint64_t pn, const uint8_t *f, size_t n, uint8_t *out)
{
	const uint8_t iv[8] = { (uint8_t)pn, (uint8_t)(pn >> 8), 0, 0x20, (uint8_t)(pn >> 16), (uint8_t)(pn >> 24),
				(uint8_t)(pn >> 32), (uint8_t)(pn >> 40) }; /* ExtIV, key ID 0 */

	memcpy(out, f, 24);
	out[1] |= 0x40;
	memcpy(out + 24, iv, 8);
	memcpy(out + 32, f + 24, n);
	ccmp_ccm(tk, out, pn, out + 32, n, true, out + 32 + n);
	return 32 + n + 8;
}

/* in place: a protected frame of len bytes becomes the 24-byte header and the plaintext body. Returns the
   new length and the PN, or -1 for a short frame, no ExtIV, or a MIC mismatch (the frame is then garbage). */
static inline int ccmp_decrypt(const uint8_t tk[16], uint8_t *f, size_t len, uint64_t *pn)
{
	uint8_t mic[8];
	size_t n;

	if (len < 32 + 8 || !(f[27] & 0x20))
		return -1;
	n = len - 40;
	*pn = (uint64_t)f[24] | (uint64_t)f[25] << 8 | (uint64_t)f[28] << 16 | (uint64_t)f[29] << 24 |
	      (uint64_t)f[30] << 32 | (uint64_t)f[31] << 40;
	ccmp_ccm(tk, f, *pn, f + 32, n, false, mic);
	if (memcmp(mic, f + 32 + n, 8))
		return -1;
	memmove(f + 24, f + 32, n);
	f[1] &= ~0x40;
	return (int)(24 + n);
}

/* AES-128-CMAC (RFC 4493) for BIP */
static inline void cmac_dbl(uint8_t b[16])
{
	const uint8_t c = b[0] & 0x80 ? 0x87 : 0;

	for (int i = 0; i < 15; i++)
		b[i] = (uint8_t)(b[i] << 1 | b[i + 1] >> 7);
	b[15] = (uint8_t)(b[15] << 1) ^ c;
}

static inline void aes_cmac(const uint8_t k[16], const uint8_t *m, size_t n, uint8_t mac[16])
{
	uint8_t sub[16] = { 0 }, x[16] = { 0 };
	size_t o = 0;

	ccmp_aes(k, sub);
	cmac_dbl(sub); /* K1 */
	for (; n - o > 16; o += 16) {
		for (int i = 0; i < 16; i++)
			x[i] ^= m[o + i];
		ccmp_aes(k, x);
	}
	if (n - o < 16) { /* short last block: 10* padding and K2 */
		cmac_dbl(sub);
		x[n - o] ^= 0x80;
	}
	for (size_t i = 0; i < n - o; i++)
		x[i] ^= m[o + i];
	for (int i = 0; i < 16; i++)
		x[i] ^= sub[i];
	ccmp_aes(k, x);
	memcpy(mac, x, 16);
}

/* BIP-CMAC-128 (12.5.4): f is a group-addressed management frame (24-byte header) ending in its 18-byte MMIE.
   Returns the IPN, or -1 for no MMIE, another key ID, or a MIC mismatch. */
static inline int64_t bip_verify(const uint8_t igtk[16], uint16_t keyid, const uint8_t *f, size_t len)
{
	uint8_t b[256], mac[16];
	const uint8_t *e = f + len - 18;
	int64_t ipn = 0;

	if (len < 24 + 18 || len - 4 > sizeof(b) || e[0] != 76 || e[1] != 16 || (e[2] | e[3] << 8) != keyid)
		return -1;
	/* AAD: FC without retry/pwrmgt/moredata, A1 A2 A3; then the body with the MIC zeroed */
	b[0] = f[0];
	b[1] = f[1] & 0xc7;
	memcpy(b + 2, f + 4, 18);
	memcpy(b + 20, f + 24, len - 24 - 8);
	memset(b + len - 12, 0, 8);
	aes_cmac(igtk, b, len - 4, mac);
	if (memcmp(mac, e + 10, 8))
		return -1;
	for (int i = 5; i >= 0; i--)
		ipn = ipn << 8 | e[4 + i];
	return ipn;
}

#endif
