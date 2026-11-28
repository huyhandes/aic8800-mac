/* SPDX-License-Identifier: BSD-3-Clause */
/* WPA3-Personal SAE (IEEE 802.11-2020 12.4), group 19 (NIST P-256), PWE by hunting-and-pecking or hash-to-element
   (H2E), for the struct wifi_ft sae step of a driver that has the optional wifi_drv op ft_connect.
   Field arithmetic picks results with masks instead of branches, and scalar multiplication is a Montgomery
   ladder with a fixed step count, so the timing does not depend on the password or the secret scalars. */
#ifndef WPA3_H
#define WPA3_H

#include "wpa2.h"
#include "wifi_drv.h"

typedef struct { uint64_t v[4]; } sae_bn;                /* little-endian 64-bit limbs */
typedef struct { sae_bn m, r2, one; uint64_t inv; } sae_mont; /* one = R mod m, inv = -1/m mod 2^64 */
typedef struct { sae_bn x, y; bool inf; } sae_pt;      /* affine, coordinates in Montgomery form mod p */

static inline void sae_bn_get(sae_bn *a, const uint8_t b[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int j = 0; j < 8; j++) w = w << 8 | b[(3 - i) * 8 + j];
        a->v[i] = w;
    }
}
static inline void sae_bn_put(uint8_t b[32], const sae_bn *a) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) b[(3 - i) * 8 + j] = (uint8_t)(a->v[i] >> (56 - 8 * j));
}
static inline uint64_t sae_bn_add(sae_bn *o, const sae_bn *a, const sae_bn *b) {
    unsigned __int128 c = 0;
    for (int i = 0; i < 4; i++) {
        c += (unsigned __int128)a->v[i] + b->v[i];
        o->v[i] = (uint64_t)c;
        c >>= 64;
    }
    return (uint64_t)c;
}
static inline uint64_t sae_bn_sub(sae_bn *o, const sae_bn *a, const sae_bn *b) {
    uint64_t br = 0;
    for (int i = 0; i < 4; i++) {
        const unsigned __int128 d = (unsigned __int128)a->v[i] - b->v[i] - br;
        o->v[i] = (uint64_t)d;
        br = (uint64_t)(d >> 64) & 1;
    }
    return br;
}
/* o = mask ? a : b, mask all ones or zero */
static inline void sae_bn_sel(sae_bn *o, uint64_t mask, const sae_bn *a, const sae_bn *b) {
    for (int i = 0; i < 4; i++) o->v[i] = (a->v[i] & mask) | (b->v[i] & ~mask);
}
static inline int sae_bn_cmp(const sae_bn *a, const sae_bn *b) {
    sae_bn t;
    return (int)sae_bn_sub(&t, b, a) - (int)sae_bn_sub(&t, a, b);
}
/* modular add / subtract of values below m */
static inline void sae_madd(const sae_mont *M, sae_bn *o, const sae_bn *a, const sae_bn *b) {
    sae_bn s, t;
    const uint64_t c = sae_bn_add(&s, a, b), br = sae_bn_sub(&t, &s, &M->m);
    sae_bn_sel(o, -(c | (br ^ 1)), &t, &s);
}
static inline void sae_msub(const sae_mont *M, sae_bn *o, const sae_bn *a, const sae_bn *b) {
    sae_bn m;
    sae_bn_sel(&m, -sae_bn_sub(o, a, b), &M->m, &(sae_bn){ { 0 } });
    sae_bn_add(o, o, &m);
}
/* Montgomery product a * b / R mod m (CIOS) */
static inline void sae_mmul(const sae_mont *M, sae_bn *o, const sae_bn *a, const sae_bn *b) {
    uint64_t t[6] = { 0 };
    for (int i = 0; i < 4; i++) {
        unsigned __int128 c = 0;
        for (int j = 0; j < 4; j++) {
            c += (unsigned __int128)a->v[j] * b->v[i] + t[j];
            t[j] = (uint64_t)c;
            c >>= 64;
        }
        c += t[4];
        t[4] = (uint64_t)c;
        t[5] = (uint64_t)(c >> 64);
        const uint64_t q = t[0] * M->inv;
        c = ((unsigned __int128)q * M->m.v[0] + t[0]) >> 64;
        for (int j = 1; j < 4; j++) {
            c += (unsigned __int128)q * M->m.v[j] + t[j];
            t[j - 1] = (uint64_t)c;
            c >>= 64;
        }
        c += t[4];
        t[3] = (uint64_t)c;
        t[4] = t[5] + (uint64_t)(c >> 64);
    }
    sae_bn r = { { t[0], t[1], t[2], t[3] } }, s;
    const uint64_t br = sae_bn_sub(&s, &r, &M->m);
    sae_bn_sel(o, -(t[4] | (br ^ 1)), &s, &r);
}
static inline void sae_mont_init(sae_mont *M, const uint8_t m[32]) {
    sae_bn t = { { 1 } };
    uint64_t x = 0;
    sae_bn_get(&M->m, m);
    x = M->m.v[0]; /* Newton: 3 correct bits, doubling each round */
    for (int i = 0; i < 5; i++) x *= 2 - M->m.v[0] * x;
    M->inv = -x;
    for (int i = 0; i < 512; i++) {
        if (i == 256) M->one = t;
        sae_madd(M, &t, &t, &t);
    }
    M->r2 = t;
}
/* a^e, a and the result in Montgomery form; e is always a public constant here */
static inline void sae_mexp(const sae_mont *M, sae_bn *o, const sae_bn *a, const sae_bn *e) {
    sae_bn r = M->one;
    for (int i = 255; i >= 0; i--) {
        sae_mmul(M, &r, &r, &r);
        if (e->v[i / 64] >> (i % 64) & 1) sae_mmul(M, &r, &r, a);
    }
    *o = r;
}

typedef struct {
    sae_mont p, n;
    sae_bn b, three, e_inv, e_sqrt, e_qr; /* b, 3 (Montgomery); p - 2, (p + 1) / 4, (p - 1) / 2 */
} sae_curve;

static inline void sae_curve_init(sae_curve *C) {
    static const uint8_t p[32] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    static const uint8_t n[32] = { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                                   0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                   0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
    static const uint8_t b[32] = { 0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55,
                                   0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6,
                                   0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b };
    const sae_bn three = { { 3 } };
    sae_mont_init(&C->p, p);
    sae_mont_init(&C->n, n);
    sae_bn_get(&C->b, b);
    sae_mmul(&C->p, &C->b, &C->b, &C->p.r2);
    sae_mmul(&C->p, &C->three, &three, &C->p.r2);
    C->e_inv = C->p.m;
    C->e_inv.v[0] -= 2; /* p ends in ...ffff: no borrow */
    for (int i = 0; i < 4; i++) { /* p = 3 mod 4: (p + 1) / 4 = (p >> 2) + 1, (p - 1) / 2 = p >> 1 */
        C->e_qr.v[i] = C->p.m.v[i] >> 1 | (i < 3 ? C->p.m.v[i + 1] << 63 : 0);
        C->e_sqrt.v[i] = C->p.m.v[i] >> 2 | (i < 3 ? C->p.m.v[i + 1] << 62 : 0);
    }
    sae_bn_add(&C->e_sqrt, &C->e_sqrt, &(sae_bn){ { 1 } }); /* carries: the low limb of p >> 2 is all ones */
}
/* x^3 - 3x + b */
static inline void sae_rhs(const sae_curve *C, sae_bn *o, const sae_bn *x) {
    sae_bn t, u;
    sae_mmul(&C->p, &t, x, x);
    sae_msub(&C->p, &t, &t, &C->three);
    sae_mmul(&C->p, &u, &t, x);
    sae_madd(&C->p, o, &u, &C->b);
}
static inline void sae_padd(const sae_curve *C, sae_pt *o, const sae_pt *P, const sae_pt *Q) {
    const sae_mont *F = &C->p;
    const sae_bn zero = { { 0 } };
    sae_bn l, t, u;
    sae_pt r = { .inf = false };
    if (P->inf || Q->inf) {
        *o = P->inf ? *Q : *P;
        return;
    }
    if (!sae_bn_cmp(&P->x, &Q->x)) {
        if (sae_bn_cmp(&P->y, &Q->y) || !sae_bn_cmp(&P->y, &zero)) {
            o->inf = true;
            return;
        }
        sae_mmul(F, &t, &P->x, &P->x); /* (3x^2 - 3) / 2y */
        sae_msub(F, &t, &t, &C->p.one);
        sae_madd(F, &l, &t, &t);
        sae_madd(F, &l, &l, &t);
        sae_madd(F, &u, &P->y, &P->y);
    } else {
        sae_msub(F, &l, &Q->y, &P->y);
        sae_msub(F, &u, &Q->x, &P->x);
    }
    sae_mexp(F, &u, &u, &C->e_inv);
    sae_mmul(F, &l, &l, &u);
    sae_mmul(F, &t, &l, &l);
    sae_msub(F, &t, &t, &P->x);
    sae_msub(F, &r.x, &t, &Q->x);
    sae_msub(F, &t, &P->x, &r.x);
    sae_mmul(F, &t, &t, &l);
    sae_msub(F, &r.y, &t, &P->y);
    *o = r;
}
static inline void sae_pt_swap(sae_pt *a, sae_pt *b, uint64_t mask) {
    for (int i = 0; i < 4; i++) {
        uint64_t t = (a->x.v[i] ^ b->x.v[i]) & mask;
        a->x.v[i] ^= t, b->x.v[i] ^= t;
        t = (a->y.v[i] ^ b->y.v[i]) & mask;
        a->y.v[i] ^= t, b->y.v[i] ^= t;
    }
}
/* k * P: a Montgomery ladder over k + n or k + 2n, whichever has bit 256 as its top bit, so every scalar takes
   the same 256 add-and-double steps (an add on R0 + R1, a double on R0: sae_padd takes one path each time).
   The ladder never meets infinity on this prime-order curve unless k is 0, 1, n - 2 or n - 1. */
static inline void sae_pmul(const sae_curve *C, sae_pt *o, const sae_bn *k, const sae_pt *P) {
    sae_bn k1, k2;
    sae_pt r[2];
    if (P->inf) {
        o->inf = true;
        return;
    }
    const uint64_t c = sae_bn_add(&k1, k, &C->n.m);
    sae_bn_add(&k2, &k1, &C->n.m);
    sae_bn_sel(&k1, -c, &k1, &k2);
    r[0] = *P;
    sae_padd(C, &r[1], P, P);
    for (int i = 255; i >= 0; i--) {
        const uint64_t bit = -(k1.v[i / 64] >> (i % 64) & 1);
        sae_pt_swap(&r[0], &r[1], bit);
        sae_padd(C, &r[1], &r[0], &r[1]);
        sae_padd(C, &r[0], &r[0], &r[0]);
        sae_pt_swap(&r[0], &r[1], bit);
    }
    *o = r[0];
}
/* 64 bytes x || y; 0, or -1 when not a point on the curve */
static inline int sae_pt_get(const sae_curve *C, sae_pt *P, const uint8_t b[64]) {
    sae_bn x, y, l, r;
    sae_bn_get(&x, b);
    sae_bn_get(&y, b + 32);
    if (sae_bn_cmp(&x, &C->p.m) >= 0 || sae_bn_cmp(&y, &C->p.m) >= 0) return -1;
    sae_mmul(&C->p, &P->x, &x, &C->p.r2);
    sae_mmul(&C->p, &P->y, &y, &C->p.r2);
    P->inf = false;
    sae_mmul(&C->p, &l, &P->y, &P->y);
    sae_rhs(C, &r, &P->x);
    return sae_bn_cmp(&l, &r) ? -1 : 0;
}
static inline void sae_pt_put(const sae_curve *C, uint8_t b[64], const sae_pt *P) {
    const sae_bn one = { { 1 } };
    sae_bn t;
    sae_mmul(&C->p, &t, &P->x, &one);
    sae_bn_put(b, &t);
    sae_mmul(&C->p, &t, &P->y, &one);
    sae_bn_put(b + 32, &t);
}

/* simplified SWU with z = -10 (12.4.4.2.3, as hostap sswu()); u below p, in normal form */
static inline void sae_sswu(const sae_curve *C, sae_pt *P, const sae_bn *u) {
    const sae_mont *F = &C->p;
    const sae_bn zero = { { 0 } };
    sae_bn um, t1, m, t, x1a, x1b, x1, x2, gx1, gx2, v, y, n;
    sae_mmul(F, &um, u, &F->r2);
    sae_mmul(F, &n, &(sae_bn){ { 10 } }, &F->r2);
    sae_msub(F, &n, &zero, &n); /* z */
    sae_mmul(F, &t1, &um, &um);
    sae_mmul(F, &t1, &t1, &n); /* z u^2 */
    sae_mmul(F, &m, &t1, &t1);
    sae_madd(F, &m, &m, &t1);         /* m = z^2 u^4 + z u^2 */
    sae_mexp(F, &t, &m, &C->e_inv);   /* 1 / m, or 0 */
    sae_mmul(F, &n, &(sae_bn){ { 30 } }, &F->r2);
    sae_mexp(F, &n, &n, &C->e_inv);
    sae_mmul(F, &x1a, &C->b, &n);     /* b / (z a) = b / 30 */
    sae_mexp(F, &n, &C->three, &C->e_inv);
    sae_mmul(F, &n, &C->b, &n);
    sae_madd(F, &x1b, &F->one, &t);
    sae_mmul(F, &x1b, &x1b, &n);      /* -b / a * (1 + t) = b / 3 * (1 + t) */
    sae_bn_sel(&x1, -(uint64_t)!sae_bn_cmp(&m, &zero), &x1a, &x1b);
    sae_mmul(F, &x2, &t1, &x1);       /* z u^2 x1 */
    sae_rhs(C, &gx1, &x1);
    sae_rhs(C, &gx2, &x2);
    sae_mexp(F, &t, &gx1, &C->e_qr);  /* 1 or 0 when gx1 is a square */
    const uint64_t qr = -((uint64_t)!sae_bn_cmp(&t, &F->one) | (uint64_t)!sae_bn_cmp(&t, &zero));
    sae_bn_sel(&P->x, qr, &x1, &x2);
    sae_bn_sel(&v, qr, &gx1, &gx2);
    sae_mexp(F, &y, &v, &C->e_sqrt);
    sae_mmul(F, &t, &y, &(sae_bn){ { 1 } });
    sae_msub(F, &n, &zero, &y);
    sae_bn_sel(&P->y, -((t.v[0] ^ u->v[0]) & 1), &n, &y); /* y with the parity of u */
    P->inf = false;
}

/* H2E: PT from the SSID and password (RFC 5869 HKDF with SHA256), then PWE = val * PT, key = MAX || MIN address */
static inline void sae_h2e_pwe(const sae_curve *C, sae_pt *pwe, const uint8_t *ssid, size_t ssid_len, const char *pw,
                               size_t pw_len, const uint8_t key[12]) {
    static const uint8_t zero[32];
    const sae_bn one = { { 1 } };
    uint8_t seed[32], pv[64], hb[32] = { 0 };
    sae_bn hi, lo, t;
    sae_pt p[2];
    CCHmac(kCCHmacAlgSHA256, ssid, ssid_len, pw, pw_len, seed); /* pwd-seed = HKDF-Extract(ssid, password) */
    for (uint8_t i = 0; i < 2; i++) {
        const char *info = i ? "SAE Hash to Element u2 P2" : "SAE Hash to Element u1 P1";
        for (uint8_t j = 1; j <= 2; j++) { /* pwd-value = HKDF-Expand(pwd-seed, info, 48) */
            CCHmacContext h;
            CCHmacInit(&h, kCCHmacAlgSHA256, seed, sizeof(seed));
            if (j == 2) CCHmacUpdate(&h, pv, 32U);
            CCHmacUpdate(&h, info, strlen(info));
            CCHmacUpdate(&h, &j, 1U);
            CCHmacFinal(&h, pv + 32 * (j - 1));
        }
        memcpy(hb + 16, pv, 16); /* u = pwd-value mod p = (hi * 2^256 + lo) mod p */
        sae_bn_get(&hi, hb);
        sae_bn_get(&lo, pv + 16);
        sae_mmul(&C->p, &hi, &hi, &C->p.r2);
        sae_bn_sel(&lo, -sae_bn_sub(&t, &lo, &C->p.m), &lo, &t);
        sae_madd(&C->p, &t, &hi, &lo);
        sae_sswu(C, &p[i], &t);
    }
    sae_padd(C, &p[0], &p[0], &p[1]); /* PT */
    CCHmac(kCCHmacAlgSHA256, zero, sizeof(zero), key, 12U, hb);
    sae_bn_get(&t, hb);
    hi = C->n.m;
    hi.v[0] -= 1;                                          /* n - 1 (n is odd) */
    sae_bn_sel(&t, -sae_bn_sub(&lo, &t, &hi), &t, &lo);    /* val mod (n - 1) */
    sae_bn_add(&t, &t, &one);
    sae_pmul(C, pwe, &t, &p[0]);
    memset(seed, 0, sizeof(seed));
    memset(pv, 0, sizeof(pv));
}

typedef struct {
    sae_curve C;
    sae_pt pwe, pwe_h2e; /* hunting-and-pecking, hash-to-element: sae_step picks one */
    sae_bn rand, scalar;
    uint8_t own_c[96], peer_c[96]; /* commit scalar || element as sent */
    uint8_t kck[32], pmk[32], pmkid[16];
    uint8_t token[256];
    size_t token_len;
    uint16_t sc; /* send-confirm */
    bool h2e;
    int state;   /* 0 nothing, 1 committed, 2 confirmed */
} sae_t;

/* both PWEs: hunting-and-pecking over all 40 rounds whatever round finds it (12.4.4.2.2), and H2E; 0 or -1 */
static inline int sae_init(sae_t *s, const uint8_t own[6], const uint8_t peer[6], const uint8_t *ssid, size_t ssid_len,
                           const char *pw, size_t pw_len) {
    uint8_t key[12], msg[64 + 1], seed[32], val[32], pb[32], odd = 0;
    const bool hi = memcmp(own, peer, 6) > 0;
    const sae_bn one = { { 1 } };
    sae_bn x, xs = { { 0 } }, t;
    uint64_t found = 0;
    memset(s, 0, sizeof(*s));
    if (pw_len > 64) return -1;
    sae_curve_init(&s->C);
    memcpy(key, hi ? own : peer, 6);
    memcpy(key + 6, hi ? peer : own, 6);
    memcpy(msg, pw, pw_len);
    sae_bn_put(pb, &s->C.p.m);
    for (int ctr = 1; ctr <= 40; ctr++) {
        msg[pw_len] = (uint8_t)ctr;
        CCHmac(kCCHmacAlgSHA256, key, sizeof(key), msg, pw_len + 1U, seed);
        wpa_kdf_sha256(seed, sizeof(seed), "SAE Hunting and Pecking", pb, sizeof(pb), val, 256);
        sae_bn_get(&x, val);
        if (sae_bn_cmp(&x, &s->C.p.m) >= 0) continue;
        sae_mmul(&s->C.p, &x, &x, &s->C.p.r2);
        sae_rhs(&s->C, &t, &x);
        sae_mexp(&s->C.p, &t, &t, &s->C.e_qr); /* Legendre symbol: 1 = quadratic residue */
        const uint64_t take = -(uint64_t)(!sae_bn_cmp(&t, &s->C.p.one) & !found);
        sae_bn_sel(&xs, take, &x, &xs);
        odd = (uint8_t)((odd & ~take) | (seed[31] & 1 & take));
        found |= take;
    }
    if (!found) return -1;
    s->pwe.x = xs;
    sae_rhs(&s->C, &t, &xs);
    sae_mexp(&s->C.p, &s->pwe.y, &t, &s->C.e_sqrt);
    sae_mmul(&s->C.p, &t, &s->pwe.y, &one);
    sae_msub(&s->C.p, &x, &(sae_bn){ { 0 } }, &s->pwe.y);
    sae_bn_sel(&s->pwe.y, -((t.v[0] ^ odd) & 1), &x, &s->pwe.y);
    sae_h2e_pwe(&s->C, &s->pwe_h2e, ssid, ssid_len, pw, pw_len, key);
    memset(seed, 0, sizeof(seed));
    memset(val, 0, sizeof(val));
    return 0;
}

/* commit scalar = rand + mask, element = -(mask * PWE); both secrets in [2, n); 0, or -1 to pick again */
static inline int sae_set_commit(sae_t *s, const uint8_t rnd[32], const uint8_t msk[32]) {
    const sae_bn two = { { 2 } };
    sae_bn mask;
    sae_pt e;
    sae_bn_get(&s->rand, rnd);
    sae_bn_get(&mask, msk);
    if (sae_bn_cmp(&s->rand, &two) < 0 || sae_bn_cmp(&s->rand, &s->C.n.m) >= 0 || sae_bn_cmp(&mask, &two) < 0 ||
        sae_bn_cmp(&mask, &s->C.n.m) >= 0)
        return -1;
    sae_madd(&s->C.n, &s->scalar, &s->rand, &mask);
    if (sae_bn_cmp(&s->scalar, &two) < 0) return -1;
    sae_pmul(&s->C, &e, &mask, &s->pwe);
    sae_msub(&s->C.p, &e.y, &(sae_bn){ { 0 } }, &e.y);
    sae_bn_put(s->own_c, &s->scalar);
    sae_pt_put(&s->C, s->own_c + 32, &e);
    return 0;
}

/* the peer's commit body after the status (group, scalar, element; extra fields ignored): KCK, PMK, PMKID */
static inline int sae_process_commit(sae_t *s, const uint8_t *b, size_t n) {
    static const uint8_t zero[32];
    uint8_t k[64], keyseed[32], val[32], keys[64];
    sae_bn ps;
    sae_pt pe, K;
    if (n < 2 + 96 || b[0] != 19 || b[1] != 0) return -1;
    sae_bn_get(&ps, b + 2);
    if (sae_bn_cmp(&ps, &(sae_bn){ { 1 } }) <= 0 || sae_bn_cmp(&ps, &s->C.n.m) >= 0 ||
        sae_pt_get(&s->C, &pe, b + 2 + 32) || !memcmp(b + 2, s->own_c, 96)) /* a reflected commit */
        return -1;
    memcpy(s->peer_c, b + 2, 96);
    sae_pmul(&s->C, &K, &ps, &s->pwe); /* K = rand * (peer scalar * PWE + peer element) */
    sae_padd(&s->C, &K, &K, &pe);
    sae_pmul(&s->C, &K, &s->rand, &K);
    if (K.inf) return -1;
    sae_pt_put(&s->C, k, &K);
    CCHmac(kCCHmacAlgSHA256, zero, sizeof(zero), k, 32U, keyseed);
    sae_madd(&s->C.n, &ps, &ps, &s->scalar);
    sae_bn_put(val, &ps);
    wpa_kdf_sha256(keyseed, sizeof(keyseed), "SAE KCK and PMK", val, sizeof(val), keys, 512);
    memcpy(s->kck, keys, 32);
    memcpy(s->pmk, keys + 32, 32);
    memcpy(s->pmkid, val, 16);
    memset(k, 0, sizeof(k));
    memset(keyseed, 0, sizeof(keyseed));
    memset(keys, 0, sizeof(keys));
    return 0;
}

/* CN(KCK, send-confirm, first commit, second commit) */
static inline void sae_confirm(const sae_t *s, uint16_t sc, bool own_first, uint8_t out[32]) {
    const uint8_t c[2] = { (uint8_t)sc, (uint8_t)(sc >> 8) };
    CCHmacContext h;
    CCHmacInit(&h, kCCHmacAlgSHA256, s->kck, sizeof(s->kck));
    CCHmacUpdate(&h, c, 2U);
    CCHmacUpdate(&h, own_first ? s->own_c : s->peer_c, 96U);
    CCHmacUpdate(&h, own_first ? s->peer_c : s->own_c, 96U);
    CCHmacFinal(&h, out);
}

/* authentication body from the transaction number on: seq (2), status (2), then the SAE fields */
static inline int sae_put_commit(sae_t *s, uint8_t *tx) {
    uint8_t *p = tx;
    *p++ = 1, *p++ = 0, *p++ = s->h2e ? 126 : 0, *p++ = 0, *p++ = 19, *p++ = 0; /* 126: SAE_HASH_TO_ELEMENT */
    if (!s->h2e) {
        memcpy(p, s->token, s->token_len);
        p += s->token_len;
    }
    memcpy(p, s->own_c, 96);
    p += 96;
    if (s->h2e && s->token_len) { /* Anti-Clogging Token Container element */
        *p++ = 255, *p++ = (uint8_t)(1 + s->token_len), *p++ = 93;
        memcpy(p, s->token, s->token_len);
        p += s->token_len;
    }
    return (int)(p - tx);
}
static inline int sae_put_confirm(sae_t *s, uint8_t *tx) {
    tx[0] = 2, tx[1] = 0, tx[2] = 0, tx[3] = 0, tx[4] = (uint8_t)s->sc, tx[5] = (uint8_t)(s->sc >> 8);
    sae_confirm(s, s->sc, true, tx + 6);
    return 6 + 32;
}

/* the struct wifi_ft sae step: rx NULL starts with our commit (rx_len 1: with H2E); then each authentication
   frame from the AP. Returns the length of the frame to send, 0 once the AP's confirm checks out, -1 to give up. */
static inline int sae_step(void *arg, const uint8_t *rx, size_t rx_len, uint8_t *tx, size_t cap) {
    sae_t *s = arg;
    if (cap < 6 + 3 + sizeof(s->token) + 96) return -1;
    if (!rx) {
        uint8_t r[32], m[32];
        s->h2e = rx_len == 1;
        if (s->h2e) s->pwe = s->pwe_h2e;
        do {
            arc4random_buf(r, sizeof(r));
            arc4random_buf(m, sizeof(m));
        } while (sae_set_commit(s, r, m));
        memset(r, 0, sizeof(r));
        memset(m, 0, sizeof(m));
        s->token_len = 0;
        s->state = 1;
        return sae_put_commit(s, tx);
    }
    if (rx_len < 4) return -1;
    const uint16_t seq = (uint16_t)(rx[0] | rx[1] << 8), st = (uint16_t)(rx[2] | rx[3] << 8);
    const uint8_t *b = rx + 4;
    const size_t n = rx_len - 4;
    if (seq == 1 && st == 76 && s->state == 1) { /* anti-clogging token: send the commit again with it */
        const uint8_t *tk = b + 2;
        size_t tl = n > 2 ? n - 2 : 0;
        if (s->h2e) { /* in a container element */
            if (tl < 4 || tk[0] != 255 || tk[2] != 93 || tk[1] < 2 || tk[1] + 2U > tl) return -1;
            tl = tk[1] - 1U;
            tk += 3;
        }
        if (!tl || tl > sizeof(s->token) - 2 || s->token_len) return -1;
        memcpy(s->token, tk, tl);
        s->token_len = tl;
        return sae_put_commit(s, tx);
    }
    if (st != (seq == 1 && s->h2e ? 126 : 0)) return -1; /* 77: the AP wants a group other than 19 */
    if (seq == 1 && s->state == 1) {
        if (sae_process_commit(s, b, n)) return -1;
        s->state = 2;
        s->sc = 1;
        return sae_put_confirm(s, tx);
    }
    if (seq == 1 && s->state == 2) { /* the AP sent its commit again: our confirm got lost */
        if (n < 2 + 96 || memcmp(b + 2, s->peer_c, 96) || s->sc == 0xffff) return -1;
        s->sc++;
        return sae_put_confirm(s, tx);
    }
    if (seq == 2 && s->state == 2 && n >= 2 + 32) {
        uint8_t c[32];
        sae_confirm(s, (uint16_t)(b[0] | b[1] << 8), false, c);
        return memcmp(c, b + 2, 32) ? -1 : 0;
    }
    return -1;
}

#endif /* WPA3_H */
