/* reorder window: a timeout tick skips only a hole that has already waited a full tick */
#include <assert.h>
#include <stdio.h>
#include "rx_reord.h"

static int out[16], nout;
static void deliver(void *p, uint32_t b, void *c) { (void)b; (void)c; out[nout++] = (int)(intptr_t)p; }
static void drop(void *p, void *c) { (void)p; (void)c; }
static void append(void *tail, void *p) { (void)tail; out[nout++] = (int)(intptr_t)p; } /* counts as handed up */
static void submit(rx_reord_t *r, uint16_t sn) { bool t; rx_reord_submit(r, 0, sn, (void *)(intptr_t)sn, 1, false, deliver, NULL, drop, NULL, &t); }
static void sub(rx_reord_t *r, uint16_t sn, int id, bool cont) { bool t; rx_reord_submit(r, 0, sn, (void *)(intptr_t)id, 1, cont, deliver, append, drop, NULL, &t); }

int main(void) {
    static rx_reord_t r;
    rx_reord_init(&r);
    submit(&r, 10);
    submit(&r, 12); /* hole at 11 */
    assert(nout == 1 && out[0] == 10);
    assert(rx_reord_timeout_flush(&r, deliver, NULL)); /* fresh hole: no skip yet */
    assert(nout == 1);
    submit(&r, 11); /* the retry fills it */
    assert(nout == 3 && out[1] == 11 && out[2] == 12);
    submit(&r, 14); /* new hole at 13 */
    assert(rx_reord_timeout_flush(&r, deliver, NULL) && nout == 3);
    assert(!rx_reord_timeout_flush(&r, deliver, NULL)); /* still stuck a tick later: skip it */
    assert(nout == 4 && out[3] == 14);
    submit(&r, 12); /* AP retry of a frame already handed up: dropped */
    assert(nout == 4);
    submit(&r, (15 - 500) & 0xfff); /* far behind: a restarted session, delivered */
    assert(nout == 5);

    /* an A-MSDU retry: its first subframe is a dup, so its tail goes too, behind the window or buffered */
    static rx_reord_t a;
    rx_reord_init(&a);
    nout = 0;
    sub(&a, 4094, 1, false);
    sub(&a, 4094, 2, true);
    sub(&a, 4095, 3, false);
    sub(&a, 0, 4, false); /* SN wraps 4095 -> 0 in order */
    assert(nout == 4 && out[3] == 4);
    sub(&a, 4095, 5, false); /* retry of an A-MSDU already handed up */
    sub(&a, 4095, 6, true);
    assert(nout == 4);
    sub(&a, 2, 7, false); /* buffered behind a hole at 1 */
    sub(&a, 2, 8, false); /* its retry */
    sub(&a, 2, 9, true);
    assert(nout == 4);
    sub(&a, 1, 11, false); /* fills the hole: 1, then the buffered 2 without its retry's tail */
    assert(nout == 6 && out[4] == 11 && out[5] == 7);
    puts("reord_test ok");
    return 0;
}
