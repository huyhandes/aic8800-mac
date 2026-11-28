/* reorder window: a timeout tick skips only a hole that has already waited a full tick */
#include <assert.h>
#include <stdio.h>
#include "rx_reord.h"

static int out[16], nout;
static void deliver(void *p, uint32_t b, void *c) { (void)b; (void)c; out[nout++] = (int)(intptr_t)p; }
static void drop(void *p, void *c) { (void)p; (void)c; }
static void submit(rx_reord_t *r, uint16_t sn) { bool t; rx_reord_submit(r, 0, sn, (void *)(intptr_t)sn, 1, false, deliver, NULL, drop, NULL, &t); }

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
    puts("reord_test ok");
    return 0;
}
