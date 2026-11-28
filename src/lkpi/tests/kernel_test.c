/* SPDX-License-Identifier: BSD-3-Clause */
/* self-check for lkpi/kernel.c: kernel printf, workqueue/timer semantics, RCU, skb */
#include "lkpi.h"
#undef snprintf
#include <assert.h>

static char out[256];
#define FMT(...) (lkpi_snprintf(out, sizeof(out), __VA_ARGS__), out)
#define EQ(a, b) do { const char *_a = (a), *_b = (b); \
	if (strcmp(_a, _b)) { fprintf(stderr, "%s:%d: got \"%s\" want \"%s\"\n", __FILE__, __LINE__, _a, _b); abort(); } } while (0)

static void vf(char *buf, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	struct va_format v = { fmt, &ap };
	lkpi_snprintf(buf, 64, "[%pV]", &v);
	va_end(ap);
}

static void test_printf(void)
{
	const u8 mac[6] = { 0x00, 0x1a, 0x2b, 0xc3, 0xd4, 0xff };
	const u8 b[4] = { 0xde, 0xad, 0xbe, 0xef };
	u8 uuid[16];
	char tiny[4];

	for (int i = 0; i < 16; i++)
		uuid[i] = i;
	EQ(FMT("%pM", mac), "00:1a:2b:c3:d4:ff");
	EQ(FMT("%*ph", 3, b), "de ad be");
	EQ(FMT("%*phN", 4, b), "deadbeef");
	EQ(FMT("%4ph|", b), "de ad be ef|");
	EQ(FMT("%pUb", uuid), "00010203-0405-0607-0809-0a0b0c0d0e0f");
	EQ(FMT("%pM", NULL), "(null)");
	EQ(FMT("%d%%%5d|%-4d|%*d|%*d|", -3, 42, 7, 3, 5, -3, 5), "-3%   42|7   |  5|5  |");
	EQ(FMT("%llu %lld %zu %lx %hhu %s %c", 1ull << 40, -5ll, (size_t)9, 0xabcUL, 300, "s", 'z'),
	   "1099511627776 -5 9 abc 44 s z");
	EQ(FMT("%.3s|%.*s|%08x", "abcdef", 2, "xyz", 0x1f), "abc|xy|0000001f");
	vf(out, "a=%d b=%s", 1, "two");
	EQ(out, "[a=1 b=two]");
	assert(lkpi_snprintf(tiny, sizeof(tiny), "%s", "hello") == 5 && !strcmp(tiny, "hel"));
	assert(scnprintf(tiny, sizeof(tiny), "%s", "hello") == 3);
	assert(lkpi_snprintf(NULL, 0, "%pM", mac) == 17);
}

/* ---- workqueue ---- */
static struct workqueue_struct *wq;
static _Atomic int ran;
static struct completion started, release;

static void count_fn(struct work_struct *w) { ran++; }

static void block_fn(struct work_struct *w)
{
	complete(&started);
	wait_for_completion(&release);
	ran++;
}

static struct work_struct self_w;
static void requeue_fn(struct work_struct *w)
{
	ran++;
	lkpi_sleep_us(200);
	queue_work(wq, w); /* refused while cancel_work_sync runs */
}

/* the lkpi threads start on first use: system_wq on the first schedule_*, the timer and RCU threads lazily */
static void test_lazy_start(void)
{
	struct work_struct w;
	struct delayed_work dw;

	assert(!system_wq);
	ran = 0;
	INIT_DELAYED_WORK(&dw, count_fn);
	assert(schedule_delayed_work(&dw, 1));
	INIT_WORK(&w, count_fn);
	assert(schedule_work(&w));
	assert(system_wq);
	flush_work(&w);
	flush_delayed_work(&dw);
	assert(ran == 2);
	ran = 0;
	kfree_rcu(malloc(16), rcu);
}

static void test_workqueue(void)
{
	struct work_struct w;
	struct delayed_work dw;

	wq = alloc_workqueue("test_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
	assert(wq);
	init_completion(&started);
	init_completion(&release);

	/* a pending work is queued once */
	INIT_WORK(&w, block_fn);
	assert(queue_work(wq, &w));
	wait_for_completion(&started);
	assert(queue_work(wq, &w));  /* requeue while running is allowed */
	assert(!queue_work(wq, &w)); /* but only once */
	complete_all(&release);
	flush_work(&w);
	assert(ran == 2 && !work_pending(&w));

	/* non-reentrant: the same work never runs on two workers at once */
	ran = 0;
	reinit_completion(&started);
	reinit_completion(&release);
	assert(queue_work(wq, &w));
	wait_for_completion(&started);
	assert(queue_work(wq, &w));
	lkpi_sleep_us(5000);
	assert(ran == 0); /* the second instance waits for the first */
	complete_all(&release);
	flush_workqueue(wq);
	assert(ran == 2);

	/* cancel_work_sync stops a self-requeueing work */
	ran = 0;
	INIT_WORK(&self_w, requeue_fn);
	queue_work(wq, &self_w);
	lkpi_sleep_us(2000);
	cancel_work_sync(&self_w);
	int after = ran;
	lkpi_sleep_us(3000);
	assert(after > 0 && ran == after && !work_pending(&self_w));

	/* delayed work fires after its delay, cancel_sync prevents it, mod reschedules */
	ran = 0;
	INIT_DELAYED_WORK(&dw, count_fn);
	u64 t0 = lkpi_now_ns();
	assert(queue_delayed_work(wq, &dw, msecs_to_jiffies(20)));
	assert(!queue_delayed_work(wq, &dw, 1));
	while (!ran)
		lkpi_sleep_us(500);
	assert(lkpi_now_ns() - t0 >= 20 * NSEC_PER_MSEC);
	flush_workqueue(wq);

	ran = 0;
	queue_delayed_work(wq, &dw, 10);
	assert(cancel_delayed_work_sync(&dw));
	lkpi_sleep_us(20000);
	assert(ran == 0 && !work_pending(&dw.work));

	queue_delayed_work(wq, &dw, 1000);
	t0 = lkpi_now_ns();
	assert(mod_delayed_work(wq, &dw, 5)); /* pull it in */
	while (!ran)
		lkpi_sleep_us(500);
	assert(lkpi_now_ns() - t0 < 500 * NSEC_PER_MSEC && ran == 1);

	ran = 0;
	queue_delayed_work(wq, &dw, 10000);
	flush_delayed_work(&dw); /* runs it now */
	assert(ran == 1);

	destroy_workqueue(wq);
}

/* ---- completion / timers / RCU ---- */
static struct completion cdone;
static void timer_fn(struct lkpi_timer *t) { complete(&cdone); }

static int rcu_phase;
static void *reader(void *a)
{
	rcu_read_lock();
	__atomic_store_n(&rcu_phase, 1, __ATOMIC_SEQ_CST);
	lkpi_sleep_us(20000);
	__atomic_store_n(&rcu_phase, 2, __ATOMIC_SEQ_CST);
	rcu_read_unlock();
	return NULL;
}

static void test_sync(void)
{
	struct lkpi_timer t = { .fn = timer_fn };
	pthread_t th;

	init_completion(&cdone);
	u64 t0 = lkpi_now_ns();
	assert(wait_for_completion_timeout(&cdone, 15) == 0);
	assert(lkpi_now_ns() - t0 >= 15 * NSEC_PER_MSEC);
	lkpi_timer_add(&t, 5 * NSEC_PER_MSEC);
	assert(wait_for_completion_timeout(&cdone, 1000) > 0);
	lkpi_timer_add(&t, 50 * NSEC_PER_MSEC);
	assert(lkpi_timer_del(&t) && !lkpi_timer_del(&t));
	assert(wait_for_completion_timeout(&cdone, 80) == 0);

	pthread_create(&th, NULL, reader, NULL);
	while (!__atomic_load_n(&rcu_phase, __ATOMIC_SEQ_CST))
		;
	synchronize_rcu();
	assert(rcu_phase == 2); /* waited for the reader */
	pthread_join(th, NULL);
	rcu_read_lock();
	rcu_read_lock(); /* nesting */
	rcu_read_unlock();
	rcu_read_unlock();
	synchronize_rcu(); /* no readers: returns at once */
}

static int polls;
static int slow_read(int x) { polls++; lkpi_sleep_us(50); return x; }

static void test_poll(void)
{
	int v;

	/* atomic: only the 10 us delays count, so a slow op still gets timeout/delay + 1 tries */
	assert(read_poll_timeout_atomic(slow_read, v, v == 1, 10, 200, false, 0) == -ETIMEDOUT && polls == 21);
	polls = 0;
	assert(read_poll_timeout_atomic(slow_read, v, v == 1, 10, 200, false, 1) == 0 && polls == 1);
	/* sleeping variant: wall-clock budget */
	polls = 0;
	u64 t0 = lkpi_now_ns();
	assert(read_poll_timeout(slow_read, v, v == 1, 10, 2000, false, 0) == -ETIMEDOUT);
	assert(lkpi_now_ns() - t0 >= 2000 * NSEC_PER_USEC && polls < 2000 / 50 + 2);
}

static void test_skb_bits(void)
{
	struct sk_buff *s = alloc_skb(64, GFP_KERNEL), *c;
	DECLARE_BITMAP(bm, 130) = { 0 };
	const struct firmware *fw;

	skb_reserve(s, 8);
	skb_put_data(s, "payload", 7);
	s->cb[0] = 9;
	assert(!pskb_expand_head(s, 0, 100, GFP_ATOMIC));
	assert(skb_headroom(s) == 8 && skb_tailroom(s) >= 100 && !memcmp(s->data, "payload", 7));
	c = skb_copy(s, GFP_ATOMIC);
	assert(c && c->len == 7 && c->cb[0] == 9 && skb_headroom(c) == 8 && !memcmp(c->data, "payload", 7));
	kfree_skb(c);
	kfree_skb(s);
	kfree_skb(NULL);

	set_bit(3, bm);
	set_bit(64, bm);
	set_bit(129, bm);
	assert(find_next_bit(bm, 130, 0) == 3 && find_next_bit(bm, 130, 4) == 64);
	assert(find_next_bit(bm, 130, 65) == 129 && find_next_bit(bm, 129, 65) == 129);
	assert(find_next_zero_bit(bm, 130, 3) == 4 && bitmap_weight(bm, 130) == 3);
	bitmap_fill(bm, 70);
	assert(bitmap_weight(bm, 130) == 71 && find_next_zero_bit(bm, 130, 0) == 70);

	assert(request_firmware(&fw, "../etc/passwd", NULL) == -EINVAL && !fw);
	assert(request_firmware(&fw, "/etc/passwd", NULL) == -EINVAL);
	assert(firmware_request_nowarn(&fw, "rtw89/does-not-exist.bin", NULL) == -ENOENT);
}

int main(void)
{
	test_printf();
	test_lazy_start();
	test_workqueue();
	test_sync();
	test_poll();
	test_skb_bits();
	puts("lkpi kernel_test: ok");
	return 0;
}
