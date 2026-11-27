/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * lkpi kernel services on macOS: time, memory, RCU, completions, one timer
 * thread, workqueues (worker threads), kernel printf, skb and firmware files.
 */
#include "lkpi.h"
#include <ctype.h>
#include <pthread/qos.h>
#include <sys/stat.h>
#include <time.h>
/* the header maps these onto lkpi_*; this file needs libc's */
#undef snprintf
#undef vsnprintf
#undef sprintf

/* ---------- time ---------- */
u64 lkpi_now_ns(void) { return clock_gettime_nsec_np(CLOCK_UPTIME_RAW); }
u64 lkpi_boot_ns(void) { return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW); }

void lkpi_sleep_us(u64 us)
{
	struct timespec ts = { .tv_sec = us / USEC_PER_SEC, .tv_nsec = (us % USEC_PER_SEC) * NSEC_PER_USEC };
	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/* udelay: spin for short waits (a nanosleep costs ~50 us on macOS), sleep for long ones */
void lkpi_delay_us(u64 us)
{
	if (us > 50)
		return lkpi_sleep_us(us);
	u64 end = lkpi_now_ns() + us * NSEC_PER_USEC;
	while (lkpi_now_ns() < end)
		__asm__ __volatile__("yield");
}

static void cond_wait_ns(pthread_cond_t *c, pthread_mutex_t *m, u64 ns)
{
	struct timespec ts = { .tv_sec = ns / NSEC_PER_SEC, .tv_nsec = ns % NSEC_PER_SEC };
	pthread_cond_timedwait_relative_np(c, m, &ts);
}

static void start_thread(void *(*fn)(void *), void *arg, qos_class_t qos)
{
	pthread_attr_t a;
	pthread_t th;
	pthread_attr_init(&a);
	pthread_attr_set_qos_class_np(&a, qos, 0);
	pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
	if (pthread_create(&th, &a, fn, arg))
		abort(); /* only at start-up; nothing works without these threads */
	pthread_attr_destroy(&a);
}

/* ---------- memory / locks ---------- */
void *lkpi_kmalloc(size_t n, gfp_t gfp)
{
	return (gfp & __GFP_ZERO) ? calloc(1, n ? n : 1) : malloc(n ? n : 1);
}

void lkpi_lock_init(pthread_mutex_t *m) { pthread_mutex_init(m, NULL); }

/* ---------- RCU ---------- */
int lkpi_rcu_readers;
_Thread_local unsigned int lkpi_rcu_nest;

void synchronize_rcu(void)
{
	if (WARN_ON(lkpi_rcu_nest)) /* would wait for ourselves */
		return;
	__atomic_thread_fence(__ATOMIC_SEQ_CST);
	/* readers are short (a lookup), so zero shows up within a few polls */
	while (__atomic_load_n(&lkpi_rcu_readers, __ATOMIC_SEQ_CST))
		lkpi_sleep_us(20);
}

struct dfree { struct dfree *next; void *p; };
static pthread_mutex_t dlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t dkick = PTHREAD_COND_INITIALIZER;
static struct dfree *dhead;

/* kfree_rcu can run under locks a reader may want, so the wait happens on this thread */
static void *dfree_main(void *arg)
{
	pthread_setname_np("lkpi-rcu");
	for (;;) {
		pthread_mutex_lock(&dlock);
		while (!dhead)
			pthread_cond_wait(&dkick, &dlock);
		struct dfree *l = dhead;
		dhead = NULL;
		pthread_mutex_unlock(&dlock);
		synchronize_rcu();
		while (l) {
			struct dfree *n = l->next;
			free(l->p);
			free(l);
			l = n;
		}
	}
	return NULL;
}

void lkpi_defer_free(void *p)
{
	struct dfree *d;

	if (!p)
		return;
	d = malloc(sizeof(*d));
	if (!d) {
		synchronize_rcu();
		free(p);
		return;
	}
	d->p = p;
	pthread_mutex_lock(&dlock);
	d->next = dhead;
	dhead = d;
	pthread_cond_signal(&dkick);
	pthread_mutex_unlock(&dlock);
}

/* ---------- completion ---------- */
void init_completion(struct completion *x)
{
	pthread_mutex_init(&x->m, NULL);
	pthread_cond_init(&x->c, NULL);
	x->done = 0;
}

void reinit_completion(struct completion *x)
{
	pthread_mutex_lock(&x->m);
	x->done = 0;
	pthread_mutex_unlock(&x->m);
}

void complete(struct completion *x)
{
	pthread_mutex_lock(&x->m);
	if (x->done != UINT_MAX)
		x->done++;
	pthread_cond_signal(&x->c);
	pthread_mutex_unlock(&x->m);
}

void complete_all(struct completion *x)
{
	pthread_mutex_lock(&x->m);
	x->done = UINT_MAX;
	pthread_cond_broadcast(&x->c);
	pthread_mutex_unlock(&x->m);
}

bool completion_done(struct completion *x)
{
	pthread_mutex_lock(&x->m);
	bool r = x->done != 0;
	pthread_mutex_unlock(&x->m);
	return r;
}

void wait_for_completion(struct completion *x)
{
	pthread_mutex_lock(&x->m);
	while (!x->done)
		pthread_cond_wait(&x->c, &x->m);
	if (x->done != UINT_MAX)
		x->done--;
	pthread_mutex_unlock(&x->m);
}

/* timeout and return value are jiffies (= ms); 0 means timed out */
unsigned long wait_for_completion_timeout(struct completion *x, unsigned long timeout)
{
	u64 end = lkpi_now_ns() + (u64)timeout * NSEC_PER_MSEC, now = 0;

	pthread_mutex_lock(&x->m);
	while (!x->done && (now = lkpi_now_ns()) < end)
		cond_wait_ns(&x->c, &x->m, end - now);
	if (!x->done) {
		pthread_mutex_unlock(&x->m);
		return 0;
	}
	if (x->done != UINT_MAX)
		x->done--;
	pthread_mutex_unlock(&x->m);
	now = lkpi_now_ns();
	return now < end ? max(1ul, (unsigned long)((end - now) / NSEC_PER_MSEC)) : 1;
}

/* ---------- timers: one thread, list sorted by expiry ---------- */
static pthread_mutex_t tlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tkick = PTHREAD_COND_INITIALIZER, tdone = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(timers);
static struct lkpi_timer *trunning;
static _Thread_local bool on_timer_thread;

static void *timer_main(void *arg)
{
	pthread_setname_np("lkpi-timer");
	on_timer_thread = true;
	pthread_mutex_lock(&tlock);
	for (;;) {
		if (list_empty(&timers)) {
			pthread_cond_wait(&tkick, &tlock);
			continue;
		}
		struct lkpi_timer *t = list_first_entry(&timers, struct lkpi_timer, entry);
		u64 now = lkpi_now_ns();
		if (t->expires_ns > now) {
			cond_wait_ns(&tkick, &tlock, t->expires_ns - now);
			continue;
		}
		list_del(&t->entry);
		__atomic_store_n(&t->pending, false, __ATOMIC_SEQ_CST);
		trunning = t;
		pthread_mutex_unlock(&tlock);
		t->fn(t); /* may free t: only the pointer value is used below */
		pthread_mutex_lock(&tlock);
		trunning = NULL;
		pthread_cond_broadcast(&tdone);
	}
	return NULL;
}

void lkpi_timer_add(struct lkpi_timer *t, u64 delay_ns)
{
	struct lkpi_timer *pos;

	pthread_mutex_lock(&tlock);
	if (t->pending)
		list_del(&t->entry);
	t->expires_ns = lkpi_now_ns() + delay_ns;
	list_for_each_entry(pos, &timers, entry)
		if (pos->expires_ns > t->expires_ns)
			break;
	list_add_tail(&t->entry, &pos->entry); /* before pos, or at the end */
	__atomic_store_n(&t->pending, true, __ATOMIC_SEQ_CST);
	if (timers.next == &t->entry)
		pthread_cond_signal(&tkick);
	pthread_mutex_unlock(&tlock);
}

/* sync: also wait out a callback already running (del_timer_sync) */
static bool timer_del(struct lkpi_timer *t, bool sync)
{
	pthread_mutex_lock(&tlock);
	bool was = t->pending;
	if (was) {
		list_del(&t->entry);
		__atomic_store_n(&t->pending, false, __ATOMIC_SEQ_CST);
	}
	while (sync && !on_timer_thread && trunning == t)
		pthread_cond_wait(&tdone, &tlock);
	pthread_mutex_unlock(&tlock);
	return was;
}

bool lkpi_timer_del(struct lkpi_timer *t) { return timer_del(t, true); }

/* ---------- workqueues ---------- */
#define LKPI_MAX_WORKERS 32
struct lkpi_worker {
	struct workqueue_struct *wq;
	struct work_struct *cur; /* compared by address only: the item may free itself */
	bool used;
};
struct workqueue_struct {
	char name[32];
	struct list_head list;
	pthread_cond_t kick;
	struct mutex *lock;
	int nthreads, alive;
	bool dying;
	qos_class_t qos;
};
/* one lock for every queue and work state; contention is a few items per frame burst */
static pthread_mutex_t wlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wdone = PTHREAD_COND_INITIALIZER; /* an item finished or a worker exited */
static struct lkpi_worker workers[LKPI_MAX_WORKERS];
static _Thread_local struct lkpi_worker *self_worker;
struct workqueue_struct *system_wq;

static bool work_running(const struct work_struct *w)
{
	for (int i = 0; i < LKPI_MAX_WORKERS; i++)
		if (workers[i].used && workers[i].cur == w && &workers[i] != self_worker)
			return true;
	return false;
}

static bool wq_busy(const struct workqueue_struct *wq)
{
	for (int i = 0; i < LKPI_MAX_WORKERS; i++)
		if (workers[i].used && workers[i].wq == wq && workers[i].cur && &workers[i] != self_worker)
			return true;
	return false;
}

/* first queued item not already running on a sibling worker (works never run concurrently with themselves) */
static struct work_struct *pick(struct workqueue_struct *wq)
{
	struct work_struct *w;

	list_for_each_entry(w, &wq->list, entry)
		if (!work_running(w))
			return w;
	return NULL;
}

static void *worker_main(void *arg)
{
	struct lkpi_worker *me = arg;
	struct workqueue_struct *wq = me->wq;
	struct work_struct *w;

	self_worker = me;
	pthread_setname_np(wq->name);
	pthread_mutex_lock(&wlock);
	for (;;) {
		w = pick(wq);
		if (!w) {
			if (wq->dying)
				break;
			pthread_cond_wait(&wq->kick, &wlock);
			continue;
		}
		if (wq->lock) {
			/* lock order is wq->lock then wlock; the item may be cancelled meanwhile */
			pthread_mutex_unlock(&wlock);
			mutex_lock(wq->lock);
			pthread_mutex_lock(&wlock);
			w = pick(wq);
			if (!w) {
				mutex_unlock(wq->lock);
				continue;
			}
		}
		list_del_init(&w->entry);
		w->state &= ~LKPI_WORK_PENDING;
		me->cur = w;
		pthread_mutex_unlock(&wlock);
		w->func(w);
		if (wq->lock)
			mutex_unlock(wq->lock);
		pthread_mutex_lock(&wlock);
		me->cur = NULL;
		pthread_cond_broadcast(&wdone);
		if (!list_empty(&wq->list))
			pthread_cond_signal(&wq->kick); /* an item skipped as running may be runnable now */
	}
	me->used = false;
	wq->alive--;
	pthread_cond_broadcast(&wdone);
	pthread_mutex_unlock(&wlock);
	return NULL;
}

static struct workqueue_struct *wq_create(const char *name, int nthreads, qos_class_t qos, struct mutex *lock)
{
	struct workqueue_struct *wq = calloc(1, sizeof(*wq));
	int started = 0;

	if (!wq)
		return NULL;
	strlcpy(wq->name, name, sizeof(wq->name));
	INIT_LIST_HEAD(&wq->list);
	pthread_cond_init(&wq->kick, NULL);
	wq->lock = lock;
	wq->qos = qos;
	pthread_mutex_lock(&wlock);
	for (int i = 0; i < LKPI_MAX_WORKERS && started < nthreads; i++) {
		if (workers[i].used)
			continue;
		workers[i] = (struct lkpi_worker){ .wq = wq, .used = true };
		started++;
		wq->alive++;
		start_thread(worker_main, &workers[i], qos);
	}
	wq->nthreads = started;
	pthread_mutex_unlock(&wlock);
	if (!started) {
		free(wq);
		return NULL;
	}
	return wq;
}

struct workqueue_struct *alloc_workqueue(const char *fmt, unsigned int flags, int max_active, ...)
{
	char name[32];
	va_list ap;

	va_start(ap, max_active);
	lkpi_vsnprintf(name, sizeof(name), fmt, ap);
	va_end(ap);
	/* the data-path queues (tx/rx) get the interactive QoS so they stay on P-cores */
	return wq_create(name, max_active == 1 ? 1 : 2,
			 flags & (WQ_HIGHPRI | WQ_BH) ? QOS_CLASS_USER_INTERACTIVE : QOS_CLASS_USER_INITIATED, NULL);
}

struct workqueue_struct *lkpi_alloc_wq_locked(const char *name, struct mutex *lock)
{
	return wq_create(name, 1, QOS_CLASS_USER_INITIATED, lock);
}

void flush_workqueue(struct workqueue_struct *wq)
{
	pthread_mutex_lock(&wlock);
	while (!list_empty(&wq->list) || wq_busy(wq))
		pthread_cond_wait(&wdone, &wlock);
	pthread_mutex_unlock(&wlock);
}

void destroy_workqueue(struct workqueue_struct *wq)
{
	if (!wq)
		return;
	flush_workqueue(wq);
	pthread_mutex_lock(&wlock);
	wq->dying = true;
	pthread_cond_broadcast(&wq->kick);
	while (wq->alive)
		pthread_cond_wait(&wdone, &wlock);
	pthread_mutex_unlock(&wlock);
	pthread_cond_destroy(&wq->kick);
	free(wq);
}

static void dwork_timer_fn(struct lkpi_timer *t);

void lkpi_init_work(struct work_struct *w, work_func_t fn)
{
	INIT_LIST_HEAD(&w->entry);
	w->func = fn;
	w->wq = NULL;
	w->state = 0;
}

void lkpi_init_delayed_work(struct delayed_work *dw, work_func_t fn)
{
	lkpi_init_work(&dw->work, fn);
	INIT_LIST_HEAD(&dw->timer.entry);
	dw->timer.pending = false;
	dw->timer.fn = dwork_timer_fn;
	dw->wq = NULL;
}

/* wlock held */
static void enqueue(struct workqueue_struct *wq, struct work_struct *w)
{
	list_add_tail(&w->entry, &wq->list);
	pthread_cond_signal(&wq->kick);
}

static bool __queue_work(struct workqueue_struct *wq, struct work_struct *w)
{
	if (w->state & (LKPI_WORK_PENDING | LKPI_WORK_CANCELING))
		return false;
	w->state |= LKPI_WORK_PENDING;
	w->wq = wq;
	enqueue(wq, w);
	return true;
}

/* a delayed work is PENDING from arming until a worker picks it; entry is empty while on the timer */
static bool __queue_delayed(struct workqueue_struct *wq, struct delayed_work *dw, unsigned long delay)
{
	struct work_struct *w = &dw->work;

	if (w->state & (LKPI_WORK_PENDING | LKPI_WORK_CANCELING))
		return false;
	w->state |= LKPI_WORK_PENDING;
	w->wq = dw->wq = wq;
	if (!delay)
		enqueue(wq, w);
	else
		lkpi_timer_add(&dw->timer, (u64)delay * NSEC_PER_MSEC);
	return true;
}

static void dwork_timer_fn(struct lkpi_timer *t)
{
	struct delayed_work *dw = container_of(t, struct delayed_work, timer);

	pthread_mutex_lock(&wlock);
	/* skip if cancelled, already queued, or re-armed by mod_delayed_work while we fired */
	if ((dw->work.state & LKPI_WORK_PENDING) && list_empty(&dw->work.entry) &&
	    !__atomic_load_n(&t->pending, __ATOMIC_SEQ_CST))
		enqueue(dw->wq, &dw->work);
	pthread_mutex_unlock(&wlock);
}

/* drop the queued instance; wlock held */
static bool unqueue(struct work_struct *w)
{
	if (!(w->state & LKPI_WORK_PENDING))
		return false;
	if (!list_empty(&w->entry))
		list_del_init(&w->entry);
	w->state &= ~LKPI_WORK_PENDING;
	return true;
}

static void wait_idle(struct work_struct *w)
{
	while (work_running(w))
		pthread_cond_wait(&wdone, &wlock);
}

bool queue_work(struct workqueue_struct *wq, struct work_struct *w)
{
	pthread_mutex_lock(&wlock);
	bool r = __queue_work(wq, w);
	pthread_mutex_unlock(&wlock);
	return r;
}

bool queue_delayed_work(struct workqueue_struct *wq, struct delayed_work *dw, unsigned long delay)
{
	pthread_mutex_lock(&wlock);
	bool r = __queue_delayed(wq, dw, delay);
	pthread_mutex_unlock(&wlock);
	return r;
}

bool mod_delayed_work(struct workqueue_struct *wq, struct delayed_work *dw, unsigned long delay)
{
	pthread_mutex_lock(&wlock);
	if (dw->work.state & LKPI_WORK_CANCELING) {
		pthread_mutex_unlock(&wlock);
		return false;
	}
	bool r = unqueue(&dw->work);
	timer_del(&dw->timer, false);
	__queue_delayed(wq, dw, delay);
	pthread_mutex_unlock(&wlock);
	return r;
}

bool cancel_work(struct work_struct *w)
{
	pthread_mutex_lock(&wlock);
	bool r = unqueue(w);
	pthread_mutex_unlock(&wlock);
	return r;
}

bool cancel_work_sync(struct work_struct *w)
{
	pthread_mutex_lock(&wlock);
	w->state |= LKPI_WORK_CANCELING; /* a running instance cannot requeue itself */
	bool r = unqueue(w);
	wait_idle(w);
	w->state &= ~LKPI_WORK_CANCELING;
	pthread_mutex_unlock(&wlock);
	return r;
}

bool cancel_delayed_work(struct delayed_work *dw)
{
	pthread_mutex_lock(&wlock);
	bool r = unqueue(&dw->work);
	timer_del(&dw->timer, false);
	pthread_mutex_unlock(&wlock);
	return r;
}

bool cancel_delayed_work_sync(struct delayed_work *dw)
{
	pthread_mutex_lock(&wlock);
	dw->work.state |= LKPI_WORK_CANCELING;
	pthread_mutex_unlock(&wlock);
	timer_del(&dw->timer, true); /* outside wlock: an in-flight dwork_timer_fn needs it */
	pthread_mutex_lock(&wlock);
	bool r = unqueue(&dw->work);
	wait_idle(&dw->work);
	dw->work.state &= ~LKPI_WORK_CANCELING;
	pthread_mutex_unlock(&wlock);
	return r;
}

bool flush_work(struct work_struct *w)
{
	bool r = false;

	pthread_mutex_lock(&wlock);
	/* a delayed work still on its timer is not flushed (same as Linux) */
	while (((w->state & LKPI_WORK_PENDING) && !list_empty(&w->entry)) || work_running(w)) {
		r = true;
		pthread_cond_wait(&wdone, &wlock);
	}
	pthread_mutex_unlock(&wlock);
	return r;
}

bool flush_delayed_work(struct delayed_work *dw)
{
	pthread_mutex_lock(&wlock);
	if ((dw->work.state & LKPI_WORK_PENDING) && list_empty(&dw->work.entry)) {
		timer_del(&dw->timer, false);
		enqueue(dw->wq, &dw->work);
	}
	pthread_mutex_unlock(&wlock);
	return flush_work(&dw->work);
}

bool work_pending(struct work_struct *w)
{
	return __atomic_load_n(&w->state, __ATOMIC_SEQ_CST) & LKPI_WORK_PENDING;
}

/* ---------- formatting: libc printf plus the kernel %p extensions rtw89 uses ---------- */
struct out { char *buf; size_t size, len; };

static void put(struct out *o, char c)
{
	if (o->len + 1 < o->size)
		o->buf[o->len] = c;
	o->len++;
}

static void puts_o(struct out *o, const char *s)
{
	while (*s)
		put(o, *s++);
}

#define EMIT(o, f, ...) do { \
	size_t _room = (o)->len < (o)->size ? (o)->size - (o)->len : 0; \
	int _r = snprintf(_room ? (o)->buf + (o)->len : NULL, _room, f, __VA_ARGS__); \
	if (_r > 0) (o)->len += _r; \
} while (0)

static void fmt_hex(struct out *o, const u8 *p, int n, char sep)
{
	static const char hx[] = "0123456789abcdef";

	if (n <= 0 || n > 64)
		n = n <= 0 ? 1 : 64; /* kernel: default 1, cap 64 */
	for (int i = 0; i < n; i++) {
		if (i && sep)
			put(o, sep);
		put(o, hx[p[i] >> 4]);
		put(o, hx[p[i] & 15]);
	}
}

/* %p<ext>; returns the number of extension chars consumed */
static int fmt_pext(struct out *o, const char *e, const void *ptr, int width, va_list *ap)
{
	const u8 *b = ptr;

	switch (*e) {
	case 'M':
		if (!b)
			break;
		EMIT(o, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
		return 1;
	case 'h': {
		char sep = ' ';
		int n = 1;
		if (e[1] == 'N') { sep = 0; n = 2; }
		else if (e[1] == 'C') { sep = ':'; n = 2; }
		else if (e[1] == 'D') { sep = '-'; n = 2; }
		if (!b)
			break;
		fmt_hex(o, b, width, sep);
		return n;
	}
	case 'U': {
		int n = strchr("bBlL", e[1]) && e[1] ? 2 : 1;
		if (!b)
			break;
		/* rtw89 only uses %pUb: raw byte order */
		EMIT(o, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		     b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
		return n;
	}
	case 'V': {
		const struct va_format *vf = ptr;
		va_list va;
		if (!vf)
			break;
		va_copy(va, *vf->va);
		size_t room = o->len < o->size ? o->size - o->len : 0;
		int r = lkpi_vsnprintf(room ? o->buf + o->len : NULL, room, vf->fmt, va);
		va_end(va);
		if (r > 0)
			o->len += r;
		return 1;
	}
	default:
		EMIT(o, "%p", ptr);
		return 0;
	}
	puts_o(o, "(null)");
	return 1;
}

int lkpi_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	struct out o = { buf, size, 0 };
	va_list va;

	va_copy(va, ap);
	for (const char *p = fmt; *p;) {
		if (*p != '%') {
			put(&o, *p++);
			continue;
		}
		const char *start = p++;
		if (*p == '%') {
			put(&o, '%');
			p++;
			continue;
		}
		/* rebuild the spec with '*' resolved, so it can go to libc with a single argument */
		char spec[48], *s = spec; /* flags 5 + width 11 + prec 12 + len 2 + conv fit */
		int width = -1, prec = -1;
		bool has_w = false;
		*s++ = '%';
		while (*p && strchr("-+ #0", *p) && s < spec + 6)
			*s++ = *p++;
		if (*p == '*') {
			width = va_arg(va, int);
			has_w = true;
			p++;
		} else if (isdigit((unsigned char)*p)) {
			width = (int)strtol(p, (char **)&p, 10);
			has_w = true;
		}
		if (*p == '.') {
			p++;
			if (*p == '*') {
				prec = va_arg(va, int);
				p++;
			} else {
				prec = (int)strtol(p, (char **)&p, 10);
			}
		}
		if (has_w)
			s += snprintf(s, spec + sizeof(spec) - s, "%d", width);
		if (prec >= 0)
			s += snprintf(s, spec + sizeof(spec) - s, ".%d", prec);
		int lng = 0; /* 1 h, 2 hh, 3 l, 4 ll, 5 z, 6 t, 7 j */
		for (;; p++) {
			if (*p == 'h') lng = lng == 1 ? 2 : 1;
			else if (*p == 'l') lng = lng == 3 ? 4 : 3;
			else if (*p == 'L' || *p == 'q') lng = 4;
			else if (*p == 'z') lng = 5;
			else if (*p == 't') lng = 6;
			else if (*p == 'j') lng = 7;
			else break;
		}
		char conv = *p;
		if (!conv)
			break;
		p++;
		static const char *const lm[] = { "", "h", "hh", "l", "ll", "z", "t", "j" };
		s = stpcpy(s, lm[lng]);
		*s++ = conv;
		*s = 0;
		switch (conv) {
		case 'd': case 'i':
			if (lng == 3 || lng == 5 || lng == 6) EMIT(&o, spec, va_arg(va, long));
			else if (lng == 4 || lng == 7) EMIT(&o, spec, va_arg(va, long long));
			else EMIT(&o, spec, va_arg(va, int));
			break;
		case 'u': case 'x': case 'X': case 'o':
			if (lng == 3 || lng == 5 || lng == 6) EMIT(&o, spec, va_arg(va, unsigned long));
			else if (lng == 4 || lng == 7) EMIT(&o, spec, va_arg(va, unsigned long long));
			else EMIT(&o, spec, va_arg(va, unsigned int));
			break;
		case 'c':
			EMIT(&o, spec, va_arg(va, int));
			break;
		case 's':
			EMIT(&o, spec, va_arg(va, const char *));
			break;
		case 'p': {
			void *ptr = va_arg(va, void *);
			p += fmt_pext(&o, p, ptr, width, &va);
			break;
		}
		default: /* no floats or %n in the kernel: print the spec as text */
			for (const char *c = start; c < p; c++)
				put(&o, *c);
			break;
		}
	}
	va_end(va);
	if (size)
		buf[o.len < size ? o.len : size - 1] = 0;
	return (int)o.len;
}

int lkpi_snprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = lkpi_vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return r;
}

int scnprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	if (!size)
		return 0;
	va_start(ap, fmt);
	int r = lkpi_vsnprintf(buf, size, fmt, ap);
	va_end(ap);
	return r < (int)size ? r : (int)size - 1;
}

int sysfs_emit(char *buf, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int r = lkpi_vsnprintf(buf, PAGE_SIZE, fmt, ap);
	va_end(ap);
	return min(r, PAGE_SIZE - 1);
}

/* ---------- logging ---------- */
unsigned int lkpi_loglevel = 6;

__attribute__((constructor)) static void loglevel_init(void)
{
	const char *e = getenv("LKPI_LOGLEVEL");
	if (e)
		lkpi_loglevel = (unsigned int)atoi(e);
}

void lkpi_log(int level, const char *fmt, ...)
{
	char line[1024];
	va_list ap;

	if (fmt[0] == '<' && fmt[1] >= '0' && fmt[1] <= '7' && fmt[2] == '>') {
		level = fmt[1] - '0';
		fmt += 3;
	}
	if (level > (int)lkpi_loglevel)
		return;
	va_start(ap, fmt);
	int n = lkpi_vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	n = min(n, (int)sizeof(line) - 1);
	fprintf(stderr, "rtw89: %s%s", line, n > 0 && line[n - 1] == '\n' ? "" : "\n");
}

void print_hex_dump(const char *level, const char *prefix, int type, int rowsize,
		    int groupsize, const void *buf, size_t len, bool ascii)
{
	const u8 *b = buf;
	char line[512];
	int lv = level && level[0] == '<' ? level[1] - '0' : 7;

	if (rowsize != 32)
		rowsize = 16;
	if (groupsize != 2 && groupsize != 4 && groupsize != 8)
		groupsize = 1;
	for (size_t off = 0; off < len; off += rowsize) {
		struct out o = { line, sizeof(line), 0 };
		size_t n = min(len - off, (size_t)rowsize);
		puts_o(&o, prefix ? prefix : "");
		if (type == DUMP_PREFIX_OFFSET)
			EMIT(&o, "%.8zx: ", off);
		else if (type == DUMP_PREFIX_ADDRESS)
			EMIT(&o, "%p: ", (void *)(b + off));
		for (size_t i = 0; i + groupsize <= n; i += groupsize) {
			u64 v = 0;
			memcpy(&v, b + off + i, groupsize); /* little-endian, like the kernel */
			EMIT(&o, "%0*llx ", groupsize * 2, (unsigned long long)v);
		}
		if (ascii)
			for (size_t i = 0; i < n; i++)
				put(&o, isprint(b[off + i]) ? b[off + i] : '.');
		line[min(o.len, sizeof(line) - 1)] = 0;
		lkpi_log(lv, "%s\n", line);
	}
}

/* ---------- small library functions ---------- */
unsigned long find_next_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	while (off < size) {
		unsigned long w = a[BIT_WORD(off)] & (~0UL << (off % BITS_PER_LONG));
		if (w)
			return min(size, BIT_WORD(off) * BITS_PER_LONG + __builtin_ctzl(w));
		off = (BIT_WORD(off) + 1) * BITS_PER_LONG;
	}
	return size;
}

unsigned long find_next_zero_bit(const unsigned long *a, unsigned long size, unsigned long off)
{
	while (off < size) {
		unsigned long w = ~a[BIT_WORD(off)] & (~0UL << (off % BITS_PER_LONG));
		if (w)
			return min(size, BIT_WORD(off) * BITS_PER_LONG + __builtin_ctzl(w));
		off = (BIT_WORD(off) + 1) * BITS_PER_LONG;
	}
	return size;
}

void bitmap_fill(unsigned long *d, unsigned int n)
{
	unsigned int full = n / BITS_PER_LONG;
	memset(d, 0xff, full * sizeof(long));
	if (n % BITS_PER_LONG)
		d[full] = ~0UL >> (BITS_PER_LONG - n % BITS_PER_LONG);
}

unsigned int bitmap_weight(const unsigned long *s, unsigned int n)
{
	unsigned int w = 0, i;
	for (i = 0; i < n / BITS_PER_LONG; i++)
		w += __builtin_popcountl(s[i]);
	if (n % BITS_PER_LONG)
		w += __builtin_popcountl(s[i] & (~0UL >> (BITS_PER_LONG - n % BITS_PER_LONG)));
	return w;
}

void *memchr_inv(const void *s, int c, size_t n)
{
	const u8 *p = s;
	for (size_t i = 0; i < n; i++)
		if (p[i] != (u8)c)
			return (void *)(p + i);
	return NULL;
}

/* shortcut: swap_fn ignored (rtw89 passes NULL), honour it if a caller sorts relative pointers */
void sort(void *base, size_t num, size_t size, int (*cmp)(const void *, const void *),
	  void (*swap_fn)(void *, void *, int))
{
	qsort(base, num, size, cmp);
}

/* ---------- netdev / napi (rtw89 uses napi only on PCIe) ---------- */
struct net_device *alloc_netdev_dummy(int sizeof_priv)
{
	size_t hdr = ALIGN(sizeof(struct net_device), NETDEV_ALIGN);
	struct net_device *d = calloc(1, hdr + sizeof_priv);
	if (!d)
		return NULL;
	strlcpy(d->name, "dummy", sizeof(d->name));
	d->priv = (char *)d + hdr;
	return d;
}

void free_netdev(struct net_device *dev) { free(dev); }

void netif_napi_add(struct net_device *dev, struct napi_struct *napi, int (*poll)(struct napi_struct *, int))
{
	napi->dev = dev;
	napi->poll = poll;
	napi->weight = NAPI_POLL_WEIGHT;
}

/* shortcut: polls inline; only the PCIe path schedules napi, give it a thread if PCIe is ever wired up */
void napi_schedule(struct napi_struct *n)
{
	if (n->poll)
		n->poll(n, n->weight);
}

/* ---------- sk_buff (one linear buffer) ---------- */
struct sk_buff *alloc_skb(unsigned int size, gfp_t gfp)
{
	struct sk_buff *skb = calloc(1, sizeof(*skb));

	if (!skb)
		return NULL;
	skb->head = malloc(size ? size : 1);
	if (!skb->head) {
		free(skb);
		return NULL;
	}
	skb->data = skb->tail = skb->head;
	skb->end = skb->head + size;
	return skb;
}

void kfree_skb(struct sk_buff *skb)
{
	if (!skb)
		return;
	free(skb->head);
	free(skb);
}

struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp)
{
	struct sk_buff *n = alloc_skb(skb->end - skb->head, gfp);

	if (!n)
		return NULL;
	skb_reserve(n, skb_headroom(skb));
	skb_put_data(n, skb->data, skb->len);
	memcpy(n->cb, skb->cb, sizeof(n->cb));
	n->priority = skb->priority;
	n->protocol = skb->protocol;
	n->queue_mapping = skb->queue_mapping;
	n->mac_header = skb->mac_header;
	n->network_header = skb->network_header;
	n->transport_header = skb->transport_header;
	n->dev = skb->dev;
	return n;
}

int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp)
{
	size_t size = (skb->end - skb->head) + nhead + ntail;
	u8 *h = malloc(size);

	if (!h)
		return -ENOMEM;
	memcpy(h + nhead, skb->head, skb->tail - skb->head);
	skb->data = h + nhead + (skb->data - skb->head);
	skb->tail = skb->data + skb->len;
	skb->end = h + size;
	skb->mac_header += nhead;
	skb->network_header += nhead;
	skb->transport_header += nhead;
	free(skb->head);
	skb->head = h;
	return 0;
}

/* ---------- firmware files ---------- */
#define LKPI_FW_DEFAULT_DIR "/Library/Application Support/USB Wifi/fw"
#define LKPI_FW_MAX (8u << 20)

static int fw_load(const struct firmware **out, const char *name, bool warn)
{
	const char *dir = getenv("LKPI_FW_DIR");
	char path[PATH_MAX];
	struct stat st;
	FILE *f;

	*out = NULL;
	/* the name comes from the driver, still refuse anything that escapes the firmware dir */
	if (!name || !*name || name[0] == '/' || strstr(name, ".."))
		return -EINVAL;
	if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir && *dir ? dir : LKPI_FW_DEFAULT_DIR, name) >= sizeof(path))
		return -ENAMETOOLONG;
	f = fopen(path, "rb");
	if (!f) {
		if (warn)
			lkpi_log(3, "firmware %s not found\n", path);
		return -ENOENT;
	}
	if (fstat(fileno(f), &st) || st.st_size <= 0 || (u64)st.st_size > LKPI_FW_MAX) {
		fclose(f);
		lkpi_log(3, "firmware %s: bad size\n", path);
		return -EINVAL;
	}
	struct firmware *fw = malloc(sizeof(*fw));
	u8 *data = malloc(st.st_size);
	if (!fw || !data || fread(data, 1, st.st_size, f) != (size_t)st.st_size) {
		fclose(f);
		free(fw);
		free(data);
		return -EIO;
	}
	fclose(f);
	fw->size = st.st_size;
	fw->data = data;
	*out = fw;
	return 0;
}

int request_firmware(const struct firmware **fw, const char *name, struct device *dev)
{
	return fw_load(fw, name, true);
}

int firmware_request_nowarn(const struct firmware **fw, const char *name, struct device *dev)
{
	return fw_load(fw, name, false);
}

void release_firmware(const struct firmware *fw)
{
	if (!fw)
		return;
	free((void *)fw->data);
	free((void *)fw);
}

/* ---------- start-up ---------- */
__attribute__((constructor)) static void lkpi_kernel_init(void)
{
	start_thread(timer_main, NULL, QOS_CLASS_USER_INTERACTIVE);
	start_thread(dfree_main, NULL, QOS_CLASS_UTILITY);
	system_wq = wq_create("lkpi-events", 2, QOS_CLASS_USER_INITIATED, NULL);
	if (!system_wq)
		abort();
}
