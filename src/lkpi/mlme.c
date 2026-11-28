// SPDX-License-Identifier: BSD-3-Clause
/*
 * Minimal station MLME for the rtw89 port: scan, open auth + association,
 * CCMP keys, 802.3 <-> 802.11 data path, block-ack, RX reorder and replay
 * checks. The 4-way handshake lives in the backend (see ../rtwd.h).
 *
 * Lock order: op_lock -> wiphy -> rx_lock -> tx_lock -> txq q.lock.
 */
#include <pthread.h>
#include <string.h>
#include "local.h"
#include "lkpi_usb.h"
#include "../rtwd.h"
#include "aic8800_reord.h"

#define HW() (&M.l->hw)
#define WIPHY() (&M.l->wiphy)
#define OPS() (M.l->ops)
#define VIF() (&M.l->lv->vif)
#define STA() (&M.sta->sta)
#define NTID 16 /* index of the non-QoS sequence/PN slot */
#define FCS_LEN 4

struct mkey {
	struct mkey *next; /* retired list */
	struct ieee80211_key_conf k; /* last: key bytes follow */
};

/* a beacon or probe response kept from the last scan */
struct bss {
	u8 bssid[ETH_ALEN];
	u16 freq;
	u16 len;
	u8 f[2400];
};
#define NBSS 64

static DEFINE_MUTEX(op_lock);
static DEFINE_MUTEX(rx_lock);
static DEFINE_MUTEX(tx_lock);

static struct {
	const struct rtwd_cb *cb;
	struct usb_interface *intf;
	struct lkpi_local *l;
	struct lkpi_sta *sta;
	struct ieee80211_chanctx_conf *ctx;
	u8 bssid[ETH_ALEN];
	enum nl80211_band band;
	bool assoc, authorized, rsn, wme, scanning, txblock, ps;
	u64 scan_since;
	int scan_fails;
	bool scan_lost; /* the last scan-done never came and rtwd_gone() aborted that scan */
	struct ieee80211_scan_request *sreq;
	u8 scan_ies[NUM_NL80211_BANDS][20];
	struct bss bss[NBSS];
	int nbss;
	/* join: rx path hands the awaited auth/assoc response over */
	u16 jwant;
	u8 jbuf[1024];
	size_t jlen;
	int jfail;
	struct completion jc;
	/* keys */
	struct mkey *ptk, *gtk[4], *retired;
	/* rx */
	aic_rx_reord_t reord;
	u16 ba_rx;
	u64 rx_pn[NTID + 1], gtk_pn[4];
	u16 last_seq[NTID + 1];
	/* tx */
	u16 seq[NTID + 1];
	u16 ba_want, ba_stop, ba_tx, ba_tried, ba_pending, ba_amsdu;
	/* deferred work */
	unsigned int token, loss_token;
	u16 loss_reason;
	bool loss_tx;
	struct work_struct loss_work;
	struct wiphy_work ba_work, mgmt_work;
	struct delayed_work reord_dw;
	struct sk_buff_head mgmt_q;
	/* LED: rtwd_led() mode, led_dw blinks it while led_alive (open .. close) */
	struct delayed_work led_dw;
	volatile int led_mode;
	volatile bool led_alive;
	bool led_lit;
} M;

static const u8 rfc1042[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };
static const u8 bridge_tunnel[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };
static const u8 wmm_oui[4] = { 0x00, 0x50, 0xf2, 0x02 };

/* ---------- small helpers ---------- */

static const u8 *ie_find(const u8 *ies, size_t len, u8 id)
{
	while (len >= 2 && ies[1] + 2u <= len) {
		if (ies[0] == id)
			return ies;
		len -= ies[1] + 2u;
		ies += ies[1] + 2u;
	}
	return NULL;
}

/* WMM information (subtype 0) or parameter (subtype 1) element */
static const u8 *wmm_find(const u8 *ies, size_t len, u8 subtype)
{
	while (len >= 2 && ies[1] + 2u <= len) {
		if (ies[0] == WLAN_EID_VENDOR_SPECIFIC && ies[1] >= 7 && !memcmp(ies + 2, wmm_oui, 4) &&
		    ies[6] == subtype)
			return ies;
		len -= ies[1] + 2u;
		ies += ies[1] + 2u;
	}
	return NULL;
}

static struct ieee80211_channel *find_chan(u16 freq)
{
	for (int b = 0; b < NUM_NL80211_BANDS; b++) {
		struct ieee80211_supported_band *sb = M.l->wiphy.bands[b];

		for (int i = 0; sb && i < sb->n_channels; i++)
			if (sb->channels[i].center_freq == freq)
				return &sb->channels[i];
	}
	return NULL;
}

static bool chan_ok(int freq)
{
	struct ieee80211_channel *c = find_chan(freq);

	return c && !(c->flags & IEEE80211_CHAN_DISABLED);
}

static u8 *put_rates(u8 *p, const struct ieee80211_supported_band *sb)
{
	int n = sb->n_bitrates, a = n < 8 ? n : 8;

	*p++ = WLAN_EID_SUPP_RATES;
	*p++ = a;
	for (int i = 0; i < a; i++)
		*p++ = sb->bitrates[i].bitrate / 5;
	if (n > 8) {
		*p++ = WLAN_EID_EXT_SUPP_RATES;
		*p++ = n - 8;
		for (int i = 8; i < n; i++)
			*p++ = sb->bitrates[i].bitrate / 5;
	}
	return p;
}

/* AP rate list (500 kb/s units, 0x80 = basic) -> sband bitrate index masks */
static void rate_masks(const u8 *ies, size_t len, const struct ieee80211_supported_band *sb, u32 *supp, u32 *basic)
{
	*supp = *basic = 0;
	for (int e = 0; e < 2; e++) {
		const u8 *r = ie_find(ies, len, e ? WLAN_EID_EXT_SUPP_RATES : WLAN_EID_SUPP_RATES);

		for (int i = 0; r && i < r[1]; i++)
			for (int j = 0; j < sb->n_bitrates; j++)
				if ((r[2 + i] & 0x7f) * 5 == sb->bitrates[j].bitrate) {
					*supp |= BIT(j);
					if (r[2 + i] & 0x80)
						*basic |= BIT(j);
				}
	}
	if (!*supp)
		*supp = BIT(0);
	if (!*basic)
		*basic = *supp & -*supp; /* lowest common rate */
}

static int sta_move(enum ieee80211_sta_state to)
{
	struct lkpi_sta *s = M.sta;

	while (s->state != to) {
		enum ieee80211_sta_state n = s->state < to ? s->state + 1 : s->state - 1;
		int r = OPS()->sta_state(HW(), VIF(), &s->sta, s->state, n);

		if (r && n > s->state)
			return r;
		s->state = n;
	}
	return 0;
}

static void mgmt_hdr(struct ieee80211_mgmt *m, u16 stype)
{
	memset(m, 0, 24);
	m->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | stype);
	memcpy(m->da, M.bssid, ETH_ALEN);
	memcpy(m->sa, VIF()->addr, ETH_ALEN);
	memcpy(m->bssid, M.bssid, ETH_ALEN);
}

/* shortcut: mgmt frames always go out unprotected (no PMF), upgrade with WPA3 */
static void mgmt_tx(const void *frame, size_t len)
{
	struct sk_buff *skb = dev_alloc_skb(HW()->extra_tx_headroom + len);
	struct ieee80211_tx_info *info;
	struct lkpi_sta *s = uploaded_sta(M.l);

	if (!skb)
		return;
	skb_reserve(skb, HW()->extra_tx_headroom);
	skb_put_data(skb, frame, len);
	info = IEEE80211_SKB_CB(skb);
	memset(info, 0, sizeof(*info));
	info->band = M.band;
	info->control.vif = VIF();
	OPS()->tx(HW(), &(struct ieee80211_tx_control){ .sta = s ? &s->sta : NULL }, skb);
}

static void txq_purge(struct ieee80211_txq *tq)
{
	if (!tq) /* txq_alloc failed partway through a connect */
		return;
	struct lkpi_txq *t = to_lt(tq);

	spin_lock(&t->q.lock);
	__skb_queue_purge(&t->q);
	t->bytes = 0;
	spin_unlock(&t->q.lock);
}

/* let queued frames go out under the key they were built for, ~200 ms max */
static void txqs_drain(void)
{
	for (int i = 0; i < 200; i++) {
		bool busy = false;

		for (int tid = 0; tid < IEEE80211_NUM_TIDS; tid++) {
			struct lkpi_txq *t = to_lt(STA()->txq[tid]);

			spin_lock(&M.l->txq_lock);
			busy |= t->inflight || t->q.qlen;
			spin_unlock(&M.l->txq_lock);
		}
		if (!busy)
			return;
		lkpi_sleep_us(1000);
	}
	/* shortcut: frames still queued after the timeout are dropped, not resent */
	for (int tid = 0; tid < IEEE80211_NUM_TIDS; tid++)
		txq_purge(STA()->txq[tid]);
}

static int ampdu(enum ieee80211_ampdu_mlme_action a, u8 tid, u16 ssn, u16 buf, bool amsdu)
{
	struct ieee80211_ampdu_params p = { .action = a, .sta = STA(), .tid = tid, .ssn = ssn,
					    .buf_size = buf, .amsdu = amsdu };

	return OPS()->ampdu_action(HW(), VIF(), &p);
}

/* ---------- RX: reorder output -> replay check -> decap ---------- */

struct rxout { struct sk_buff_head q; };

static void rx_drop(void *head, void *ctx)
{
	for (struct sk_buff *s = head, *n; s; s = n) {
		n = s->next;
		kfree_skb(s);
	}
}

static void rx_append(void *tail, void *pkt)
{
	((struct sk_buff *)tail)->next = pkt;
}

/* queue one decapped frame (DA, SA, proto, payload); cb->rx runs later, unlocked */
static void rx_emit(struct rxout *o, const u8 *da, const u8 *sa, const u8 *proto_payload, size_t plen)
{
	u16 proto = get_unaligned_be16(proto_payload);
	struct sk_buff *e;

	if (!M.authorized && proto != ETH_P_PAE)
		return; /* port closed: EAPOL only */
	e = alloc_skb(12 + plen, GFP_ATOMIC);
	if (!e)
		return;
	skb_put_data(e, da, ETH_ALEN);
	skb_put_data(e, sa, ETH_ALEN);
	skb_put_data(e, proto_payload, plen);
	e->cb[0] = proto == ETH_P_PAE;
	__skb_queue_tail(&o->q, e);
}

static bool snap_ok(const u8 *p, size_t len)
{
	return len >= 8 && (!memcmp(p, rfc1042, 6) || !memcmp(p, bridge_tunnel, 6));
}

static u64 ccmp_pn(const u8 *iv)
{
	return (u64)iv[0] | (u64)iv[1] << 8 | (u64)iv[4] << 16 | (u64)iv[5] << 24 | (u64)iv[6] << 32 |
	       (u64)iv[7] << 40;
}

/* rx_lock held; consumes skb */
static void rx_one(struct sk_buff *skb, struct rxout *o)
{
	struct ieee80211_hdr *h = (void *)skb->data;
	struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb);
	u16 fc = le16_to_cpu(h->frame_control);
	unsigned int hl = ieee80211_hdrlen(h->frame_control);
	bool mc = is_multicast_ether_addr(h->addr1), qos = ieee80211_is_data_qos(h->frame_control);
	u8 tid = qos ? ieee80211_get_tid(h) : NTID;
	u8 da[ETH_ALEN], sa[ETH_ALEN];
	u8 *p;
	size_t plen;

	if (fc & IEEE80211_FCTL_PROTECTED) {
		const u8 *iv = skb->data + hl;
		u8 kid;
		u64 pn, *last;

		if (skb->len < hl + 16 || !(st->flag & RX_FLAG_DECRYPTED) || !(iv[3] & 0x20))
			goto drop;
		kid = iv[3] >> 6;
		if (mc ? !M.gtk[kid] : !M.ptk)
			goto drop;
		pn = ccmp_pn(iv);
		last = mc ? &M.gtk_pn[kid] : &M.rx_pn[tid];
		if (pn <= *last)
			goto drop; /* replay */
		*last = pn;
		if (!(st->flag & RX_FLAG_IV_STRIPPED)) {
			memmove(skb->data + 8, skb->data, hl);
			skb_pull(skb, 8);
			h = (void *)skb->data;
		}
		if (!(st->flag & RX_FLAG_MIC_STRIPPED))
			skb_trim(skb, skb->len - 8);
	} else if (M.rsn && M.ptk) {
		goto drop; /* keys are in place: plaintext data is not accepted */
	}

	p = skb->data + hl;
	plen = skb->len - hl;
	if (qos && (*ieee80211_get_qos_ctl(h) & IEEE80211_QOS_CTL_A_MSDU_PRESENT)) {
		/* FragAttacks: an A-MSDU whose first DA looks like an LLC/SNAP header is forged */
		if (plen >= 14 && !memcmp(p, rfc1042, 6))
			goto drop;
		while (plen >= 14) {
			size_t sl = get_unaligned_be16(p + 12);

			if (14 + sl > plen || !snap_ok(p + 14, sl))
				break;
			rx_emit(o, p, p + 6, p + 14 + 6, sl - 6);
			sl = 14 + sl;
			if (sl == plen)
				break;
			sl = (sl + 3) & ~3u;
			if (sl > plen)
				break;
			p += sl;
			plen -= sl;
		}
		goto drop;
	}
	/* shortcut: only RFC1042/bridge-tunnel SNAP payloads, others are dropped */
	if (!snap_ok(p, plen))
		goto drop;
	memcpy(da, h->addr1, ETH_ALEN);
	memcpy(sa, h->addr3, ETH_ALEN); /* FromDS: addr3 is the source */
	rx_emit(o, da, sa, p + 6, plen - 6);
drop:
	kfree_skb(skb);
}

static void rx_deliver(void *head, uint32_t bytes, void *ctx)
{
	for (struct sk_buff *s = head, *n; s; s = n) {
		n = s->next;
		s->next = NULL;
		rx_one(s, ctx);
	}
}

static void rx_flush_out(struct rxout *o)
{
	struct sk_buff *e;

	while ((e = __skb_dequeue(&o->q))) {
		if (M.cb && M.cb->rx)
			M.cb->rx(e->data, e->len, e->cb[0]);
		kfree_skb(e);
	}
}

static void reord_timeout(struct work_struct *w)
{
	struct rxout o;
	bool more;

	__skb_queue_head_init(&o.q);
	mutex_lock(&rx_lock);
	more = aic_rx_reord_timeout_flush(&M.reord, rx_deliver, &o);
	mutex_unlock(&rx_lock);
	if (more)
		schedule_delayed_work(&M.reord_dw, msecs_to_jiffies(AIC_REORD_TIMEOUT_MS));
	rx_flush_out(&o);
}

static void rx_data(struct sk_buff *skb)
{
	struct ieee80211_hdr *h = (void *)skb->data;
	u16 fc = le16_to_cpu(h->frame_control);
	bool mc = is_multicast_ether_addr(h->addr1), qos = ieee80211_is_data_qos(h->frame_control);
	u16 sc = le16_to_cpu(h->seq_ctrl), sn = sc >> 4;
	u8 tid = qos ? ieee80211_get_tid(h) : NTID;
	bool timer = false;
	struct rxout o;

	/* AP -> us only; no nulls, no 4-addr, shortcut: no defragmentation */
	if ((fc & (IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS)) != IEEE80211_FCTL_FROMDS ||
	    (fc & IEEE80211_FCTL_MOREFRAGS) || (sc & IEEE80211_SCTL_FRAG) || (fc & 0x0040) /* no data */ ||
	    skb->len < ieee80211_hdrlen(h->frame_control) + 8) {
		kfree_skb(skb);
		return;
	}
	__skb_queue_head_init(&o.q);
	mutex_lock(&rx_lock);
	if (!M.assoc || !ether_addr_equal(h->addr2, M.bssid) ||
	    (!mc && !ether_addr_equal(h->addr1, VIF()->addr)) || (mc && ether_addr_equal(h->addr3, VIF()->addr))) {
		kfree_skb(skb);
		goto out;
	}
	skb->next = NULL;
	if (!mc && qos && tid < 8 && (M.ba_rx & BIT(tid))) {
		aic_rx_reord_submit(&M.reord, tid, sn, skb, skb->len, false, rx_deliver, rx_append, rx_drop, &o,
				    &timer);
	} else {
		if (!mc && (fc & IEEE80211_FCTL_RETRY) && M.last_seq[tid] == sc) {
			kfree_skb(skb); /* retransmission */
			goto out;
		}
		if (!mc)
			M.last_seq[tid] = sc;
		rx_one(skb, &o);
	}
out:
	mutex_unlock(&rx_lock);
	if (timer)
		schedule_delayed_work(&M.reord_dw, msecs_to_jiffies(AIC_REORD_TIMEOUT_MS));
	rx_flush_out(&o);
}

static void loss_queue(u16 reason, bool tx)
{
	M.loss_reason = reason;
	M.loss_tx = tx;
	__atomic_store_n(&M.loss_token, __atomic_load_n(&M.token, __ATOMIC_RELAXED), __ATOMIC_RELEASE);
	schedule_work(&M.loss_work);
}

static void rx_mgmt(struct sk_buff *skb)
{
	struct ieee80211_mgmt *m = (void *)skb->data;
	__le16 fc = m->frame_control;
	size_t len = skb->len;
	struct sk_buff *c;

	if (len < 24)
		return;
	if (ieee80211_is_beacon(fc) || ieee80211_is_probe_resp(fc)) {
		struct bss *b = NULL;

		if (!M.scanning || len < 36 || len > sizeof(b->f))
			return;
		mutex_lock(&rx_lock);
		for (int i = 0; i < M.nbss; i++)
			if (ether_addr_equal(M.bss[i].bssid, m->bssid))
				b = &M.bss[i];
		if (!b && M.nbss < NBSS)
			b = &M.bss[M.nbss++];
		if (b) {
			/* keep a probe response over a beacon: it carries the full IE set */
			if (!ieee80211_is_beacon(fc) || !b->len || ieee80211_is_beacon(((struct ieee80211_mgmt *)b->f)->frame_control)) {
				memcpy(b->bssid, m->bssid, ETH_ALEN);
				b->freq = IEEE80211_SKB_RXCB(skb)->freq;
				b->len = len;
				memcpy(b->f, m, len);
			}
		}
		mutex_unlock(&rx_lock);
		if (M.cb && M.cb->bss)
			M.cb->bss(skb->data, len, IEEE80211_SKB_RXCB(skb)->freq, IEEE80211_SKB_RXCB(skb)->signal);
		return;
	}
	if (!ether_addr_equal(m->da, VIF()->addr) || !ether_addr_equal(m->sa, M.bssid))
		return;
	if (ieee80211_has_protected(fc))
		return; /* shortcut: no PMF yet, protected mgmt frames are ignored */
	mutex_lock(&rx_lock);
	if ((ieee80211_is_auth(fc) && M.jwant == IEEE80211_STYPE_AUTH) ||
	    ((ieee80211_is_assoc_resp(fc) || ieee80211_is_reassoc_resp(fc)) && M.jwant == IEEE80211_STYPE_ASSOC_RESP)) {
		M.jlen = len < sizeof(M.jbuf) ? len : sizeof(M.jbuf);
		memcpy(M.jbuf, m, M.jlen);
		M.jwant = 0;
		complete(&M.jc);
	} else if ((ieee80211_is_deauth(fc) || ieee80211_is_disassoc(fc)) && len >= 26) {
		/* shortcut: unprotected deauth is honoured (no PMF), upgrade with WPA3 */
		u16 reason = le16_to_cpu(m->u.deauth.reason_code);

		if (M.jwant) {
			M.jfail = reason ? reason : 1;
			M.jwant = 0;
			complete(&M.jc);
		} else if (M.assoc) {
			loss_queue(reason, false);
		}
	} else if (ieee80211_is_action(fc) && len > 25 && m->u.action.category == WLAN_CATEGORY_BACK && M.assoc &&
		   (c = skb_copy(skb, GFP_ATOMIC))) {
		skb_queue_tail(&M.mgmt_q, c);
		wiphy_work_queue(WIPHY(), &M.mgmt_work);
	}
	mutex_unlock(&rx_lock);
}

void ieee80211_rx_napi(struct ieee80211_hw *hw, struct ieee80211_link_sta *link_sta, struct sk_buff *skb,
		       struct napi_struct *napi)
{
	struct ieee80211_rx_status *st = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_hdr *h = (void *)skb->data;

	if ((st->flag & RX_FLAG_FAILED_FCS_CRC) || skb->len < 24 + FCS_LEN || !M.l) {
		kfree_skb(skb);
		return;
	}
	skb_trim(skb, skb->len - FCS_LEN);
	if (ieee80211_is_mgmt(h->frame_control)) {
		rx_mgmt(skb);
		kfree_skb(skb);
	} else if (ieee80211_is_data(h->frame_control)) {
		rx_data(skb);
	} else {
		kfree_skb(skb);
	}
}

/* ---------- block ack ---------- */

static void addba_req_tx(u8 tid, u16 ssn)
{
	u8 f[64];
	struct ieee80211_mgmt *m = (void *)f;

	mgmt_hdr(m, IEEE80211_STYPE_ACTION);
	m->u.action.category = WLAN_CATEGORY_BACK;
	m->u.action.action_code = WLAN_ACTION_ADDBA_REQ;
	m->u.action.addba_req.dialog_token = tid + 1;
	m->u.action.addba_req.capab = cpu_to_le16(1 | 1 << 1 | tid << 2 | 64 << 6);
	m->u.action.addba_req.timeout = 0;
	m->u.action.addba_req.start_seq_num = cpu_to_le16(ssn << 4);
	mgmt_tx(f, offsetof(struct ieee80211_mgmt, u.action.addba_req) + sizeof(m->u.action.addba_req));
}

static void delba_tx(u8 tid, bool initiator)
{
	u8 f[64];
	struct ieee80211_mgmt *m = (void *)f;

	mgmt_hdr(m, IEEE80211_STYPE_ACTION);
	m->u.action.category = WLAN_CATEGORY_BACK;
	m->u.action.action_code = WLAN_ACTION_DELBA;
	m->u.action.delba.params = cpu_to_le16((initiator ? 1 << 11 : 0) | tid << 12);
	m->u.action.delba.reason_code = cpu_to_le16(WLAN_REASON_QSTA_LEAVE_QBSS);
	mgmt_tx(f, offsetof(struct ieee80211_mgmt, u.action.delba) + sizeof(m->u.action.delba));
}

/* wiphy held */
static void ba_work_fn(struct wiphy *w, struct wiphy_work *wk)
{
	u16 want = __atomic_exchange_n(&M.ba_want, 0, __ATOMIC_ACQ_REL);
	u16 stop = __atomic_exchange_n(&M.ba_stop, 0, __ATOMIC_ACQ_REL);

	if (!M.authorized)
		return;
	for (u8 tid = 0; tid < 8; tid++) {
		if ((stop & BIT(tid)) && (M.ba_tx | M.ba_pending) & BIT(tid)) {
			ampdu(IEEE80211_AMPDU_TX_STOP_FLUSH, tid, 0, 0, false);
			delba_tx(tid, true);
			M.ba_tx &= ~BIT(tid);
			M.ba_pending &= ~BIT(tid);
			M.ba_tried &= ~BIT(tid);
		}
		if ((want & BIT(tid)) && !((M.ba_tried | M.ba_tx) & BIT(tid))) {
			u16 ssn;
			int r;

			mutex_lock(&tx_lock);
			ssn = M.seq[tid] & 0xfff;
			mutex_unlock(&tx_lock);
			M.ba_tried |= BIT(tid);
			r = ampdu(IEEE80211_AMPDU_TX_START, tid, ssn, 0, false);
			if (r == 0 || r == IEEE80211_AMPDU_TX_START_IMMEDIATE) {
				M.ba_pending |= BIT(tid);
				addba_req_tx(tid, ssn);
			}
		}
	}
}

/* shortcut: no ADDBA response timeout, a lost response leaves that TID non-aggregated */
static void mgmt_work_fn(struct wiphy *w, struct wiphy_work *wk)
{
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&M.mgmt_q))) {
		struct ieee80211_mgmt *m = (void *)skb->data;
		u8 act = m->u.action.action_code;

		if (!M.assoc)
			goto next;
		if (act == WLAN_ACTION_ADDBA_REQ && skb->len >= 33) {
			u16 capab = le16_to_cpu(m->u.action.addba_req.capab);
			u8 tid = (capab >> 2) & 0xf, f[64];
			u16 buf = capab >> 6, ssn = le16_to_cpu(m->u.action.addba_req.start_seq_num) >> 4;
			u16 status = WLAN_STATUS_REQUEST_DECLINED;
			struct ieee80211_mgmt *r = (void *)f;

			if (!buf || buf > AIC_REORD_WINSIZE)
				buf = AIC_REORD_WINSIZE;
			if (tid < 8 && (capab & 2)) {
				if (M.ba_rx & BIT(tid))
					ampdu(IEEE80211_AMPDU_RX_STOP, tid, 0, 0, false);
				if (!ampdu(IEEE80211_AMPDU_RX_START, tid, ssn, buf, false)) {
					struct rxout o;

					__skb_queue_head_init(&o.q);
					mutex_lock(&rx_lock);
					aic_rx_reord_flush_tid(&M.reord, tid, false, rx_deliver, rx_drop, &o);
					M.ba_rx |= BIT(tid);
					mutex_unlock(&rx_lock);
					rx_flush_out(&o);
					status = 0;
				} else {
					M.ba_rx &= ~BIT(tid);
				}
			}
			mgmt_hdr(r, IEEE80211_STYPE_ACTION);
			r->u.action.category = WLAN_CATEGORY_BACK;
			r->u.action.action_code = WLAN_ACTION_ADDBA_RESP;
			r->u.action.addba_resp.dialog_token = m->u.action.addba_req.dialog_token;
			r->u.action.addba_resp.status = cpu_to_le16(status);
			r->u.action.addba_resp.capab = cpu_to_le16((capab & 1) | 1 << 1 | tid << 2 | buf << 6);
			r->u.action.addba_resp.timeout = m->u.action.addba_req.timeout;
			mgmt_tx(f, offsetof(struct ieee80211_mgmt, u.action.addba_resp) +
					   sizeof(r->u.action.addba_resp));
		} else if (act == WLAN_ACTION_ADDBA_RESP && skb->len >= 33) {
			u16 capab = le16_to_cpu(m->u.action.addba_resp.capab);
			u8 tid = (capab >> 2) & 0xf;
			u16 buf = capab >> 6;

			if (tid >= 8 || !(M.ba_pending & BIT(tid)))
				goto next;
			M.ba_pending &= ~BIT(tid);
			if (!m->u.action.addba_resp.status) {
				if (!buf || buf > 64)
					buf = 64;
				ampdu(IEEE80211_AMPDU_TX_OPERATIONAL, tid, 0, buf, capab & 1);
				M.ba_amsdu = (M.ba_amsdu & ~BIT(tid)) | (capab & 1) << tid;
				M.ba_tx |= BIT(tid);
			} else {
				ampdu(IEEE80211_AMPDU_TX_STOP_CONT, tid, 0, 0, false);
			}
		} else if (act == WLAN_ACTION_DELBA && skb->len >= 28) {
			u16 params = le16_to_cpu(m->u.action.delba.params);
			u8 tid = params >> 12;

			if (tid >= 8)
				goto next;
			if (params & (1 << 11)) { /* AP was the originator: our RX session */
				struct rxout o;

				if (!(M.ba_rx & BIT(tid)))
					goto next;
				ampdu(IEEE80211_AMPDU_RX_STOP, tid, 0, 0, false);
				__skb_queue_head_init(&o.q);
				mutex_lock(&rx_lock);
				M.ba_rx &= ~BIT(tid);
				aic_rx_reord_flush_tid(&M.reord, tid, false, rx_deliver, rx_drop, &o);
				mutex_unlock(&rx_lock);
				rx_flush_out(&o);
			} else if ((M.ba_tx | M.ba_pending) & BIT(tid)) {
				ampdu(IEEE80211_AMPDU_TX_STOP_FLUSH, tid, 0, 0, false);
				M.ba_tx &= ~BIT(tid);
				M.ba_pending &= ~BIT(tid);
			}
		}
next:
		kfree_skb(skb);
	}
}

/* rtw89 calls these from its ba work under a spinlock: only record and defer */
int ieee80211_start_tx_ba_session(struct ieee80211_sta *sta, u16 tid, u16 timeout)
{
	if (tid >= 8)
		return -EINVAL;
	if (__atomic_load_n(&M.ba_tried, __ATOMIC_RELAXED) & BIT(tid) &&
	    !(__atomic_load_n(&M.ba_tx, __ATOMIC_RELAXED) & BIT(tid)))
		return -EINVAL; /* the AP refused or never answered */
	__atomic_fetch_or(&M.ba_want, BIT(tid), __ATOMIC_RELEASE);
	wiphy_work_queue(WIPHY(), &M.ba_work);
	return 0;
}

int ieee80211_stop_tx_ba_session(struct ieee80211_sta *sta, u16 tid)
{
	if (tid >= 8)
		return -EINVAL;
	__atomic_fetch_or(&M.ba_stop, BIT(tid), __ATOMIC_RELEASE);
	wiphy_work_queue(WIPHY(), &M.ba_work);
	return 0;
}

void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_vif *vif, const u8 *ra, u16 tid) { }

/* ---------- keys ---------- */

void ieee80211_iter_keys(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			 void (*iter)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta,
				      struct ieee80211_key_conf *key, void *data),
			 void *iter_data)
{
	if (M.ptk)
		iter(hw, vif, STA(), &M.ptk->k, iter_data);
	for (int i = 0; i < 4; i++)
		if (M.gtk[i])
			iter(hw, vif, NULL, &M.gtk[i]->k, iter_data);
}

static void key_retire(struct mkey *k)
{
	if (k) {
		k->next = M.retired;
		M.retired = k;
	}
}

/* ---------- teardown (wiphy held) ---------- */

static void teardown(u16 reason, bool send)
{
	struct lkpi_sta *s = M.sta;
	struct mkey *ptk, *gtk[4];
	bool was_assoc;
	struct rxout o;

	if (!M.ctx)
		return;
	wiphy_work_cancel(WIPHY(), &M.ba_work);
	wiphy_work_cancel(WIPHY(), &M.mgmt_work);
	skb_queue_purge(&M.mgmt_q);
	mutex_lock(&rx_lock);
	mutex_lock(&tx_lock);
	was_assoc = M.assoc;
	M.assoc = M.authorized = M.txblock = false;
	M.jwant = 0;
	ptk = M.ptk;
	M.ptk = NULL;
	memcpy(gtk, M.gtk, sizeof(gtk));
	memset(M.gtk, 0, sizeof(M.gtk));
	mutex_unlock(&tx_lock);
	mutex_unlock(&rx_lock);

	for (int tid = 0; tid < IEEE80211_NUM_TIDS; tid++)
		txq_purge(s->sta.txq[tid]);
	if (send && s->state >= IEEE80211_STA_AUTH && !lkpi_usb_gone(M.intf)) {
		u8 f[26];
		struct ieee80211_mgmt *m = (void *)f;

		mgmt_hdr(m, IEEE80211_STYPE_DEAUTH);
		m->u.deauth.reason_code = cpu_to_le16(reason);
		mgmt_tx(f, sizeof(f));
		OPS()->flush(HW(), VIF(), ~0u, false);
	}
	OPS()->flush(HW(), VIF(), ~0u, true);
	if (ptk)
		OPS()->set_key(HW(), DISABLE_KEY, VIF(), &s->sta, &ptk->k);
	key_retire(ptk);
	for (int i = 0; i < 4; i++) {
		if (gtk[i])
			OPS()->set_key(HW(), DISABLE_KEY, VIF(), NULL, &gtk[i]->k);
		key_retire(gtk[i]);
	}
	for (u8 tid = 0; tid < 8; tid++) {
		if ((M.ba_tx | M.ba_pending) & BIT(tid))
			ampdu(IEEE80211_AMPDU_TX_STOP_FLUSH, tid, 0, 0, false);
		if (M.ba_rx & BIT(tid))
			ampdu(IEEE80211_AMPDU_RX_STOP, tid, 0, 0, false);
	}
	M.ba_tx = M.ba_pending = M.ba_tried = M.ba_rx = M.ba_amsdu = 0;
	__atomic_store_n(&M.ba_want, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&M.ba_stop, 0, __ATOMIC_RELAXED);
	if (was_assoc) {
		VIF()->cfg.assoc = false;
		VIF()->cfg.aid = 0;
		VIF()->cfg.ps = false; /* mac80211 never keeps PS on without an AP */
		OPS()->vif_cfg_changed(HW(), VIF(), BSS_CHANGED_ASSOC | BSS_CHANGED_PS);
	}
	sta_move(IEEE80211_STA_NOTEXIST);
	M.l->ap = NULL;
	for (int tid = 0; tid < IEEE80211_NUM_TIDS; tid++) {
		txq_free(M.l, s->sta.txq[tid]);
		s->sta.txq[tid] = NULL;
	}
	memset(M.bssid, 0, ETH_ALEN);
	OPS()->link_info_changed(HW(), VIF(), &VIF()->bss_conf, BSS_CHANGED_BSSID);
	OPS()->unassign_vif_chanctx(HW(), VIF(), &VIF()->bss_conf, M.ctx);
	OPS()->remove_chanctx(HW(), M.ctx);
	kfree(M.ctx);
	M.ctx = NULL;
	memset(&VIF()->bss_conf.chanreq, 0, sizeof(VIF()->bss_conf.chanreq));

	__skb_queue_head_init(&o.q);
	mutex_lock(&rx_lock);
	aic_rx_reord_flush_all(&M.reord, true, rx_deliver, rx_drop, &o);
	memset(M.rx_pn, 0, sizeof(M.rx_pn));
	memset(M.gtk_pn, 0, sizeof(M.gtk_pn));
	memset(M.last_seq, 0xff, sizeof(M.last_seq));
	mutex_unlock(&rx_lock);
	__skb_queue_purge(&o.q);
}

/* called by lkpi80211_down() with the wiphy lock held */
void lkpi_mlme_down(struct lkpi_local *l)
{
	if (M.l != l)
		return;
	if (M.scanning)
		OPS()->cancel_hw_scan(HW(), VIF());
	teardown(WLAN_REASON_DEAUTH_LEAVING, true);
}

static void loss_work_fn(struct work_struct *w)
{
	bool fire = false;
	u16 reason;

	mutex_lock(&op_lock);
	reason = M.loss_reason;
	if (M.l && M.assoc && __atomic_load_n(&M.loss_token, __ATOMIC_ACQUIRE) == M.token) {
		wiphy_lock(WIPHY());
		teardown(reason, M.loss_tx);
		wiphy_unlock(WIPHY());
		fire = true;
	}
	mutex_unlock(&op_lock);
	if (fire && M.cb && M.cb->disconnected)
		M.cb->disconnected(reason);
}

/* shortcut: beacon loss is a disconnect (no AP probing first), upgrade if links drop on busy channels */
void ieee80211_beacon_loss(struct ieee80211_vif *vif)
{
	loss_queue(WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY, true);
}

void ieee80211_connection_loss(struct ieee80211_vif *vif)
{
	loss_queue(WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY, false);
}

/* ---------- API ---------- */

static pthread_once_t once = PTHREAD_ONCE_INIT;

/* mode 0: slow blink (not connected), 1: fast blink (connecting), 2: steady on (connected) */
static void led_fn(struct work_struct *w)
{
	int m = M.led_mode;

	if (!M.led_alive)
		return;
	M.led_lit = m == 2 || !M.led_lit;
	/* rtw89's register access shares one USB request buffer, unlocked: the driver's calls are
	   serialized by the wiphy lock, so ours must be too or both writes land corrupted */
	wiphy_lock(WIPHY());
	rtwd_led_set(&M.l->hw, M.led_lit);
	wiphy_unlock(WIPHY());
	if (m != 2)
		schedule_delayed_work(&M.led_dw, msecs_to_jiffies(m ? 120 : 1000));
}

void rtwd_led(int mode)
{
	M.led_mode = mode;
	if (M.led_alive)
		mod_delayed_work(system_wq, &M.led_dw, 0);
}

static void init_once(void)
{
	INIT_WORK(&M.loss_work, loss_work_fn);
	wiphy_work_init(&M.ba_work, ba_work_fn);
	wiphy_work_init(&M.mgmt_work, mgmt_work_fn);
	INIT_DELAYED_WORK(&M.reord_dw, reord_timeout);
	INIT_DELAYED_WORK(&M.led_dw, led_fn);
	skb_queue_head_init(&M.mgmt_q);
	init_completion(&M.jc);
}

int rtwd_open(const struct rtwd_cb *cb, uint8_t mac[6], int timeout_ms, const char *country)
{
	struct ieee80211_hw *hw;
	int r;

	pthread_once(&once, init_once);
	mutex_lock(&op_lock);
	r = -EALREADY;
	if (M.l)
		goto out;
	M.cb = cb;
	r = -ENODEV;
	M.intf = lkpi_usb_probe(timeout_ms);
	if (!M.intf || !(hw = usb_get_intfdata(M.intf)))
		goto err;
	M.sta = kzalloc(sizeof(*M.sta) + hw->sta_data_size, GFP_KERNEL);
	r = -ENOMEM;
	if (!M.sta)
		goto err;
	r = lkpi80211_up(hw);
	if (r)
		goto err;
	M.l = hw_to_local(hw);
	M.sta->lv = M.l->lv;
	regulatory_hint(WIPHY(), country);
	wiphy_lock(WIPHY());
	rtwd_led_init(hw);
	wiphy_unlock(WIPHY());
	M.led_alive = true;
	aic_rx_reord_init(&M.reord);
	memset(M.last_seq, 0xff, sizeof(M.last_seq));
	memcpy(mac, VIF()->addr, ETH_ALEN);
	mutex_unlock(&op_lock);
	return 0;
err:
	kfree(M.sta);
	M.sta = NULL;
	lkpi_usb_remove(M.intf);
	M.intf = NULL;
out:
	mutex_unlock(&op_lock);
	return r;
}

/* A wedged chip can keep the link looking up while TX is dead, and as the primary service it then
   blackholes the Mac's traffic. Report it as unplugged: the worker exits (the service goes
   inactive, macOS falls back to the next one) and a fresh worker rebinds the dongle. */
static void wedged(const char *why)
{
	pr_err("mlme: %s, rebinding the dongle\n", why);
	__atomic_store_n(&M.intf->udev->gone, true, __ATOMIC_RELAXED);
}

/* polled every 0.5 s by drv_rtw89 */
bool rtwd_gone(void)
{
	/* A full scan takes ~5 s, so a scan-done this late is lost: unplugging another dongle on the same hub
	   mid-scan does that. Abort the scan and keep the link; a second lost one in a row means a wedged firmware.
	   trylock: a stuck op must not stall this unplug poll. */
	if (M.intf && __atomic_load_n(&M.scanning, __ATOMIC_ACQUIRE) &&
	    lkpi_now_ns() - __atomic_load_n(&M.scan_since, __ATOMIC_RELAXED) > 10 * NSEC_PER_SEC) {
		if (M.scan_lost) {
			wedged("scan stuck twice");
		} else if (mutex_trylock(&op_lock)) {
			if (M.l) {
				wiphy_lock(WIPHY());
				if (M.scanning) {
					pr_err("mlme: scan stuck for 10 s, aborting it\n");
					M.scan_lost = true;
					OPS()->cancel_hw_scan(HW(), VIF());
				}
				wiphy_unlock(WIPHY());
			}
			mutex_unlock(&op_lock);
		}
	}
	return M.intf && !lkpi_usb_present(M.intf);
}

/* shortcut: constant while RTL8852BU is the only rtw89 chip built in */
const char *rtwd_chip(void)
{
	return "RTL8852BU";
}

void ieee80211_scan_completed(struct ieee80211_hw *hw, struct cfg80211_scan_info *info)
{
	M.scanning = false;
	if (!info || !info->aborted)
		M.scan_lost = false;
	if (M.cb && M.cb->scan_done)
		M.cb->scan_done(info && info->aborted);
}

int rtwd_scan(const uint8_t *ssid, uint8_t ssid_len, const uint16_t *freqs, int n)
{
	static struct cfg80211_ssid ss;
	struct ieee80211_scan_request *sr;
	int nch = 0, r;

	if (ssid_len > IEEE80211_MAX_SSID_LEN)
		return -EINVAL;
	mutex_lock(&op_lock);
	r = -ENODEV;
	if (!M.l)
		goto out;
	wiphy_lock(WIPHY());
	r = -EBUSY;
	if (M.scanning)
		goto unlock;
	kfree(M.sreq);
	M.sreq = NULL;
	r = -ENOMEM;
	sr = kzalloc(sizeof(*sr) + 64 * sizeof(sr->req.channels[0]), GFP_KERNEL);
	if (!sr)
		goto unlock;
	for (int b = 0; b < NUM_NL80211_BANDS; b++) {
		struct ieee80211_supported_band *sb = M.l->wiphy.bands[b];

		if (!sb)
			continue;
		for (int i = 0; i < sb->n_channels && nch < 64; i++) {
			struct ieee80211_channel *c = &sb->channels[i];
			bool want = !n;

			for (int j = 0; j < n; j++)
				want |= freqs[j] == c->center_freq;
			if (want && !(c->flags & IEEE80211_CHAN_DISABLED))
				sr->req.channels[nch++] = c;
		}
		sr->ies.ies[b] = M.scan_ies[b];
		sr->ies.len[b] = put_rates(M.scan_ies[b], sb) - M.scan_ies[b];
		sr->req.rates[b] = (u32)BIT(sb->n_bitrates) - 1;
		sr->req.ie_len += sr->ies.len[b]; /* like mac80211: drivers size probe requests from it */
	}
	sr->req.ie = M.scan_ies[0];
	sr->ies.common_ies = M.scan_ies[0];
	sr->ies.common_ie_len = 0;
	memcpy(ss.ssid, ssid, ssid_len);
	ss.ssid_len = ssid_len;
	sr->req.ssids = &ss;
	sr->req.n_ssids = 1;
	sr->req.n_channels = nch;
	sr->req.wiphy = WIPHY();
	memcpy(sr->req.mac_addr, VIF()->addr, ETH_ALEN);
	mutex_lock(&rx_lock);
	M.nbss = 0;
	mutex_unlock(&rx_lock);
	M.sreq = sr;
	__atomic_store_n(&M.scan_since, lkpi_now_ns(), __ATOMIC_RELAXED);
	__atomic_store_n(&M.scanning, true, __ATOMIC_RELEASE); /* after scan_since: rtwd_gone() reads both */
	r = OPS()->hw_scan(HW(), VIF(), sr);
	if (r) {
		/* errno tells H2C ack timeout (-EAGAIN) from fw reject (-EFAULT) or no offload slot (-ENOSPC) */
		pr_err("mlme: hw_scan failed %d after %lld ms (assoc %d)\n", r,
		       (long long)((lkpi_now_ns() - M.scan_since) / 1000000), !!VIF()->cfg.assoc);
		M.scanning = false;
		if (r == 1)
			r = -EOPNOTSUPP;
		else if (++M.scan_fails >= 3) /* "Update probe request failed": the H2C pipe is dead */
			wedged("3 scan starts failed");
	} else {
		M.scan_fails = 0;
	}
unlock:
	wiphy_unlock(WIPHY());
out:
	mutex_unlock(&op_lock);
	return r;
}

/* wait for the response the rx path hands over; op held, wiphy not held */
static int join_xchg(const u8 *f, size_t len, u16 want)
{
	int fail = 0;

	for (int tries = 0; tries < 3; tries++) {
		mutex_lock(&rx_lock);
		reinit_completion(&M.jc);
		M.jfail = 0;
		M.jwant = want;
		mutex_unlock(&rx_lock);
		mgmt_tx(f, len);
		if (wait_for_completion_timeout(&M.jc, msecs_to_jiffies(400))) {
			if (!M.jfail)
				return 0;
			/* an AP still holding our old association deauths it first; the retry then goes through */
			fail = M.jfail;
			pr_info("mlme: deauth/disassoc reason %d while joining, retrying\n", fail);
		}
	}
	mutex_lock(&rx_lock);
	M.jwant = 0;
	mutex_unlock(&rx_lock);
	return fail ? -ECONNRESET : -ETIMEDOUT;
}

static int rate_nss(u16 map)
{
	int n = 0;

	for (int i = 0; i < 8; i++)
		n += ((map >> (2 * i)) & 3) != 3;
	return n;
}

static void conf_wmm(const u8 *wmm)
{
	static const u8 aci_to_ac[4] = { 2, 3, 1, 0 }; /* BE BK VI VO -> mac80211 ac */

	if (!wmm || wmm[1] < 24)
		return;
	for (int i = 0; i < 4; i++) {
		const u8 *a = wmm + 2 + 8 + 4 * i;
		struct ieee80211_tx_queue_params p = {
			.aifs = a[0] & 0xf,
			.acm = !!(a[0] & 0x10), /* shortcut: ACM is passed on but admission control is never requested */
			.cw_min = (1 << (a[1] & 0xf)) - 1,
			.cw_max = (1 << (a[1] >> 4)) - 1,
			.txop = get_unaligned_le16(a + 2),
		};

		OPS()->conf_tx(HW(), VIF(), 0, aci_to_ac[(a[0] >> 5) & 3], &p);
	}
}

int rtwd_connect(const uint8_t bssid[6], uint16_t freq, const uint8_t *ssid, uint8_t ssid_len, const uint8_t *rsn_ie,
		 size_t rsn_len)
{
	static u8 bf[sizeof(((struct bss *)0)->f)], f[600];
	struct ieee80211_mgmt *bm = (void *)bf, *m = (void *)f;
	struct ieee80211_channel *ch;
	struct ieee80211_supported_band *sb;
	struct ieee80211_link_sta *ls;
	struct cfg80211_chan_def cd;
	const u8 *ies, *htc, *hto, *vhtc, *vhto, *tim, *wmm;
	size_t ilen, blen = 0;
	u32 supp, basic;
	u16 capab;
	u8 *p;
	int r;

	if (ssid_len > IEEE80211_MAX_SSID_LEN || rsn_len > 255 || (rsn_len && rsn_len < 2))
		return -EINVAL;
	mutex_lock(&op_lock);
	r = -ENODEV;
	if (!M.l)
		goto out;
	r = -EBUSY;
	if (M.scanning)
		goto out;
	wiphy_lock(WIPHY());
	if (M.ctx)
		teardown(WLAN_REASON_DEAUTH_LEAVING, true);
	/* torn down: rtw89 holds none of the retired keys now */
	for (struct mkey *k = M.retired, *n; k; k = n) {
		n = k->next;
		kfree(k);
	}
	M.retired = NULL;
	wiphy_unlock(WIPHY());
	M.token++;
	mutex_lock(&rx_lock);
	for (int i = 0; i < M.nbss; i++)
		if (ether_addr_equal(M.bss[i].bssid, bssid) && M.bss[i].freq == freq) {
			blen = M.bss[i].len;
			memcpy(bf, M.bss[i].f, blen);
		}
	mutex_unlock(&rx_lock);
	r = -ENOENT; /* connect needs a fresh scan result for the capabilities */
	ch = find_chan(freq);
	if (!blen || !ch || (ch->flags & IEEE80211_CHAN_DISABLED))
		goto out;
	M.band = ch->band;
	sb = M.l->wiphy.bands[M.band];
	ies = bm->u.beacon.variable;
	ilen = blen - offsetof(struct ieee80211_mgmt, u.beacon.variable);
	htc = ie_find(ies, ilen, WLAN_EID_HT_CAPABILITY);
	hto = ie_find(ies, ilen, WLAN_EID_HT_OPERATION);
	vhtc = ie_find(ies, ilen, WLAN_EID_VHT_CAPABILITY);
	vhto = ie_find(ies, ilen, WLAN_EID_VHT_OPERATION);
	tim = ie_find(ies, ilen, WLAN_EID_TIM);
	wmm = wmm_find(ies, ilen, 1);
	if (htc && htc[1] < sizeof(struct ieee80211_ht_cap))
		htc = NULL;
	if (hto && hto[1] < sizeof(struct ieee80211_ht_operation))
		hto = NULL;
	if (vhtc && vhtc[1] < sizeof(struct ieee80211_vht_cap))
		vhtc = NULL;
	if (vhto && vhto[1] < 3)
		vhto = NULL;
	M.wme = wmm || wmm_find(ies, ilen, 0);
	if (!M.wme || !sb->ht_cap.ht_supported)
		htc = hto = NULL; /* HT needs QoS */
	if (!htc || M.band != NL80211_BAND_5GHZ || !sb->vht_cap.vht_supported)
		vhtc = vhto = NULL;
	M.rsn = rsn_len > 0;

	/* channel width: shortcut: 20 MHz on 2.4 GHz, up to 80 MHz on 5 GHz */
	cfg80211_chandef_create(&cd, ch, htc ? NL80211_CHAN_HT20 : NL80211_CHAN_NO_HT);
	if (hto && M.band == NL80211_BAND_5GHZ && (hto[3] & IEEE80211_HT_PARAM_CHAN_WIDTH_ANY) &&
	    (sb->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40) &&
	    (get_unaligned_le16(htc + 2) & IEEE80211_HT_CAP_SUP_WIDTH_20_40)) {
		int off = hto[3] & 3, sec = off == 1 ? freq + 20 : off == 3 ? freq - 20 : 0;

		if (sec && chan_ok(sec)) {
			cfg80211_chandef_create(&cd, ch, off == 1 ? NL80211_CHAN_HT40PLUS : NL80211_CHAN_HT40MINUS);
			if (vhto && vhto[2] >= 1) {
				int c = ieee80211_channel_to_frequency(vhto[3], M.band);

				if (chan_ok(c - 30) && chan_ok(c - 10) && chan_ok(c + 10) && chan_ok(c + 30) &&
				    freq >= c - 30 && freq <= c + 30) {
					cd.width = NL80211_CHAN_WIDTH_80;
					cd.center_freq1 = c;
				}
			}
		}
	}

	mutex_lock(&rx_lock);
	memcpy(M.bssid, bssid, ETH_ALEN);
	mutex_unlock(&rx_lock);
	wiphy_lock(WIPHY());
	r = -ENOMEM;
	M.ctx = kzalloc(sizeof(*M.ctx) + HW()->chanctx_data_size, GFP_KERNEL);
	if (!M.ctx)
		goto fail_locked;
	M.ctx->def = cd;
	r = OPS()->add_chanctx(HW(), M.ctx);
	if (r) {
		kfree(M.ctx);
		M.ctx = NULL;
		goto fail_locked;
	}
	VIF()->bss_conf.chanreq.oper = cd;
	r = OPS()->assign_vif_chanctx(HW(), VIF(), &VIF()->bss_conf, M.ctx);
	if (r) {
		OPS()->remove_chanctx(HW(), M.ctx);
		kfree(M.ctx);
		M.ctx = NULL;
		goto fail_locked;
	}
	rate_masks(ies, ilen, sb, &supp, &basic);
	capab = le16_to_cpu(bm->u.beacon.capab_info);
	VIF()->bss_conf.bssid = M.bssid;
	VIF()->bss_conf.beacon_int = le16_to_cpu(bm->u.beacon.beacon_int);
	VIF()->bss_conf.basic_rates = basic;
	VIF()->bss_conf.use_short_slot = M.band == NL80211_BAND_5GHZ || (capab & WLAN_CAPABILITY_SHORT_SLOT_TIME);
	VIF()->bss_conf.qos = M.wme;
	VIF()->bss_conf.dtim_period = tim && tim[1] >= 2 && tim[3] ? tim[3] : 1;
	OPS()->link_info_changed(HW(), VIF(), &VIF()->bss_conf,
				 BSS_CHANGED_BSSID | BSS_CHANGED_BASIC_RATES | BSS_CHANGED_BEACON_INT |
					 BSS_CHANGED_ERP_SLOT | BSS_CHANGED_QOS | BSS_CHANGED_HT | BSS_CHANGED_BANDWIDTH);

	/* the AP as seen by the driver: what it can receive, capped by what we can send */
	memset(M.sta, 0, sizeof(*M.sta) + HW()->sta_data_size);
	M.sta->lv = M.l->lv;
	M.sta->state = IEEE80211_STA_NOTEXIST;
	memcpy(STA()->addr, bssid, ETH_ALEN);
	STA()->wme = M.wme;
	STA()->max_rx_aggregation_subframes = 64;
	STA()->max_amsdu_subframes = 0;
	ls = &STA()->deflink;
	ls->sta = STA();
	memcpy(ls->addr, bssid, ETH_ALEN);
	STA()->link[0] = ls;
	ls->supp_rates[M.band] = supp;
	ls->rx_nss = 1;
	ls->agg.max_amsdu_len = ls->agg.max_rc_amsdu_len = 3839;
	if (htc) {
		const struct ieee80211_ht_cap *h = (const void *)(htc + 2);
		u16 cap = le16_to_cpu(h->cap_info);
		int nss = 0;

		ls->ht_cap.ht_supported = true;
		ls->ht_cap.cap = cap & (sb->ht_cap.cap | IEEE80211_HT_CAP_MAX_AMSDU);
		ls->ht_cap.ampdu_factor = h->ampdu_params_info & 3;
		ls->ht_cap.ampdu_density = (h->ampdu_params_info >> 2) & 7;
		ls->ht_cap.mcs = h->mcs;
		for (int i = 0; i < IEEE80211_HT_MCS_MASK_LEN; i++)
			ls->ht_cap.mcs.rx_mask[i] &= sb->ht_cap.mcs.rx_mask[i];
		for (int i = 0; i < 4; i++)
			nss += !!ls->ht_cap.mcs.rx_mask[i];
		ls->rx_nss = nss ? nss : 1;
		if (cap & IEEE80211_HT_CAP_MAX_AMSDU)
			ls->agg.max_amsdu_len = ls->agg.max_rc_amsdu_len = 7935;
	}
	if (vhtc) {
		const struct ieee80211_vht_cap *v = (const void *)(vhtc + 2);
		u16 ap = le16_to_cpu(v->supp_mcs.rx_mcs_map), us = le16_to_cpu(sb->vht_cap.vht_mcs.tx_mcs_map), map = 0;
		u32 vcap = le32_to_cpu(v->vht_cap_info);
		static const u16 mpdu[3] = { 3895, 7991, 11454 };

		for (int i = 0; i < 8; i++) {
			u16 a = (ap >> (2 * i)) & 3, b = (us >> (2 * i)) & 3;

			map |= (a == 3 || b == 3 ? 3 : a < b ? a : b) << (2 * i);
		}
		ls->vht_cap.vht_supported = true;
		ls->vht_cap.cap = vcap & (sb->vht_cap.cap | IEEE80211_VHT_CAP_MAX_MPDU_MASK);
		ls->vht_cap.vht_mcs = v->supp_mcs;
		ls->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(map);
		if (rate_nss(map))
			ls->rx_nss = rate_nss(map);
		ls->agg.max_amsdu_len = ls->agg.max_rc_amsdu_len = mpdu[(vcap & 3) < 3 ? vcap & 3 : 0];
	}
	ls->bandwidth = cd.width == NL80211_CHAN_WIDTH_80 ? IEEE80211_STA_RX_BW_80 :
			cd.width == NL80211_CHAN_WIDTH_40 ? IEEE80211_STA_RX_BW_40 : IEEE80211_STA_RX_BW_20;
	r = -ENOMEM;
	for (int tid = 0; tid < IEEE80211_NUM_TIDS; tid++) {
		struct lkpi_txq *t = txq_alloc(M.l, VIF(), STA(), tid);

		if (!t)
			goto fail_locked;
		STA()->txq[tid] = &t->txq;
	}
	M.l->ap = M.sta;
	r = sta_move(IEEE80211_STA_NONE);
	wiphy_unlock(WIPHY());
	if (r)
		goto fail;

	/* open system authentication */
	mgmt_hdr(m, IEEE80211_STYPE_AUTH);
	m->u.auth.auth_alg = cpu_to_le16(WLAN_AUTH_OPEN);
	m->u.auth.auth_transaction = cpu_to_le16(1);
	m->u.auth.status_code = 0;
	r = join_xchg(f, offsetof(struct ieee80211_mgmt, u.auth.variable), IEEE80211_STYPE_AUTH);
	if (!r && (M.jlen < 30 || le16_to_cpu(((struct ieee80211_mgmt *)M.jbuf)->u.auth.status_code)))
		r = -EACCES;
	if (r)
		goto fail;
	wiphy_lock(WIPHY());
	r = sta_move(IEEE80211_STA_AUTH);
	wiphy_unlock(WIPHY());
	if (r)
		goto fail;

	/* association request */
	mgmt_hdr(m, IEEE80211_STYPE_ASSOC_REQ);
	capab = WLAN_CAPABILITY_ESS;
	if (M.band == NL80211_BAND_2GHZ)
		capab |= WLAN_CAPABILITY_SHORT_SLOT_TIME | WLAN_CAPABILITY_SHORT_PREAMBLE;
	m->u.assoc_req.capab_info = cpu_to_le16(capab);
	m->u.assoc_req.listen_interval = cpu_to_le16(10);
	p = m->u.assoc_req.variable;
	*p++ = WLAN_EID_SSID;
	*p++ = ssid_len;
	memcpy(p, ssid, ssid_len);
	p = put_rates(p + ssid_len, sb);
	if (rsn_len) {
		memcpy(p, rsn_ie, rsn_len);
		p += rsn_len;
	}
	if (htc) {
		struct ieee80211_ht_cap h = {
			.cap_info = cpu_to_le16(sb->ht_cap.cap),
			.ampdu_params_info = sb->ht_cap.ampdu_factor | sb->ht_cap.ampdu_density << 2,
			.mcs = sb->ht_cap.mcs,
		};

		/* SM PS 0 is "static": the AP then sends 1SS only. mac80211 sets "disabled" (3) here, as we do */
		h.cap_info |= cpu_to_le16(IEEE80211_HT_CAP_SM_PS);

		if (cd.width == NL80211_CHAN_WIDTH_20 || cd.width == NL80211_CHAN_WIDTH_20_NOHT)
			h.cap_info &= cpu_to_le16(~(IEEE80211_HT_CAP_SUP_WIDTH_20_40 | IEEE80211_HT_CAP_SGI_40));
		*p++ = WLAN_EID_HT_CAPABILITY;
		*p++ = sizeof(h);
		memcpy(p, &h, sizeof(h));
		p += sizeof(h);
	}
	if (vhtc) {
		struct ieee80211_vht_cap v = { .vht_cap_info = cpu_to_le32(sb->vht_cap.cap), .supp_mcs = sb->vht_cap.vht_mcs };

		*p++ = WLAN_EID_VHT_CAPABILITY;
		*p++ = sizeof(v);
		memcpy(p, &v, sizeof(v));
		p += sizeof(v);
	}
	if (M.wme) {
		static const u8 wmm_info[] = { WLAN_EID_VENDOR_SPECIFIC, 7, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00 };

		memcpy(p, wmm_info, sizeof(wmm_info));
		p += sizeof(wmm_info);
	}
	r = join_xchg(f, p - f, IEEE80211_STYPE_ASSOC_RESP);
	if (r)
		goto fail;
	m = (void *)M.jbuf;
	if (M.jlen < 30 || m->u.assoc_resp.status_code) {
		pr_err("mlme: association refused, status %u\n", M.jlen < 30 ? 0xffff : le16_to_cpu(m->u.assoc_resp.status_code));
		r = -ECONNREFUSED;
		goto fail;
	}
	wiphy_lock(WIPHY());
	STA()->aid = le16_to_cpu(m->u.assoc_resp.aid) & 0x3fff;
	r = sta_move(IEEE80211_STA_ASSOC);
	if (r)
		goto fail_locked;
	if (M.wme) {
		const u8 *w = wmm_find(m->u.assoc_resp.variable, M.jlen - offsetof(struct ieee80211_mgmt, u.assoc_resp.variable), 1);

		conf_wmm(w ? w : wmm);
	}
	VIF()->cfg.assoc = true;
	VIF()->cfg.aid = STA()->aid;
	memcpy(VIF()->cfg.ssid, ssid, ssid_len);
	VIF()->cfg.ssid_len = ssid_len;
	memcpy(VIF()->cfg.ap_addr, bssid, ETH_ALEN);
	mutex_lock(&rx_lock);
	mutex_lock(&tx_lock);
	M.assoc = true;
	memset(M.seq, 0, sizeof(M.seq));
	mutex_unlock(&tx_lock);
	mutex_unlock(&rx_lock);
	VIF()->cfg.ps = M.ps;
	OPS()->vif_cfg_changed(HW(), VIF(), BSS_CHANGED_ASSOC | BSS_CHANGED_PS);
	if (!M.rsn) {
		r = sta_move(IEEE80211_STA_AUTHORIZED);
		if (r)
			goto fail_locked;
		M.authorized = true;
	}
	wiphy_unlock(WIPHY());
	pr_info("mlme: associated aid %u, %u MHz width %d, ht %d vht %d nss %d\n", STA()->aid, freq, cd.width,
		!!htc, !!vhtc, ls->rx_nss);
	mutex_unlock(&op_lock);
	return 0;

fail:
	wiphy_lock(WIPHY());
fail_locked:
	teardown(WLAN_REASON_DEAUTH_LEAVING, true);
	wiphy_unlock(WIPHY());
out:
	mutex_unlock(&op_lock);
	return r;
}

void rtwd_disconnect(uint16_t reason)
{
	mutex_lock(&op_lock);
	if (M.l) {
		wiphy_lock(WIPHY());
		teardown(reason, true);
		wiphy_unlock(WIPHY());
	}
	mutex_unlock(&op_lock);
}

int rtwd_power_save(bool on)
{
	mutex_lock(&op_lock);
	M.ps = on;
	if (M.l && M.assoc) {
		wiphy_lock(WIPHY());
		VIF()->cfg.ps = on;
		OPS()->vif_cfg_changed(HW(), VIF(), BSS_CHANGED_PS);
		wiphy_unlock(WIPHY());
	}
	mutex_unlock(&op_lock);
	return 0;
}

int rtwd_set_authorized(bool on)
{
	int r = -ENOTCONN;

	mutex_lock(&op_lock);
	if (M.l && M.assoc) {
		wiphy_lock(WIPHY());
		r = sta_move(on ? IEEE80211_STA_AUTHORIZED : IEEE80211_STA_ASSOC);
		mutex_lock(&rx_lock);
		M.authorized = on && !r;
		mutex_unlock(&rx_lock);
		wiphy_unlock(WIPHY());
	}
	mutex_unlock(&op_lock);
	return r;
}

/* shortcut: CCMP-128 only (no TKIP/WEP/GCMP); BIP arrives with WPA3 */
int rtwd_add_key(bool pairwise, uint8_t idx, uint32_t cipher_suite, const uint8_t *key, uint8_t len)
{
	struct mkey *k, *old;
	int r;

	if (cipher_suite != WLAN_CIPHER_SUITE_CCMP || len != 16 || (!pairwise && (idx < 1 || idx > 3)) ||
	    (pairwise && idx))
		return -EOPNOTSUPP;
	k = kzalloc(sizeof(*k) + len, GFP_KERNEL);
	if (!k)
		return -ENOMEM;
	k->k.cipher = cipher_suite;
	k->k.keyidx = idx;
	k->k.keylen = len;
	k->k.link_id = -1;
	k->k.iv_len = 8;
	k->k.icv_len = 8;
	k->k.flags = pairwise ? IEEE80211_KEY_FLAG_PAIRWISE : 0;
	memcpy(k->k.key, key, len);
	atomic64_set(&k->k.tx_pn, 0);

	mutex_lock(&op_lock);
	r = -ENOTCONN;
	if (!M.l || !M.assoc)
		goto out;
	old = pairwise ? M.ptk : M.gtk[idx];
	if (old && pairwise) {
		/* rekey: stop data, let old-key frames out, then swap like mac80211 (old off, new on) */
		mutex_lock(&tx_lock);
		M.txblock = true;
		mutex_unlock(&tx_lock);
		txqs_drain();
	}
	wiphy_lock(WIPHY());
	if (old) {
		OPS()->flush(HW(), VIF(), ~0u, false);
		OPS()->set_key(HW(), DISABLE_KEY, VIF(), pairwise ? STA() : NULL, &old->k);
	}
	r = OPS()->set_key(HW(), SET_KEY, VIF(), pairwise ? STA() : NULL, &k->k);
	mutex_lock(&rx_lock);
	mutex_lock(&tx_lock);
	if (pairwise) {
		M.ptk = r ? NULL : k;
		memset(M.rx_pn, 0, sizeof(M.rx_pn));
		M.txblock = r && old; /* a failed rekey must not fall back to plaintext */
	} else {
		M.gtk[idx] = r ? NULL : k;
		M.gtk_pn[idx] = 0; /* shortcut: GTK RSC from msg3 is not honoured, upgrade to close the replay window */
	}
	mutex_unlock(&tx_lock);
	mutex_unlock(&rx_lock);
	wiphy_unlock(WIPHY());
	key_retire(old); /* rtw89 may still point at it: freed at the next connect, after teardown */
	if (r)
		goto out;
	k = NULL;
out:
	mutex_unlock(&op_lock);
	kfree(k);
	return r;
}

static u8 classify(const u8 *eth, size_t len, u16 proto)
{
	if (proto == ETH_P_PAE)
		return 7;
	if (proto == ETH_P_IP && len >= 16)
		return eth[15] >> 5;
	if (proto == ETH_P_IPV6 && len >= 16)
		return (eth[14] & 0x0f) >> 1;
	return 0;
}

/* Backlog: append the packet to the queued tail as an A-MSDU subframe. rtw89 sends one MPDU per URB and the
 * dongle tops out near 6500 URBs/s, so packing several packets per MPDU is what lifts throughput. The tail
 * keeps its seq and PN, so nothing goes missing in the AP's reorder window. */
#define AMSDU_MAX 5000 /* rtw8852b max_amsdu_limit */
static bool amsdu_append(struct lkpi_txq *t, const u8 *eth, size_t len)
{
	const struct ieee80211_sta_aggregates *a = &STA()->deflink.agg;
	/* rtw89's rate-based cap; a flat 5000 measured worse on air (fewer MPDUs per A-MPDU, lower MCS) */
	unsigned int cap = min(a->max_amsdu_len, a->max_rc_amsdu_len), hl = sizeof(struct ieee80211_qos_hdr) + (M.ptk ? 8 : 0);
	unsigned int conv, pad, sub = ETH_HLEN + 6 + len - 12;
	struct ieee80211_qos_hdr *h;
	struct sk_buff *tail;
	bool ok = false;
	u8 *p;

	spin_lock(&t->q.lock);
	tail = skb_peek_tail(&t->q);
	if (!tail || tail->protocol == cpu_to_be16(ETH_P_PAE))
		goto out;
	h = (void *)tail->data;
	conv = (h->qos_ctrl & cpu_to_le16(IEEE80211_QOS_CTL_A_MSDU_PRESENT)) ? 0 : ETH_HLEN;
	pad = -(tail->len - hl + conv) & 3;
	if (tail->len + conv + pad + sub > cap || skb_tailroom(tail) < (int)(pad + sub) ||
	    skb_headroom(tail) < HW()->extra_tx_headroom + conv)
		goto out;
	if (conv) { /* first packet becomes subframe 1: DA moves from addr3 into it, addr3 becomes the BSSID */
		unsigned int mlen = tail->len - hl;

		skb_push(tail, ETH_HLEN);
		h = memmove(tail->data, tail->data + ETH_HLEN, hl);
		p = tail->data + hl;
		memcpy(p, h->addr3, ETH_ALEN);
		memcpy(p + 6, VIF()->addr, ETH_ALEN);
		p[12] = mlen >> 8;
		p[13] = mlen;
		memcpy(h->addr3, M.bssid, ETH_ALEN);
		h->qos_ctrl |= cpu_to_le16(IEEE80211_QOS_CTL_A_MSDU_PRESENT);
	}
	p = skb_put_zero(tail, pad + sub) + pad;
	memcpy(p, eth, ETH_ALEN);
	memcpy(p + 6, VIF()->addr, ETH_ALEN);
	p[12] = (sub - ETH_HLEN) >> 8;
	p[13] = sub - ETH_HLEN;
	memcpy(p + ETH_HLEN, rfc1042, 6);
	memcpy(p + ETH_HLEN + 6, eth + 12, len - 12);
	t->bytes += conv + pad + sub;
	ok = true;
out:
	spin_unlock(&t->q.lock);
	return ok;
}

int rtwd_tx_eth(const uint8_t *eth, size_t len)
{
	u16 proto;
	u8 tid;
	struct lkpi_txq *t;
	struct sk_buff *skb;
	struct ieee80211_tx_info *info;
	struct ieee80211_qos_hdr *h;
	unsigned int hl;
	int r = 0;

	if (len < ETH_HLEN || len > ETH_HLEN + 2304 - 8)
		return -EINVAL;
	proto = get_unaligned_be16(eth + 12);
	if (proto < 0x600)
		return -EINVAL; /* shortcut: 802.3 length frames (no EtherType) are not sent */
	mutex_lock(&tx_lock);
	if (!M.assoc) {
		r = -ENOTCONN;
		goto out;
	}
	if (M.txblock || (!M.authorized && proto != ETH_P_PAE)) {
		r = -EAGAIN;
		goto out;
	}
	tid = M.wme ? classify(eth, len, proto) : 0;
	t = to_lt(STA()->txq[tid]);
	if (t->q.qlen > 1024) {
		r = -ENOBUFS;
		goto out;
	}
	if (M.wme && proto != ETH_P_PAE && (M.ba_tx & M.ba_amsdu & BIT(tid)) && amsdu_append(t, eth, len)) {
		r = 0;
		goto out; /* the tail is already scheduled */
	}
	hl = M.wme ? sizeof(struct ieee80211_qos_hdr) : 24;
	/* room for amsdu_append: ETH_HLEN of headroom, tailroom up to AMSDU_MAX */
	skb = dev_alloc_skb(HW()->extra_tx_headroom + ETH_HLEN + max_t(size_t, hl + 8 + 8 + len - ETH_HLEN, AMSDU_MAX));
	r = -ENOMEM;
	if (!skb)
		goto out;
	skb_reserve(skb, HW()->extra_tx_headroom + ETH_HLEN);
	h = skb_put_zero(skb, hl);
	h->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_FCTL_TODS |
				       (M.wme ? IEEE80211_STYPE_QOS_DATA : IEEE80211_STYPE_DATA) |
				       (M.ptk ? IEEE80211_FCTL_PROTECTED : 0));
	memcpy(h->addr1, M.bssid, ETH_ALEN);
	memcpy(h->addr2, VIF()->addr, ETH_ALEN);
	memcpy(h->addr3, eth, ETH_ALEN);
	h->seq_ctrl = cpu_to_le16((M.seq[M.wme ? tid : NTID]++ & 0xfff) << 4);
	if (M.wme)
		h->qos_ctrl = cpu_to_le16(tid);
	if (M.ptk) {
		u64 pn = atomic64_inc_return(&M.ptk->k.tx_pn);
		u8 *iv = skb_put(skb, 8);

		iv[0] = pn;
		iv[1] = pn >> 8;
		iv[2] = 0;
		iv[3] = 0x20 | M.ptk->k.keyidx << 6;
		iv[4] = pn >> 16;
		iv[5] = pn >> 24;
		iv[6] = pn >> 32;
		iv[7] = pn >> 40;
	}
	skb_put_data(skb, rfc1042, 6);
	skb_put_data(skb, eth + 12, len - 12);
	info = IEEE80211_SKB_CB(skb);
	memset(info, 0, sizeof(*info));
	info->band = M.band;
	info->control.vif = VIF();
	info->control.hw_key = M.ptk ? &M.ptk->k : NULL;
	if (proto == ETH_P_PAE)
		info->control.flags |= IEEE80211_TX_CTRL_PORT_CTRL_PROTO;
	skb->priority = tid;
	skb->protocol = cpu_to_be16(proto);
	spin_lock(&t->q.lock);
	__skb_queue_tail(&t->q, skb);
	t->bytes += skb->len;
	spin_unlock(&t->q.lock);
	/* still under tx_lock: teardown cannot free the txq underneath us */
	ieee80211_schedule_txq(HW(), &t->txq);
	wake_all_txqs(M.l);
	r = 0;
out:
	mutex_unlock(&tx_lock);
	return r;
}
