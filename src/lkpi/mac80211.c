// SPDX-License-Identifier: BSD-3-Clause
/*
 * Mini cfg80211/mac80211 for one rtw89 station interface in user space.
 * Linux semantics are kept where the driver depends on them: ops run under
 * the wiphy mutex, wiphy work is ordered and runs under that mutex, data
 * frames reach the driver through per-TID txqs (so it can batch USB writes
 * and start A-MPDU sessions), management frames through ops->tx.
 */
#include "local.h"
#include <ctype.h>

static const u8 tid_to_ac[8] = { /* 802.1D priority -> access category */
	IEEE80211_AC_BE, IEEE80211_AC_BK, IEEE80211_AC_BK, IEEE80211_AC_BE,
	IEEE80211_AC_VI, IEEE80211_AC_VI, IEEE80211_AC_VO, IEEE80211_AC_VO,
};

const unsigned char rfc1042_header[6] = { 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

/* ---------- wiphy work: ordered, runs with wiphy->mtx held ---------- */
static void wiphy_work_tramp(struct work_struct *w)
{
	struct wiphy_work *ww = container_of(w, struct wiphy_work, lkpi);

	ww->func(ww->wiphy, ww);
}

void wiphy_work_init(struct wiphy_work *work, wiphy_work_func_t func)
{
	INIT_WORK(&work->lkpi, wiphy_work_tramp);
	work->func = func;
	work->wiphy = NULL;
}

void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work)
{
	work->wiphy = wiphy;
	queue_work(wiphy->lkpi_wq, &work->lkpi);
}

/* caller holds the wiphy mutex, so the work cannot be running */
void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work)
{
	cancel_work(&work->lkpi);
}

static void wiphy_delayed_work_timer(struct lkpi_timer *t)
{
	struct wiphy_delayed_work *dw = container_of(t, struct wiphy_delayed_work, timer);

	wiphy_work_queue(dw->wiphy, &dw->work);
}

void wiphy_delayed_work_init(struct wiphy_delayed_work *dwork, wiphy_work_func_t func)
{
	wiphy_work_init(&dwork->work, func);
	memset(&dwork->timer, 0, sizeof(dwork->timer));
	dwork->timer.fn = wiphy_delayed_work_timer;
}

void wiphy_delayed_work_queue(struct wiphy *wiphy, struct wiphy_delayed_work *dwork, unsigned long delay)
{
	dwork->wiphy = wiphy;
	if (!delay) {
		lkpi_timer_del(&dwork->timer);
		wiphy_work_queue(wiphy, &dwork->work);
		return;
	}
	lkpi_timer_add(&dwork->timer, (u64)jiffies_to_msecs(delay) * NSEC_PER_MSEC);
}

void wiphy_delayed_work_cancel(struct wiphy *wiphy, struct wiphy_delayed_work *dwork)
{
	lkpi_timer_del(&dwork->timer); /* the timer only queues, it never takes the mutex */
	wiphy_work_cancel(wiphy, &dwork->work);
}

/* run it now, in the caller (which holds the wiphy mutex), if it was pending */
void wiphy_delayed_work_flush(struct wiphy *wiphy, struct wiphy_delayed_work *dwork)
{
	bool armed = lkpi_timer_del(&dwork->timer);

	if (cancel_work(&dwork->work.lkpi) || armed)
		dwork->work.func(wiphy, &dwork->work);
}

void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *work)
{
	if (cancel_work(&work->lkpi))
		work->func(wiphy, work);
}

bool wiphy_delayed_work_pending(struct wiphy *wiphy, struct wiphy_delayed_work *dwork)
{
	return dwork->timer.pending || work_pending(&dwork->work.lkpi);
}

/* ---------- hw lifecycle ---------- */
struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len, const struct ieee80211_ops *ops)
{
	struct lkpi_local *l;

	if (!ops->tx || !ops->start || !ops->stop || !ops->add_interface || !ops->remove_interface ||
	    !ops->configure_filter || !ops->wake_tx_queue)
		return NULL;
	l = kzalloc(sizeof(*l) + priv_data_len, GFP_KERNEL);
	if (!l)
		return NULL;
	l->ops = ops;
	l->hw.wiphy = &l->wiphy;
	l->hw.priv = l->priv;
	l->hw.queues = 1;
	l->hw.conf.flags = IEEE80211_CONF_IDLE;
	mutex_init(&l->wiphy.mtx);
	spin_lock_init(&l->txq_lock);
	for (int ac = 0; ac < IEEE80211_NUM_ACS; ac++) {
		INIT_LIST_HEAD(&l->active[ac]);
		INIT_LIST_HEAD(&l->round[ac]);
	}
	l->wiphy.lkpi_wq = lkpi_alloc_wq_locked("phy0-wiphy", &l->wiphy.mtx);
	l->wq = alloc_ordered_workqueue("phy0", 0);
	if (!l->wiphy.lkpi_wq || !l->wq) {
		if (l->wq)
			destroy_workqueue(l->wq);
		if (l->wiphy.lkpi_wq)
			destroy_workqueue(l->wiphy.lkpi_wq);
		kfree(l);
		return NULL;
	}
	return &l->hw;
}

struct ieee80211_hw *wiphy_to_ieee80211_hw(struct wiphy *wiphy)
{
	return &container_of(wiphy, struct lkpi_local, wiphy)->hw;
}

static void reg_work_fn(struct wiphy *wiphy, struct wiphy_work *w)
{
	struct lkpi_local *l = container_of(w, struct lkpi_local, reg_work);

	if (wiphy->reg_notifier)
		wiphy->reg_notifier(wiphy, &l->reg_req);
}

/* shortcut: no regulatory database here; the driver carries its own power-limit
 * tables keyed by alpha2, so a hint only has to reach its reg_notifier */
int regulatory_hint(struct wiphy *wiphy, const char *alpha2)
{
	struct lkpi_local *l = container_of(wiphy, struct lkpi_local, wiphy);

	if (!alpha2 || !isalpha(alpha2[0]) || !isalpha(alpha2[1]))
		return -EINVAL;
	l->reg_req.alpha2[0] = alpha2[0];
	l->reg_req.alpha2[1] = alpha2[1];
	l->reg_req.initiator = NL80211_REGDOM_SET_BY_DRIVER;
	wiphy_work_queue(wiphy, &l->reg_work);
	return 0;
}

int ieee80211_register_hw(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);

	if (l->registered)
		return -EBUSY;
	wiphy_work_init(&l->reg_work, reg_work_fn);
	/* like wiphy_register(): tell the driver the current (world) domain */
	l->reg_req = (struct regulatory_request){ .alpha2 = "00", .initiator = NL80211_REGDOM_SET_BY_CORE };
	if (l->wiphy.reg_notifier) {
		wiphy_lock(&l->wiphy);
		l->wiphy.reg_notifier(&l->wiphy, &l->reg_req);
		wiphy_unlock(&l->wiphy);
	}
	/* world domain: passive scan where the regdomain may forbid initiating, radar on 5250-5730,
	 * nothing above 5825 (as cfg80211's world regdomain); the driver still applies its own TX-power limits */
	for (int b = 0; b < NUM_NL80211_BANDS; b++) {
		struct ieee80211_supported_band *sb = l->wiphy.bands[b];

		for (int c = 0; sb && c < sb->n_channels; c++) {
			struct ieee80211_channel *ch = &sb->channels[c];
			u32 f = ch->center_freq;

			if ((b == NL80211_BAND_2GHZ && f >= 2467) || b == NL80211_BAND_5GHZ)
				ch->flags |= IEEE80211_CHAN_NO_IR;
			if (f >= 5260 && f <= 5720)
				ch->flags |= IEEE80211_CHAN_RADAR;
			if (f > 5825 || b == NL80211_BAND_6GHZ)
				ch->flags |= IEEE80211_CHAN_DISABLED;
		}
	}
	l->registered = true;
	return 0;
}

void ieee80211_unregister_hw(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);

	lkpi80211_down(hw);
	wiphy_lock(&l->wiphy);
	wiphy_work_cancel(&l->wiphy, &l->reg_work);
	wiphy_unlock(&l->wiphy);
	flush_workqueue(l->wiphy.lkpi_wq);
	flush_workqueue(l->wq);
	l->registered = false;
}

void ieee80211_free_hw(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);

	destroy_workqueue(l->wq);
	destroy_workqueue(l->wiphy.lkpi_wq);
	kfree(l);
}

/* shortcut: no in-place reconfiguration; the backend sees the link drop and
 * reconnects from scratch. Upgrade if firmware recovery (SER L2) is frequent. */
void ieee80211_restart_hw(struct ieee80211_hw *hw)
{
	pr_err("rtw89: hardware restart requested\n");
	if (hw_to_local(hw)->lv)
		ieee80211_connection_loss(&hw_to_local(hw)->lv->vif);
}

void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work)
{
	queue_work(hw_to_local(hw)->wq, work);
}

void ieee80211_queue_delayed_work(struct ieee80211_hw *hw, struct delayed_work *dwork, unsigned long delay)
{
	queue_delayed_work(hw_to_local(hw)->wq, dwork, delay);
}

/* ---------- txqs ---------- */
struct lkpi_txq *txq_alloc(struct lkpi_local *l, struct ieee80211_vif *vif,
			   struct ieee80211_sta *sta, u8 tid)
{
	struct lkpi_txq *t = kzalloc(sizeof(*t) + l->hw.txq_data_size, GFP_KERNEL);

	if (!t)
		return NULL;
	INIT_LIST_HEAD(&t->sched);
	skb_queue_head_init(&t->q);
	t->txq.vif = vif;
	t->txq.sta = sta;
	t->txq.tid = tid;
	t->txq.ac = tid < 8 ? tid_to_ac[tid] : IEEE80211_AC_VO;
	return t;
}

void txq_free(struct lkpi_local *l, struct ieee80211_txq *txq)
{
	struct lkpi_txq *t;

	if (!txq)
		return;
	t = to_lt(txq);
	for (bool busy = true; busy;) {
		spin_lock(&l->txq_lock);
		busy = t->inflight;
		if (!busy)
			list_del_init(&t->sched);
		spin_unlock(&l->txq_lock);
		if (busy)
			lkpi_sleep_us(200);
	}
	skb_queue_purge(&t->q);
	kfree(t);
}

void ieee80211_schedule_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct lkpi_txq *t = to_lt(txq);

	spin_lock(&l->txq_lock);
	if (list_empty(&t->sched))
		list_add_tail(&t->sched, &l->active[txq->ac]);
	spin_unlock(&l->txq_lock);
}

/* a round visits each txq that was scheduled when it started at most once */
void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac)
{
	struct lkpi_local *l = hw_to_local(hw);

	spin_lock(&l->txq_lock);
	list_splice_tail_init(&l->active[ac], &l->round[ac]);
	spin_unlock(&l->txq_lock);
}

void ieee80211_txq_schedule_end(struct ieee80211_hw *hw, u8 ac)
{
	struct lkpi_local *l = hw_to_local(hw);

	spin_lock(&l->txq_lock);
	list_splice_init(&l->round[ac], &l->active[ac]); /* unvisited ones go first next time */
	spin_unlock(&l->txq_lock);
}

struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw, u8 ac)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct lkpi_txq *t = NULL;

	spin_lock(&l->txq_lock);
	if (!l->queues_stopped && !list_empty(&l->round[ac])) {
		t = list_first_entry(&l->round[ac], struct lkpi_txq, sched);
		list_del_init(&t->sched);
		t->inflight = true;
	}
	spin_unlock(&l->txq_lock);
	return t ? &t->txq : NULL;
}

void ieee80211_return_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq, bool force)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct lkpi_txq *t = to_lt(txq);

	spin_lock(&l->txq_lock);
	t->inflight = false;
	if (list_empty(&t->sched) && (force || skb_queue_len(&t->q)))
		list_add_tail(&t->sched, &l->active[txq->ac]);
	spin_unlock(&l->txq_lock);
}

struct sk_buff *ieee80211_tx_dequeue_ni(struct ieee80211_hw *hw, struct ieee80211_txq *txq)
{
	struct lkpi_txq *t = to_lt(txq);
	struct sk_buff *skb;

	spin_lock(&t->q.lock);
	skb = __skb_dequeue(&t->q);
	if (skb)
		t->bytes -= skb->len;
	spin_unlock(&t->q.lock);
	return skb;
}

void ieee80211_txq_get_depth(struct ieee80211_txq *txq, unsigned long *frame_cnt, unsigned long *byte_cnt)
{
	struct lkpi_txq *t = to_lt(txq);

	spin_lock(&t->q.lock);
	if (frame_cnt)
		*frame_cnt = t->q.qlen;
	if (byte_cnt)
		*byte_cnt = t->bytes;
	spin_unlock(&t->q.lock);
}

void wake_all_txqs(struct lkpi_local *l)
{
	struct lkpi_txq *t = NULL;

	spin_lock(&l->txq_lock);
	for (int ac = 0; ac < IEEE80211_NUM_ACS && !t; ac++)
		if (!list_empty(&l->active[ac]))
			t = list_first_entry(&l->active[ac], struct lkpi_txq, sched);
	spin_unlock(&l->txq_lock);
	/* the driver's wake_tx_queue kicks its single tx worker, which walks every AC */
	if (t)
		l->ops->wake_tx_queue(&l->hw, &t->txq);
}

void ieee80211_stop_queues(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);

	spin_lock(&l->txq_lock);
	l->queues_stopped = 1;
	spin_unlock(&l->txq_lock);
}

void ieee80211_wake_queues(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);

	spin_lock(&l->txq_lock);
	l->queues_stopped = 0;
	spin_unlock(&l->txq_lock);
	wake_all_txqs(l);
}

/* ---------- tx status ---------- */
void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb) { kfree_skb(skb); }

void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb) { kfree_skb(skb); }

void ieee80211_purge_tx_queue(struct ieee80211_hw *hw, struct sk_buff_head *skbs)
{
	skb_queue_purge(skbs);
}

/* ---------- iteration ---------- */
void ieee80211_iterate_active_interfaces_atomic(struct ieee80211_hw *hw, u32 iter_flags,
						void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif),
						void *data)
{
	struct lkpi_vif *lv = hw_to_local(hw)->lv;

	if (lv)
		iterator(data, lv->vif.addr, &lv->vif);
}

struct lkpi_sta *uploaded_sta(struct lkpi_local *l)
{
	return l->ap && l->ap->state >= IEEE80211_STA_NONE ? l->ap : NULL;
}

void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
				       void (*iterator)(void *data, struct ieee80211_sta *sta), void *data)
{
	struct lkpi_sta *s = uploaded_sta(hw_to_local(hw));

	if (s)
		iterator(data, &s->sta);
}

struct ieee80211_sta *__ieee80211_iterate_stations(struct ieee80211_hw *hw, struct ieee80211_sta *prev)
{
	struct lkpi_sta *s = uploaded_sta(hw_to_local(hw));

	return s && !prev ? &s->sta : NULL;
}

struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_vif *vif, const u8 *addr)
{
	struct lkpi_sta *s = uploaded_sta(to_lv(vif)->local);

	return s && ether_addr_equal(s->sta.addr, addr) ? &s->sta : NULL;
}

/* shortcut: no BSS table yet, so no OBSS narrow-bandwidth RU check on DFS channels */
void cfg80211_bss_iter(struct wiphy *wiphy, struct cfg80211_chan_def *chandef,
		       void (*iter)(struct wiphy *wiphy, struct cfg80211_bss *bss, void *data),
		       void *iter_data)
{
}

/* ---------- notifications from the driver ---------- */
/* no roaming: signal-threshold events are informational only */
void ieee80211_cqm_rssi_notify(struct ieee80211_vif *vif, enum nl80211_cqm_rssi_threshold_event rssi_event,
			       s32 rssi_level, gfp_t gfp) { }

/* remain-on-channel, AP, MLO and A-MPDU paths below are not entered by a plain
 * station that never calls remain_on_channel/start_ap/ampdu_action */
void ieee80211_ready_on_channel(struct ieee80211_hw *hw) { }
void ieee80211_remain_on_channel_expired(struct ieee80211_hw *hw) { }
void ieee80211_csa_finish(struct ieee80211_vif *vif, unsigned int link_id) { }
bool ieee80211_beacon_cntdwn_is_complete(struct ieee80211_vif *vif, unsigned int link_id) { return false; }
struct sk_buff *ieee80211_beacon_get_tim(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 *tim_offset,
					 u16 *tim_length, unsigned int link_id) { return NULL; }
void ieee80211_sta_ps_transition(struct ieee80211_sta *sta, bool start) { }
void ieee80211_sta_pspoll(struct ieee80211_sta *sta) { }
void ieee80211_sta_uapsd_trigger(struct ieee80211_sta *sta, u8 tid) { }
int ieee80211_set_active_links(struct ieee80211_vif *vif, u16 active_links) { return -EOPNOTSUPP; }
/* only feeds mac80211's own A-MSDU builder, which this stack does not have */
void ieee80211_sta_recalc_aggregates(struct ieee80211_sta *sta) { }

/* chanctx emulation for firmware without channel-context support: one context
 * maps onto hw->conf.chandef, as in mac80211's ieee80211_emulate_*_chanctx */
int ieee80211_emulate_add_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx)
{
	hw->conf.chandef = ctx->def;
	return hw_to_local(hw)->ops->config(hw, -1, IEEE80211_CONF_CHANGE_CHANNEL);
}

void ieee80211_emulate_remove_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx)
{
	hw->conf.chandef.chan = NULL;
}

void ieee80211_emulate_change_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx, u32 changed)
{
	hw->conf.chandef = ctx->def;
	hw_to_local(hw)->ops->config(hw, -1, IEEE80211_CONF_CHANGE_CHANNEL);
}

int ieee80211_emulate_switch_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif_chanctx_switch *vifs,
					 int n_vifs, enum ieee80211_chanctx_switch_mode mode)
{
	if (n_vifs <= 0)
		return -EINVAL;
	hw->conf.chandef = vifs[0].new_ctx->def;
	return hw_to_local(hw)->ops->config(hw, -1, IEEE80211_CONF_CHANGE_CHANNEL);
}

/* ---------- frame templates (layouts as mac80211 builds them) ---------- */
struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw, const u8 *src_addr, const u8 *ssid,
				       size_t ssid_len, size_t tailroom)
{
	struct ieee80211_hdr_3addr *hdr;
	struct sk_buff *skb;
	u8 *pos;

	if (ssid_len > IEEE80211_MAX_SSID_LEN)
		return NULL;
	skb = dev_alloc_skb(hw->extra_tx_headroom + sizeof(*hdr) + 2 + ssid_len + tailroom);
	if (!skb)
		return NULL;
	skb_reserve(skb, hw->extra_tx_headroom);
	hdr = skb_put_zero(skb, sizeof(*hdr));
	hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
	eth_broadcast_addr(hdr->addr1);
	memcpy(hdr->addr2, src_addr, ETH_ALEN);
	eth_broadcast_addr(hdr->addr3);
	pos = skb_put(skb, 2 + ssid_len);
	pos[0] = WLAN_EID_SSID;
	pos[1] = ssid_len;
	if (ssid_len)
		memcpy(pos + 2, ssid, ssid_len);
	return skb;
}

struct sk_buff *ieee80211_nullfunc_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, int link_id, bool qos_ok)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct ieee80211_bss_conf *conf = &vif->bss_conf;
	struct ieee80211_qos_hdr *h;
	struct sk_buff *skb;
	bool qos;

	if (vif->type != NL80211_IFTYPE_STATION || !conf->bssid)
		return NULL;
	qos = qos_ok && l->ap && l->ap->sta.wme;
	skb = dev_alloc_skb(hw->extra_tx_headroom + sizeof(*h));
	if (!skb)
		return NULL;
	skb_reserve(skb, hw->extra_tx_headroom);
	h = skb_put_zero(skb, qos ? sizeof(*h) : sizeof(struct ieee80211_hdr_3addr));
	h->frame_control = cpu_to_le16(IEEE80211_FTYPE_DATA | IEEE80211_FCTL_TODS |
				       (qos ? IEEE80211_STYPE_QOS_NULLFUNC : IEEE80211_STYPE_NULLFUNC));
	if (qos)
		h->qos_ctrl = cpu_to_le16(7);
	memcpy(h->addr1, conf->bssid, ETH_ALEN);
	memcpy(h->addr2, conf->addr, ETH_ALEN);
	memcpy(h->addr3, conf->bssid, ETH_ALEN);
	return skb;
}

struct sk_buff *ieee80211_pspoll_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif)
{
	struct { __le16 frame_control, aid; u8 bssid[ETH_ALEN], ta[ETH_ALEN]; } __packed *p;
	struct sk_buff *skb;

	if (vif->type != NL80211_IFTYPE_STATION || !vif->bss_conf.bssid)
		return NULL;
	skb = dev_alloc_skb(hw->extra_tx_headroom + sizeof(*p));
	if (!skb)
		return NULL;
	skb_reserve(skb, hw->extra_tx_headroom);
	p = skb_put_zero(skb, sizeof(*p));
	p->frame_control = cpu_to_le16(IEEE80211_FTYPE_CTL | IEEE80211_STYPE_PSPOLL);
	p->aid = cpu_to_le16(vif->cfg.aid | 0xc000); /* the two MSBs are set in a PS-Poll AID */
	memcpy(p->bssid, vif->bss_conf.bssid, ETH_ALEN);
	memcpy(p->ta, vif->addr, ETH_ALEN);
	return skb;
}

/* ---------- cfg80211 helpers ---------- */
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	if (chan <= 0)
		return 0;
	switch (band) {
	case NL80211_BAND_2GHZ:
		if (chan == 14)
			return 2484;
		return chan < 14 ? 2407 + chan * 5 : 0;
	case NL80211_BAND_5GHZ:
		return chan >= 182 && chan <= 196 ? 4000 + chan * 5 : 5000 + chan * 5;
	case NL80211_BAND_6GHZ:
		if (chan == 2)
			return 5935;
		return chan <= 233 ? 5950 + chan * 5 : 0;
	default:
		return 0;
	}
}

int ieee80211_frequency_to_channel(int freq)
{
	if (freq < 1000)
		return 0;
	if (freq == 2484)
		return 14;
	if (freq < 2484)
		return (freq - 2407) / 5;
	if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	if (freq < 5925)
		return (freq - 5000) / 5;
	if (freq == 5935)
		return 2;
	if (freq <= 45000)
		return (freq - 5950) / 5;
	return 0;
}

void cfg80211_chandef_create(struct cfg80211_chan_def *chandef, struct ieee80211_channel *chan,
			     enum nl80211_channel_type chantype)
{
	*chandef = (struct cfg80211_chan_def){ .chan = chan, .center_freq1 = chan->center_freq };
	switch (chantype) {
	case NL80211_CHAN_NO_HT:
		chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
		break;
	case NL80211_CHAN_HT20:
		chandef->width = NL80211_CHAN_WIDTH_20;
		break;
	case NL80211_CHAN_HT40PLUS:
		chandef->width = NL80211_CHAN_WIDTH_40;
		chandef->center_freq1 += 10;
		break;
	case NL80211_CHAN_HT40MINUS:
		chandef->width = NL80211_CHAN_WIDTH_40;
		chandef->center_freq1 -= 10;
		break;
	default:
		WARN_ON(1);
	}
}

int cfg80211_get_ies_channel_number(const u8 *ie, size_t ielen, enum nl80211_band band)
{
	const struct element *e;

	if (band == NL80211_BAND_6GHZ) /* RTL8852B has no 6 GHz radio */
		return -1;
	e = cfg80211_find_elem(WLAN_EID_DS_PARAMS, ie, ielen);
	if (e && e->datalen == 1)
		return e->data[0];
	e = cfg80211_find_elem(WLAN_EID_HT_OPERATION, ie, ielen);
	if (e && e->datalen >= sizeof(struct ieee80211_ht_operation))
		return ((const struct ieee80211_ht_operation *)e->data)->primary_chan;
	return -1;
}

/*
 * PHY rate in 100 kbit/s from the OFDM formula
 * data subcarriers * bits per subcarrier * coding rate * streams / symbol time.
 * Matches cfg80211's tables to within rounding.
 */
u32 cfg80211_calculate_bitrate(struct rate_info *r)
{
	/* bits per subcarrier * coding rate, times 6, for MCS 0..13 */
	static const u8 bpsc6[14] = { 3, 6, 9, 12, 18, 24, 27, 30, 36, 40, 45, 50, 54, 60 };
	static const u16 sd_ht[] = { [RATE_INFO_BW_20] = 52, [RATE_INFO_BW_40] = 108,
				     [RATE_INFO_BW_80] = 234, [RATE_INFO_BW_160] = 468 };
	static const u16 sd_he[] = { [RATE_INFO_BW_20] = 234, [RATE_INFO_BW_40] = 468,
				     [RATE_INFO_BW_80] = 980, [RATE_INFO_BW_160] = 1960 };
	unsigned int mcs = r->mcs, nss = r->nss, sd, sym_ns;

	if (r->flags & RATE_INFO_FLAGS_MCS) {
		nss = mcs / 8 + 1;
		mcs %= 8;
	} else if (!(r->flags & (RATE_INFO_FLAGS_VHT_MCS | RATE_INFO_FLAGS_HE_MCS))) {
		return r->legacy;
	}
	if (r->bw > RATE_INFO_BW_160 || mcs >= ARRAY_SIZE(bpsc6) || !nss)
		return 0;
	if (r->flags & RATE_INFO_FLAGS_HE_MCS) {
		sd = sd_he[r->bw];
		sym_ns = 12800 + (r->he_gi == NL80211_RATE_INFO_HE_GI_0_8 ? 800 :
				  r->he_gi == NL80211_RATE_INFO_HE_GI_1_6 ? 1600 : 3200);
	} else {
		sd = sd_ht[r->bw];
		sym_ns = r->flags & RATE_INFO_FLAGS_SHORT_GI ? 3600 : 4000;
	}
	if (!sd)
		return 0;
	/* 100 kbit/s = bits per 10 us */
	return (u32)(((u64)sd * bpsc6[mcs] * nss * 10000 / 6 + sym_ns / 2) / sym_ns);
}

/* ---------- station interface lifecycle (used by the backend) ---------- */
int lkpi80211_up(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct ieee80211_vif *vif;
	unsigned int filter = FIF_ALLMULTI; /* multicast: IPv6 ND, mDNS */
	struct lkpi_vif *lv;
	struct lkpi_txq *t;
	int ret;

	if (!l->registered)
		return -ENODEV;
	wiphy_lock(&l->wiphy);
	if (l->lv) {
		wiphy_unlock(&l->wiphy);
		return 0;
	}
	ret = l->ops->start(hw);
	if (ret)
		goto out;
	l->started = true;

	lv = kzalloc(sizeof(*lv) + hw->vif_data_size, GFP_KERNEL);
	ret = -ENOMEM;
	if (!lv)
		goto err_stop;
	lv->local = l;
	vif = &lv->vif;
	vif->type = NL80211_IFTYPE_STATION;
	memcpy(vif->addr, l->wiphy.perm_addr, ETH_ALEN);
	memcpy(vif->bss_conf.addr, vif->addr, ETH_ALEN);
	vif->bss_conf.vif = vif;
	vif->link_conf[0] = &vif->bss_conf;
	t = txq_alloc(l, vif, NULL, 0);
	if (!t)
		goto err_vif;
	vif->txq = &t->txq;
	ret = l->ops->add_interface(hw, vif);
	if (ret)
		goto err_txq;
	l->lv = lv;

	l->ops->configure_filter(hw, filter, &filter, 0);
	/* like ieee80211_hw_conf_init(): push the idle state, the driver may enter IPS */
	if (l->ops->config)
		l->ops->config(hw, -1, ~(IEEE80211_CONF_CHANGE_CHANNEL | IEEE80211_CONF_CHANGE_SMPS));
	wiphy_unlock(&l->wiphy);
	return 0;

err_txq:
	txq_free(l, vif->txq);
err_vif:
	kfree(lv);
err_stop:
	l->ops->stop(hw, false);
	l->started = false;
out:
	wiphy_unlock(&l->wiphy);
	return ret;
}

void lkpi80211_down(struct ieee80211_hw *hw)
{
	struct lkpi_local *l = hw_to_local(hw);
	struct lkpi_vif *lv;

	wiphy_lock(&l->wiphy);
	lkpi_mlme_down(l);
	lv = l->lv;
	if (lv) {
		l->ops->remove_interface(hw, &lv->vif);
		l->lv = NULL;
		txq_free(l, lv->vif.txq);
		kfree(lv);
	}
	if (l->started) {
		l->ops->stop(hw, false);
		l->started = false;
	}
	wiphy_unlock(&l->wiphy);
}
