/* SPDX-License-Identifier: BSD-3-Clause */
/* self-check for lkpi/mac80211.c: rate/channel math, frame templates, txq rounds, wiphy work, reg hints */
#include "net/mac80211.h"
#undef snprintf
#include <assert.h>

static u32 rate(u32 flags, u8 mcs, u8 nss, u8 bw, u8 gi)
{
	struct rate_info r = { .flags = flags, .mcs = mcs, .nss = nss, .bw = bw, .he_gi = gi };

	return cfg80211_calculate_bitrate(&r);
}

static void test_math(void)
{
	/* reference values from the 802.11 rate tables, in 100 kbit/s */
	assert(rate(RATE_INFO_FLAGS_MCS, 7, 0, RATE_INFO_BW_20, 0) == 650);
	assert(rate(RATE_INFO_FLAGS_MCS | RATE_INFO_FLAGS_SHORT_GI, 15, 0, RATE_INFO_BW_40, 0) == 3000);
	assert(rate(RATE_INFO_FLAGS_VHT_MCS | RATE_INFO_FLAGS_SHORT_GI, 9, 2, RATE_INFO_BW_80, 0) == 8667);
	assert(rate(RATE_INFO_FLAGS_HE_MCS, 11, 2, RATE_INFO_BW_80, NL80211_RATE_INFO_HE_GI_0_8) == 12010);
	assert(rate(RATE_INFO_FLAGS_HE_MCS, 0, 1, RATE_INFO_BW_20, NL80211_RATE_INFO_HE_GI_3_2) == 73);
	assert(rate(RATE_INFO_FLAGS_HE_MCS, 14, 1, RATE_INFO_BW_20, 0) == 0); /* out of range */
	struct rate_info leg = { .legacy = 540 };
	assert(cfg80211_calculate_bitrate(&leg) == 540);

	assert(ieee80211_channel_to_frequency(1, NL80211_BAND_2GHZ) == 2412);
	assert(ieee80211_channel_to_frequency(14, NL80211_BAND_2GHZ) == 2484);
	assert(ieee80211_channel_to_frequency(36, NL80211_BAND_5GHZ) == 5180);
	assert(ieee80211_channel_to_frequency(15, NL80211_BAND_2GHZ) == 0);
	assert(ieee80211_frequency_to_channel(2412) == 1 && ieee80211_frequency_to_channel(2484) == 14);
	assert(ieee80211_frequency_to_channel(5180) == 36 && ieee80211_frequency_to_channel(5825) == 165);

	struct ieee80211_channel ch = { .band = NL80211_BAND_5GHZ, .center_freq = 5180 };
	struct cfg80211_chan_def cd;
	cfg80211_chandef_create(&cd, &ch, NL80211_CHAN_HT40PLUS);
	assert(cd.chan == &ch && cd.width == NL80211_CHAN_WIDTH_40 && cd.center_freq1 == 5190);
	cfg80211_chandef_create(&cd, &ch, NL80211_CHAN_NO_HT);
	assert(cd.width == NL80211_CHAN_WIDTH_20_NOHT && cd.center_freq1 == 5180);

	const u8 ds[] = { WLAN_EID_SSID, 1, 'x', WLAN_EID_DS_PARAMS, 1, 6 };
	u8 ht[2 + sizeof(struct ieee80211_ht_operation)] = { WLAN_EID_HT_OPERATION, sizeof(struct ieee80211_ht_operation), 44 };
	assert(cfg80211_get_ies_channel_number(ds, sizeof(ds), NL80211_BAND_2GHZ) == 6);
	assert(cfg80211_get_ies_channel_number(ht, sizeof(ht), NL80211_BAND_5GHZ) == 44);
	assert(cfg80211_get_ies_channel_number(ds, 3, NL80211_BAND_2GHZ) == -1);
}

/* ---- a fake driver ---- */
static int n_start, n_stop, n_add, n_remove, n_wake, n_config;
static u32 last_changed;
static char reg_seen[8];
static int reg_by[2];

static void d_tx(struct ieee80211_hw *hw, struct ieee80211_tx_control *c, struct sk_buff *skb) { kfree_skb(skb); }
static int d_start(struct ieee80211_hw *hw) { n_start++; return 0; }
static void d_stop(struct ieee80211_hw *hw, bool s) { n_stop++; }
static int d_add(struct ieee80211_hw *hw, struct ieee80211_vif *vif) { n_add++; return 0; }
static void d_remove(struct ieee80211_hw *hw, struct ieee80211_vif *vif) { n_remove++; }
static int d_config(struct ieee80211_hw *hw, int r, u32 changed) { n_config++; last_changed = changed; return 0; }
static void d_filter(struct ieee80211_hw *hw, unsigned int ch, unsigned int *total, u64 mc) { *total &= FIF_ALLMULTI; }
static void d_wake(struct ieee80211_hw *hw, struct ieee80211_txq *txq) { n_wake++; }
static void d_reg(struct wiphy *wiphy, struct regulatory_request *req)
{
	/* wiphy work and the register-time call both hold the wiphy mutex */
	assert(pthread_mutex_trylock(&wiphy->mtx.m) != 0);
	memcpy(reg_seen, req->alpha2, 2);
	reg_by[req->initiator == NL80211_REGDOM_SET_BY_DRIVER]++;
}

static const struct ieee80211_ops ops = {
	.tx = d_tx, .start = d_start, .stop = d_stop, .add_interface = d_add, .remove_interface = d_remove,
	.config = d_config, .configure_filter = d_filter, .wake_tx_queue = d_wake,
};

static int dw_ran;
static void dw_fn(struct wiphy *wiphy, struct wiphy_work *w)
{
	assert(pthread_mutex_trylock(&wiphy->mtx.m) != 0);
	dw_ran++;
}

static void grab_vif(void *d, u8 *m, struct ieee80211_vif *v) { *(struct ieee80211_vif **)d = v; }

static void test_stack(void)
{
	struct ieee80211_hw *hw = ieee80211_alloc_hw(32, &ops);
	struct ieee80211_vif *vif = NULL;
	const u8 mac[ETH_ALEN] = { 2, 0, 0, 0, 0, 1 }, bssid[ETH_ALEN] = { 2, 0, 0, 0, 0, 2 };

	assert(hw && hw->priv && hw->wiphy && wiphy_to_ieee80211_hw(hw->wiphy) == hw);
	assert(hw->conf.flags & IEEE80211_CONF_IDLE);
	hw->extra_tx_headroom = 16;
	hw->wiphy->reg_notifier = d_reg;
	memcpy(hw->wiphy->perm_addr, mac, ETH_ALEN);
	assert(lkpi80211_up(hw) == -ENODEV); /* not registered */

	/* registration reports the world domain; a hint arrives later from wiphy work */
	assert(ieee80211_register_hw(hw) == 0);
	assert(!memcmp(reg_seen, "00", 2) && reg_by[0] == 1 && reg_by[1] == 0);
	assert(regulatory_hint(hw->wiphy, "1x") == -EINVAL);
	assert(regulatory_hint(hw->wiphy, "US") == 0);
	flush_workqueue(hw->wiphy->lkpi_wq);
	assert(!memcmp(reg_seen, "US", 2) && reg_by[1] == 1);

	assert(lkpi80211_up(hw) == 0 && lkpi80211_up(hw) == 0); /* second call is a no-op */
	assert(n_start == 1 && n_add == 1);
	assert(n_config == 1 && !(last_changed & IEEE80211_CONF_CHANGE_CHANNEL) && (last_changed & IEEE80211_CONF_CHANGE_IDLE));
	ieee80211_iterate_active_interfaces_atomic(hw, 0, grab_vif, &vif);
	assert(vif && !memcmp(vif->addr, mac, ETH_ALEN) && vif->txq && vif->txq->ac == IEEE80211_AC_BE);

	/* templates */
	struct sk_buff *skb = ieee80211_probereq_get(hw, mac, (const u8 *)"net", 3, 10);
	struct ieee80211_hdr_3addr *h = (void *)skb->data;
	assert(skb->len == 24 + 5 && skb_headroom(skb) >= 16 && skb_tailroom(skb) >= 10);
	assert(le16_to_cpu(h->frame_control) == (IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ));
	assert(is_broadcast_ether_addr(h->addr1) && !memcmp(h->addr2, mac, 6) && is_broadcast_ether_addr(h->addr3));
	assert(skb->data[24] == WLAN_EID_SSID && skb->data[25] == 3 && !memcmp(skb->data + 26, "net", 3));
	kfree_skb(skb);
	assert(!ieee80211_nullfunc_get(hw, vif, -1, true)); /* not associated */
	vif->bss_conf.bssid = bssid;
	vif->cfg.aid = 5;
	skb = ieee80211_nullfunc_get(hw, vif, -1, true); /* no WMM peer: plain nullfunc */
	h = (void *)skb->data;
	assert(skb->len == 24 && le16_to_cpu(h->frame_control) ==
	       (IEEE80211_FTYPE_DATA | IEEE80211_STYPE_NULLFUNC | IEEE80211_FCTL_TODS));
	assert(!memcmp(h->addr1, bssid, 6) && !memcmp(h->addr2, mac, 6) && !memcmp(h->addr3, bssid, 6));
	kfree_skb(skb);
	skb = ieee80211_pspoll_get(hw, vif);
	assert(skb->len == 16 && skb->data[0] == 0xa4 && skb->data[2] == 5 && skb->data[3] == 0xc0);
	kfree_skb(skb);

	/* txq rounds: each scheduled txq is handed out once per round */
	struct ieee80211_txq *q = vif->txq;
	assert(!ieee80211_next_txq(hw, IEEE80211_AC_BE));
	ieee80211_schedule_txq(hw, q);
	ieee80211_schedule_txq(hw, q); /* idempotent */
	ieee80211_txq_schedule_start(hw, IEEE80211_AC_BE);
	assert(ieee80211_next_txq(hw, IEEE80211_AC_BE) == q && !ieee80211_next_txq(hw, IEEE80211_AC_BE));
	ieee80211_return_txq(hw, q, false); /* empty: dropped from the schedule */
	ieee80211_txq_schedule_end(hw, IEEE80211_AC_BE);
	ieee80211_txq_schedule_start(hw, IEEE80211_AC_BE);
	assert(!ieee80211_next_txq(hw, IEEE80211_AC_BE));
	ieee80211_txq_schedule_end(hw, IEEE80211_AC_BE);
	ieee80211_schedule_txq(hw, q);
	ieee80211_stop_queues(hw);
	ieee80211_txq_schedule_start(hw, IEEE80211_AC_BE);
	assert(!ieee80211_next_txq(hw, IEEE80211_AC_BE)); /* stopped: kept for later */
	ieee80211_txq_schedule_end(hw, IEEE80211_AC_BE);
	ieee80211_wake_queues(hw);
	assert(n_wake == 1);
	ieee80211_txq_schedule_start(hw, IEEE80211_AC_BE);
	assert(ieee80211_next_txq(hw, IEEE80211_AC_BE) == q);
	ieee80211_return_txq(hw, q, true); /* force keeps it scheduled */
	ieee80211_txq_schedule_end(hw, IEEE80211_AC_BE);
	unsigned long frames = 9, bytes = 9;
	ieee80211_txq_get_depth(q, &frames, &bytes);
	assert(frames == 0 && bytes == 0 && !ieee80211_tx_dequeue_ni(hw, q));

	/* wiphy delayed work: fires, flush runs it inline, cancel stops it */
	struct wiphy_delayed_work dw;
	wiphy_delayed_work_init(&dw, dw_fn);
	wiphy_delayed_work_queue(hw->wiphy, &dw, msecs_to_jiffies(5));
	for (int i = 0; i < 200 && !dw_ran; i++)
		lkpi_sleep_us(1000);
	assert(dw_ran == 1);
	wiphy_lock(hw->wiphy);
	wiphy_delayed_work_queue(hw->wiphy, &dw, msecs_to_jiffies(10000));
	wiphy_delayed_work_flush(hw->wiphy, &dw);
	assert(dw_ran == 2);
	wiphy_delayed_work_flush(hw->wiphy, &dw); /* nothing pending */
	assert(dw_ran == 2);
	wiphy_delayed_work_queue(hw->wiphy, &dw, msecs_to_jiffies(5));
	wiphy_delayed_work_cancel(hw->wiphy, &dw);
	wiphy_delayed_work_queue(hw->wiphy, &dw, 0); /* queued now, runs after we unlock */
	wiphy_unlock(hw->wiphy);
	flush_workqueue(hw->wiphy->lkpi_wq);
	lkpi_sleep_us(20000);
	assert(dw_ran == 3);

	ieee80211_unregister_hw(hw);
	assert(n_remove == 1 && n_stop == 1);
	ieee80211_free_hw(hw);
}

int main(void)
{
	test_math();
	test_stack();
	puts("lkpi mac80211_test: ok");
	return 0;
}
