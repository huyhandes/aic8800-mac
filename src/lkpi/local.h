// SPDX-License-Identifier: BSD-3-Clause
/* shared between the mac80211 shim and the station MLME */
#ifndef LKPI_LOCAL_H
#define LKPI_LOCAL_H
#include "net/mac80211.h"

struct lkpi_txq {
	struct list_head sched; /* on local->active[ac] or local->round[ac] */
	struct sk_buff_head q;
	u32 bytes;
	bool inflight; /* between next_txq() and return_txq(): txq_free() waits */
	struct ieee80211_txq txq; /* last: driver data follows */
};

struct lkpi_local;
struct lkpi_vif {
	struct lkpi_local *local;
	struct ieee80211_vif vif; /* last */
};
struct lkpi_sta {
	struct lkpi_vif *lv;
	enum ieee80211_sta_state state;
	struct ieee80211_sta sta; /* last */
};

struct lkpi_local {
	struct ieee80211_hw hw;
	struct wiphy wiphy;
	const struct ieee80211_ops *ops;
	struct workqueue_struct *wq; /* ieee80211_queue_work(): ordered */
	spinlock_t txq_lock;
	struct list_head active[IEEE80211_NUM_ACS], round[IEEE80211_NUM_ACS];
	int queues_stopped;
	bool registered, started;
	struct lkpi_vif *lv;  /* the station interface, NULL while down */
	struct lkpi_sta *ap;  /* its AP once added to the driver */
	struct wiphy_work reg_work;
	struct regulatory_request reg_req;
	u8 priv[] __aligned(64);
};

static inline struct lkpi_local *hw_to_local(struct ieee80211_hw *hw) { return container_of(hw, struct lkpi_local, hw); }
static inline struct lkpi_vif *to_lv(struct ieee80211_vif *vif) { return container_of(vif, struct lkpi_vif, vif); }
static inline struct lkpi_txq *to_lt(struct ieee80211_txq *txq) { return container_of(txq, struct lkpi_txq, txq); }

struct lkpi_txq *txq_alloc(struct lkpi_local *l, struct ieee80211_vif *vif, struct ieee80211_sta *sta, u8 tid);
void txq_free(struct lkpi_local *l, struct ieee80211_txq *txq);
void wake_all_txqs(struct lkpi_local *l);
struct lkpi_sta *uploaded_sta(struct lkpi_local *l);
void lkpi_mlme_down(struct lkpi_local *l);
#endif
