/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Minimal cfg80211/mac80211 interface for running the rtw89 driver in user
 * space. Structures carry only the members rtw89 or src/lkpi/mac80211.c use;
 * over-the-air frame layouts and constant values follow IEEE 802.11.
 */
#pragma once
#include "../lkpi.h"
#include "lkpi_80211_consts.h"

#define IEEE80211_MAX_CHAINS 4
#define IEEE80211_HT_MCS_MASK_LEN 10
#define IEEE80211_HE_PPE_THRES_MAX_LEN 25
#define IEEE80211_EHT_PPE_THRES_MAX_LEN 32
#define IEEE80211_TPE_EIRP_ENTRIES_320MHZ 5
#define IEEE80211_TPE_PSD_ENTRIES_320MHZ 16
#define IEEE80211_BSS_ARP_ADDR_LIST_LEN 4
#define IEEE80211_TX_INFO_DRIVER_DATA_SIZE 40
#define IEEE80211_TX_MAX_RATES 4
#define IEEE80211_TX_RATE_TABLE_SIZE 4
#define IEEE80211_QOS_CTL_LEN 2
#define IEEE80211_HT_CTL_LEN 4
#define ETHTOOL_FWVERS_LEN 32
#define __iftd

extern const unsigned char rfc1042_header[6];

/* wiphy->regulatory_flags (values as in Linux net/regulatory.h) */
enum ieee80211_regulatory_flags {
	REGULATORY_CUSTOM_REG = BIT(0),
	REGULATORY_STRICT_REG = BIT(1),
	REGULATORY_DISABLE_BEACON_HINTS = BIT(2),
	REGULATORY_COUNTRY_IE_FOLLOW_POWER = BIT(3),
	REGULATORY_COUNTRY_IE_IGNORE = BIT(4),
	REGULATORY_ENABLE_RELAX_NO_IR = BIT(5),
	REGULATORY_WIPHY_SELF_MANAGED = BIT(7),
};

struct wiphy;
struct ieee80211_hw;
struct ieee80211_vif;
struct ieee80211_sta;
struct ieee80211_txq;

/* ---------- over-the-air formats ---------- */
struct ieee80211_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	u8 addr4[ETH_ALEN];
} __packed __aligned(2);

struct ieee80211_hdr_3addr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
} __packed __aligned(2);

struct ieee80211_qos_hdr {
	__le16 frame_control;
	__le16 duration_id;
	u8 addr1[ETH_ALEN];
	u8 addr2[ETH_ALEN];
	u8 addr3[ETH_ALEN];
	__le16 seq_ctrl;
	__le16 qos_ctrl;
} __packed __aligned(2);

struct ieee80211_mgmt {
	__le16 frame_control;
	__le16 duration;
	u8 da[ETH_ALEN];
	u8 sa[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	__le16 seq_ctrl;
	union {
		struct { __le16 auth_alg, auth_transaction, status_code; u8 variable[]; } __packed auth;
		struct { __le16 reason_code; } __packed deauth;
		struct { __le16 capab_info, listen_interval; u8 variable[]; } __packed assoc_req;
		struct { __le16 capab_info, status_code, aid; u8 variable[]; } __packed assoc_resp, reassoc_resp;
		struct { __le16 capab_info, listen_interval; u8 current_ap[ETH_ALEN]; u8 variable[]; } __packed reassoc_req;
		struct { __le16 reason_code; } __packed disassoc;
		struct { __le64 timestamp; __le16 beacon_int, capab_info; u8 variable[]; } __packed beacon;
		struct { DECLARE_FLEX_ARRAY(u8, variable); } __packed probe_req;
		struct { __le64 timestamp; __le16 beacon_int, capab_info; u8 variable[]; } __packed probe_resp;
		struct {
			u8 category;
			u8 action_code;
			union {
				struct { u8 dialog_token; __le16 capab, timeout, start_seq_num; u8 variable[]; } __packed addba_req;
				struct { u8 dialog_token; __le16 status, capab, timeout; u8 variable[]; } __packed addba_resp;
				struct { __le16 params, reason_code; } __packed delba;
				struct { u8 trans_id[WLAN_SA_QUERY_TR_ID_LEN]; } __packed sa_query;
			};
		} __packed action;
		DECLARE_FLEX_ARRAY(u8, body);
	} u;
} __packed __aligned(2);

struct ieee80211_trigger {
	__le16 frame_control;
	__le16 duration;
	u8 ra[ETH_ALEN];
	u8 ta[ETH_ALEN];
	__le64 common_info;
	u8 variable[];
} __packed __aligned(2);

struct element {
	u8 id;
	u8 datalen;
	u8 data[];
} __packed;

struct ieee80211_mcs_info {
	u8 rx_mask[IEEE80211_HT_MCS_MASK_LEN];
	__le16 rx_highest;
	u8 tx_params;
	u8 reserved[3];
} __packed;

struct ieee80211_ht_cap {
	__le16 cap_info;
	u8 ampdu_params_info;
	struct ieee80211_mcs_info mcs;
	__le16 extended_ht_cap_info;
	__le32 tx_BF_cap_info;
	u8 antenna_selection_info;
} __packed;

struct ieee80211_ht_operation {
	u8 primary_chan;
	u8 ht_param;
	__le16 operation_mode;
	__le16 stbc_param;
	u8 basic_set[16];
} __packed;

struct ieee80211_vht_mcs_info {
	__le16 rx_mcs_map;
	__le16 rx_highest;
	__le16 tx_mcs_map;
	__le16 tx_highest;
} __packed;

struct ieee80211_vht_cap {
	__le32 vht_cap_info;
	struct ieee80211_vht_mcs_info supp_mcs;
} __packed;

struct ieee80211_vht_operation {
	u8 chan_width;
	u8 center_freq_seg0_idx;
	u8 center_freq_seg1_idx;
	__le16 basic_mcs_set;
} __packed;

struct ieee80211_he_cap_elem {
	u8 mac_cap_info[6];
	u8 phy_cap_info[11];
} __packed;

struct ieee80211_he_mcs_nss_supp {
	__le16 rx_mcs_80, tx_mcs_80;
	__le16 rx_mcs_160, tx_mcs_160;
	__le16 rx_mcs_80p80, tx_mcs_80p80;
} __packed;

struct ieee80211_he_operation {
	__le32 he_oper_params;
	__le16 he_mcs_nss_set;
	u8 optional[];
} __packed;

struct ieee80211_he_6ghz_capa {
	__le16 capa;
} __packed;

struct ieee80211_he_mu_edca_param_ac_rec {
	u8 aifsn;
	u8 ecw_min_max;
	u8 mu_edca_timer;
} __packed;

struct ieee80211_eht_cap_elem_fixed {
	u8 mac_cap_info[2];
	u8 phy_cap_info[9];
} __packed;

struct ieee80211_eht_mcs_nss_supp_20mhz_only {
	union {
		struct { u8 rx_tx_mcs7_max_nss, rx_tx_mcs9_max_nss, rx_tx_mcs11_max_nss, rx_tx_mcs13_max_nss; };
		u8 rx_tx_max_nss[4];
	};
} __packed;

struct ieee80211_eht_mcs_nss_supp_bw {
	union {
		struct { u8 rx_tx_mcs9_max_nss, rx_tx_mcs11_max_nss, rx_tx_mcs13_max_nss; };
		u8 rx_tx_max_nss[3];
	};
} __packed;

struct ieee80211_eht_mcs_nss_supp {
	union {
		struct ieee80211_eht_mcs_nss_supp_20mhz_only only_20mhz;
		struct {
			struct ieee80211_eht_mcs_nss_supp_bw _80, _160, _320;
		} __packed bw;
	} __packed;
} __packed;

struct ieee80211_p2p_noa_desc {
	u8 count;
	__le32 duration;
	__le32 interval;
	__le32 start_time;
} __packed;

struct ieee80211_p2p_noa_attr {
	u8 index;
	u8 oppps_ctwindow;
	struct ieee80211_p2p_noa_desc desc[IEEE80211_P2P_NOA_DESC_MAX];
} __packed;

struct ieee80211_radiotap_vht {
	__le16 known;
	u8 flags, bandwidth, mcs_nss[4], coding, group_id;
	__le16 partial_aid;
} __packed;
struct ieee80211_radiotap_he { __le16 data1, data2, data3, data4, data5, data6; } __packed;
struct ieee80211_radiotap_he_mu { __le16 flags1, flags2; u8 ru_ch1[4], ru_ch2[4]; } __packed;
struct ieee80211_radiotap_tlv { __le16 type, len; u8 data[]; } __packed;
struct ieee80211_radiotap_eht { __le32 known; __le32 data[9]; __le32 user_info[]; } __packed;
struct ieee80211_radiotap_eht_usig { __le32 common, value, mask; } __packed;

/* ---------- cfg80211 ---------- */
struct ieee80211_channel {
	enum nl80211_band band;
	u32 center_freq;
	u16 hw_value;
	u32 flags;
	int max_power;
};

struct ieee80211_rate {
	u32 flags;
	u16 bitrate;
	u16 hw_value, hw_value_short;
};

struct ieee80211_sta_ht_cap {
	u16 cap;
	bool ht_supported;
	u8 ampdu_factor;
	u8 ampdu_density;
	struct ieee80211_mcs_info mcs;
};

struct ieee80211_sta_vht_cap {
	bool vht_supported;
	u32 cap;
	struct ieee80211_vht_mcs_info vht_mcs;
};

struct ieee80211_sta_he_cap {
	bool has_he;
	struct ieee80211_he_cap_elem he_cap_elem;
	struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp;
	u8 ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN];
};

struct ieee80211_sta_eht_cap {
	bool has_eht;
	struct ieee80211_eht_cap_elem_fixed eht_cap_elem;
	struct ieee80211_eht_mcs_nss_supp eht_mcs_nss_supp;
	u8 eht_ppe_thres[IEEE80211_EHT_PPE_THRES_MAX_LEN];
};

struct ieee80211_sband_iftype_data {
	u16 types_mask;
	struct ieee80211_sta_he_cap he_cap;
	struct ieee80211_he_6ghz_capa he_6ghz_capa;
	struct ieee80211_sta_eht_cap eht_cap;
	struct { const u8 *data; unsigned int len; } vendor_elems;
};

struct ieee80211_supported_band {
	struct ieee80211_channel *channels;
	struct ieee80211_rate *bitrates;
	enum nl80211_band band;
	int n_channels;
	int n_bitrates;
	struct ieee80211_sta_ht_cap ht_cap;
	struct ieee80211_sta_vht_cap vht_cap;
	u16 n_iftype_data;
	const struct ieee80211_sband_iftype_data *iftype_data;
};

static inline void _ieee80211_set_sband_iftype_data(struct ieee80211_supported_band *sband,
						    const struct ieee80211_sband_iftype_data *d, u16 n)
{ sband->iftype_data = d; sband->n_iftype_data = n; }

static inline const struct ieee80211_sband_iftype_data *
ieee80211_get_sband_iftype_data(const struct ieee80211_supported_band *sband, u16 iftype)
{
	for (int i = 0; i < sband->n_iftype_data; i++)
		if (sband->iftype_data[i].types_mask & BIT(iftype))
			return &sband->iftype_data[i];
	return NULL;
}

struct cfg80211_chan_def {
	struct ieee80211_channel *chan;
	enum nl80211_chan_width width;
	u32 center_freq1;
	u32 center_freq2;
	u16 punctured;
};

struct cfg80211_ssid {
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 ssid_len;
};

struct cfg80211_scan_info {
	bool aborted;
};

struct cfg80211_scan_6ghz_params {
	u32 short_ssid;
	u32 channel_idx;
	u8 bssid[ETH_ALEN];
	bool unsolicited_probe;
	bool short_ssid_valid;
	bool psc_no_listen;
	s8 psd_20;
};

struct cfg80211_scan_request {
	struct cfg80211_ssid *ssids;
	int n_ssids;
	u32 n_channels;
	const u8 *ie;
	size_t ie_len;
	u16 duration;
	bool duration_mandatory;
	u32 flags;
	u32 rates[NUM_NL80211_BANDS];
	u8 mac_addr[ETH_ALEN] __aligned(2);
	u8 mac_addr_mask[ETH_ALEN] __aligned(2);
	u8 bssid[ETH_ALEN] __aligned(2);
	struct wiphy *wiphy;
	bool no_cck;
	u32 n_6ghz_params;
	struct cfg80211_scan_6ghz_params *scan_6ghz_params;
	struct ieee80211_channel *channels[];
};

struct cfg80211_match_set {
	struct cfg80211_ssid ssid;
	u8 bssid[ETH_ALEN];
	s32 rssi_thold;
};

struct cfg80211_sched_scan_request {
	struct cfg80211_ssid *ssids;
	int n_ssids;
	u32 n_channels;
	const u8 *ie;
	size_t ie_len;
	u32 flags;
	struct cfg80211_match_set *match_sets;
	int n_match_sets;
	u32 delay;
	u8 mac_addr[ETH_ALEN] __aligned(2);
	u8 mac_addr_mask[ETH_ALEN] __aligned(2);
	struct wiphy *wiphy;
	struct net_device *dev;
	struct list_head list;
	struct ieee80211_channel *channels[];
};

struct cfg80211_bitrate_mask {
	struct {
		u32 legacy;
		u8 ht_mcs[IEEE80211_HT_MCS_MASK_LEN];
		u16 vht_mcs[NL80211_VHT_NSS_MAX];
		u16 he_mcs[NL80211_HE_NSS_MAX];
		u16 eht_mcs[NL80211_EHT_NSS_MAX];
		enum nl80211_txrate_gi gi;
		enum nl80211_he_gi he_gi;
		enum nl80211_eht_gi eht_gi;
		enum nl80211_he_ltf he_ltf;
		enum nl80211_eht_ltf eht_ltf;
	} control[NUM_NL80211_BANDS];
};

struct cfg80211_tid_cfg {
	u8 tids;
	u64 mask;
	enum nl80211_tid_config ampdu;
	enum nl80211_tid_config amsdu;
};

struct cfg80211_tid_config {
	const u8 *peer;
	u32 n_tid_conf;
	struct cfg80211_tid_cfg tid_conf[];
};

struct ieee80211_iface_limit {
	u16 max;
	u16 types;
};

struct ieee80211_iface_combination {
	const struct ieee80211_iface_limit *limits;
	u32 num_different_channels;
	u16 max_interfaces;
	u8 n_limits;
	bool beacon_int_infra_match;
};

struct wiphy_iftype_ext_capab {
	enum nl80211_iftype iftype;
	const u8 *extended_capabilities;
	const u8 *extended_capabilities_mask;
	u8 extended_capabilities_len;
	u16 eml_capabilities;
	u16 mld_capa_and_ops;
};

struct cfg80211_sar_sub_specs {
	s32 power;
	u32 freq_range_index;
};

struct cfg80211_sar_specs {
	enum nl80211_sar_type type;
	u32 num_sub_specs;
	struct cfg80211_sar_sub_specs sub_specs[];
};

struct cfg80211_sar_freq_ranges {
	u32 start_freq;
	u32 end_freq;
};

struct cfg80211_sar_capa {
	enum nl80211_sar_type type;
	u32 num_freq_ranges;
	const struct cfg80211_sar_freq_ranges *freq_ranges;
};

struct regulatory_request {
	char alpha2[3];
	enum nl80211_reg_initiator initiator;
};

struct rate_info {
	u16 flags;
	u16 legacy;
	u8 mcs;
	u8 nss;
	u8 bw;
	u8 he_gi;
	u8 he_dcm;
	u8 he_ru_alloc;
	u8 eht_gi;
};

struct link_station_info {
	u64 filled;
	s8 signal;
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	struct rate_info txrate;
};

struct station_info {
	u64 filled;
	s8 signal;
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	struct rate_info txrate;
	u16 valid_links;
	struct link_station_info *links[IEEE80211_MLD_MAX_NUM_LINKS];
};

struct survey_info {
	struct ieee80211_channel *channel;
	u32 filled;
	s8 noise;
};

struct cfg80211_bss_ies {
	int len;
	u8 data[];
};

struct cfg80211_bss {
	struct ieee80211_channel *channel;
	const struct cfg80211_bss_ies *ies;
	s32 signal;
	u16 beacon_interval;
	u8 bssid[ETH_ALEN];
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	u8 bssid_index;
};

struct cfg80211_wowlan {
	bool any, disconnect, magic_pkt, gtk_rekey_failure, eap_identity_req, four_way_handshake, rfkill_release;
	struct cfg80211_wowlan_tcp *tcp;
	int n_patterns;
	struct cfg80211_sched_scan_request *nd_config;
};

struct wiphy_wowlan_support {
	u32 flags;
	int n_patterns;
	int pattern_max_len;
	int pattern_min_len;
	const struct wiphy_wowlan_tcp_support *tcp;
};

struct cfg80211_gtk_rekey_data {
	const u8 *kek, *kck, *replay_ctr;
	u32 akm;
	u8 kek_len, kck_len;
};

struct cfg80211_he_bss_color {
	u8 color;
	bool enabled;
	bool partial;
};

struct ieee80211_parsed_tpe_eirp {
	bool valid;
	s8 power[IEEE80211_TPE_EIRP_ENTRIES_320MHZ];
	u8 count;
};

struct ieee80211_parsed_tpe_psd {
	bool valid;
	s8 power[IEEE80211_TPE_PSD_ENTRIES_320MHZ];
	u8 count, n;
};

struct ieee80211_parsed_tpe {
	struct ieee80211_parsed_tpe_eirp max_local[2], max_reg_client[2];
	struct ieee80211_parsed_tpe_psd psd_local[2], psd_reg_client[2];
};

/* wiphy work runs on the wiphy's worker thread with the wiphy mutex held */
struct wiphy_work;
typedef void (*wiphy_work_func_t)(struct wiphy *, struct wiphy_work *);
struct wiphy_work {
	struct work_struct lkpi;
	struct wiphy *wiphy;
	wiphy_work_func_t func;
};
struct wiphy_delayed_work {
	struct wiphy_work work;
	struct wiphy *wiphy;
	struct lkpi_timer timer;
};

struct wiphy {
	struct mutex mtx;
	struct workqueue_struct *lkpi_wq; /* ordered, runs items under mtx */
	u8 perm_addr[ETH_ALEN];
	u8 addr_mask[ETH_ALEN];
	const struct ieee80211_iface_combination *iface_combinations;
	int n_iface_combinations;
	u16 interface_modes;
	u32 flags, regulatory_flags, features;
	unsigned long ext_features[BITS_TO_LONGS(NUM_NL80211_EXT_FEATURES)];
	u8 max_scan_ssids;
	u8 max_sched_scan_ssids;
	u8 max_sched_scan_reqs;
	u16 max_scan_ie_len;
	u16 max_sched_scan_ie_len;
	u32 rts_threshold;
	char fw_version[ETHTOOL_FWVERS_LEN];
	const struct wiphy_wowlan_support *wowlan;
	u16 max_remain_on_channel_duration;
	u32 available_antennas_tx;
	u32 available_antennas_rx;
	const u8 *extended_capabilities, *extended_capabilities_mask;
	u8 extended_capabilities_len;
	const struct wiphy_iftype_ext_capab *iftype_ext_capab;
	unsigned int num_iftype_ext_capab;
	struct ieee80211_supported_band *bands[NUM_NL80211_BANDS];
	void (*reg_notifier)(struct wiphy *wiphy, struct regulatory_request *request);
	struct device dev;
	struct dentry *debugfsdir;
	struct { u64 peer, vif; } tid_config_support;
	const struct cfg80211_sar_capa *sar_capa;
};

static inline void wiphy_lock(struct wiphy *w) { mutex_lock(&w->mtx); }
static inline void wiphy_unlock(struct wiphy *w) { mutex_unlock(&w->mtx); }
#define lockdep_assert_wiphy(w) do { (void)(w); } while (0)
#define wiphy_dereference(w, p) (p)
static inline struct device *wiphy_dev(struct wiphy *w) { return w->dev.parent; }
static inline void wiphy_ext_feature_set(struct wiphy *w, enum nl80211_ext_feature_index i)
{ __set_bit(i, w->ext_features); }
static inline bool wiphy_ext_feature_isset(struct wiphy *w, enum nl80211_ext_feature_index i)
{ return test_bit(i, w->ext_features); }
/* shortcut: no rfkill switch on a USB dongle, add one if a radio-off button is wired up */
static inline void wiphy_rfkill_set_hw_state(struct wiphy *w, bool blocked) { (void)w; (void)blocked; }
static inline void wiphy_rfkill_start_polling(struct wiphy *w) { (void)w; }
static inline void wiphy_rfkill_stop_polling(struct wiphy *w) { (void)w; }

void wiphy_work_init(struct wiphy_work *work, wiphy_work_func_t func);
void wiphy_work_queue(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_work_cancel(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_work_flush(struct wiphy *wiphy, struct wiphy_work *work);
void wiphy_delayed_work_init(struct wiphy_delayed_work *dwork, wiphy_work_func_t func);
void wiphy_delayed_work_queue(struct wiphy *wiphy, struct wiphy_delayed_work *dwork, unsigned long delay);
void wiphy_delayed_work_cancel(struct wiphy *wiphy, struct wiphy_delayed_work *dwork);
void wiphy_delayed_work_flush(struct wiphy *wiphy, struct wiphy_delayed_work *dwork);
bool wiphy_delayed_work_pending(struct wiphy *wiphy, struct wiphy_delayed_work *dwork);

void cfg80211_chandef_create(struct cfg80211_chan_def *chandef, struct ieee80211_channel *channel,
			     enum nl80211_channel_type chantype);
u32 cfg80211_calculate_bitrate(struct rate_info *rate);
int cfg80211_get_ies_channel_number(const u8 *ie, size_t ielen, enum nl80211_band band);
void cfg80211_bss_iter(struct wiphy *wiphy, struct cfg80211_chan_def *chandef,
		       void (*iter)(struct wiphy *wiphy, struct cfg80211_bss *bss, void *data),
		       void *iter_data);
int regulatory_hint(struct wiphy *wiphy, const char *alpha2);
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band);
int ieee80211_frequency_to_channel(int freq);

static inline const struct element *cfg80211_find_elem(u8 eid, const u8 *ies, int len)
{
	while (len >= 2 && len >= 2 + ies[1]) {
		if (ies[0] == eid)
			return (const struct element *)ies;
		len -= 2 + ies[1];
		ies += 2 + ies[1];
	}
	return NULL;
}
static inline const u8 *cfg80211_find_ie(u8 eid, const u8 *ies, int len)
{ return (const u8 *)cfg80211_find_elem(eid, ies, len); }

static inline bool cfg80211_channel_is_psc(struct ieee80211_channel *chan)
{
	return chan->band == NL80211_BAND_6GHZ &&
	       ieee80211_frequency_to_channel(chan->center_freq) % 16 == 5;
}

/* ---------- mac80211 ---------- */
struct ieee80211_conf {
	u32 flags;
	struct cfg80211_chan_def chandef;
};

struct ieee80211_chan_req {
	struct cfg80211_chan_def oper;
};

struct ieee80211_mu_group_data {
	u8 membership[WLAN_MEMBERSHIP_LEN];
	u8 position[WLAN_USER_POSITION_LEN];
};

struct ieee80211_vif_cfg {
	bool assoc, ibss_joined;
	bool ps;
	u16 aid;
	__be32 arp_addr_list[IEEE80211_BSS_ARP_ADDR_LIST_LEN];
	int arp_addr_cnt;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	size_t ssid_len;
	u8 ap_addr[ETH_ALEN] __aligned(2);
};

struct ieee80211_bss_conf {
	struct ieee80211_vif *vif;
	const u8 *bssid;
	unsigned int link_id;
	u8 addr[ETH_ALEN] __aligned(2);
	bool he_support;
	bool use_short_slot;
	bool qos;
	u8 dtim_period;
	u16 beacon_int;
	u32 basic_rates;
	struct ieee80211_rate *beacon_rate;
	s32 cqm_rssi_thold;
	u32 cqm_rssi_hyst;
	struct ieee80211_chan_req chanreq;
	struct ieee80211_mu_group_data mu_group;
	struct ieee80211_p2p_noa_attr p2p_noa_attr;
	bool nontransmitted;
	u8 transmitter_bssid[ETH_ALEN];
	u8 bssid_index;
	struct { u32 params; u16 nss_set; } he_oper;
	struct cfg80211_he_bss_color he_bss_color;
	enum ieee80211_ap_reg_power power_type;
	struct ieee80211_parsed_tpe tpe;
	bool eht_support;
	bool csa_active;
};

struct ieee80211_vif {
	enum nl80211_iftype type;
	struct ieee80211_vif_cfg cfg;
	struct ieee80211_bss_conf bss_conf;
	struct ieee80211_bss_conf *link_conf[IEEE80211_MLD_MAX_NUM_LINKS];
	u16 valid_links, active_links, dormant_links, suspended_links;
	u8 addr[ETH_ALEN] __aligned(2);
	bool p2p;
	struct ieee80211_txq *txq;
	u32 driver_flags;
	bool probe_req_reg;
	u8 drv_priv[] __aligned(sizeof(void *));
};

static inline bool ieee80211_vif_is_mld(const struct ieee80211_vif *vif) { return vif->valid_links != 0; }
static inline u16 ieee80211_vif_usable_links(const struct ieee80211_vif *vif)
{ return vif->valid_links & ~vif->dormant_links; }

struct ieee80211_sta_aggregates {
	u16 max_amsdu_len;
	u16 max_rc_amsdu_len;
	u16 max_tid_amsdu_len[IEEE80211_NUM_TIDS];
};

struct ieee80211_sta_txpwr {
	s16 power;
	enum nl80211_tx_power_setting type;
};

struct ieee80211_link_sta {
	struct ieee80211_sta *sta;
	u8 addr[ETH_ALEN];
	u8 link_id;
	u32 supp_rates[NUM_NL80211_BANDS];
	struct ieee80211_sta_ht_cap ht_cap;
	struct ieee80211_sta_vht_cap vht_cap;
	struct ieee80211_sta_he_cap he_cap;
	struct ieee80211_he_6ghz_capa he_6ghz_capa;
	struct ieee80211_sta_eht_cap eht_cap;
	struct ieee80211_sta_aggregates agg;
	u8 rx_nss;
	enum ieee80211_sta_rx_bandwidth bandwidth;
	struct ieee80211_sta_txpwr txpwr;
};

struct ieee80211_sta_rates {
	struct rcu_head rcu_head;
	struct { s8 idx; u8 count, count_cts, count_rts; u16 flags; } rate[IEEE80211_TX_RATE_TABLE_SIZE];
};

struct ieee80211_sta {
	u8 addr[ETH_ALEN] __aligned(2);
	u16 aid;
	u16 max_rx_aggregation_subframes;
	bool wme;
	struct ieee80211_sta_rates *rates;
	bool tdls;
	bool mfp;
	bool mlo;
	u8 max_amsdu_subframes;
	struct ieee80211_txq *txq[IEEE80211_NUM_TIDS + 1];
	u16 valid_links;
	struct ieee80211_link_sta deflink;
	struct ieee80211_link_sta *link[IEEE80211_MLD_MAX_NUM_LINKS];
	u8 drv_priv[] __aligned(sizeof(void *));
};

struct ieee80211_txq {
	struct ieee80211_vif *vif;
	struct ieee80211_sta *sta;
	u8 tid;
	u8 ac;
	u8 drv_priv[] __aligned(sizeof(void *));
};

struct ieee80211_chanctx_conf {
	struct cfg80211_chan_def def;
	u8 drv_priv[] __aligned(sizeof(void *));
};

struct ieee80211_vif_chanctx_switch {
	struct ieee80211_vif *vif;
	struct ieee80211_bss_conf *link_conf;
	struct ieee80211_chanctx_conf *old_ctx;
	struct ieee80211_chanctx_conf *new_ctx;
};

struct ieee80211_key_conf {
	atomic64_t tx_pn;
	u32 cipher;
	u8 icv_len;
	u8 iv_len;
	u8 hw_key_idx;
	s8 keyidx;
	u16 flags;
	s8 link_id;
	u8 keylen;
	u8 key[];
};

struct ieee80211_tx_queue_params {
	u16 txop;
	u16 cw_min;
	u16 cw_max;
	u8 aifs;
	bool acm;
	bool uapsd;
	bool mu_edca;
	struct ieee80211_he_mu_edca_param_ac_rec mu_edca_param_rec;
};

struct ieee80211_ampdu_params {
	enum ieee80211_ampdu_mlme_action action;
	struct ieee80211_sta *sta;
	u16 tid;
	u16 ssn;
	u16 buf_size;
	bool amsdu;
	u16 timeout;
};

struct ieee80211_scan_ies {
	const u8 *ies[NUM_NL80211_BANDS];
	size_t len[NUM_NL80211_BANDS];
	const u8 *common_ies;
	size_t common_ie_len;
};

struct ieee80211_scan_request {
	struct ieee80211_scan_ies ies;
	struct cfg80211_scan_request req; /* ends in a flexible array */
};

struct ieee80211_tx_control {
	struct ieee80211_sta *sta;
};

struct ieee80211_tx_rate {
	s8 idx;
	u16 count:5, flags:11;
} __packed;

/* lives in skb->cb */
struct ieee80211_tx_info {
	u32 flags;
	u32 band:3, status_data_idr:1, status_data:13, hw_queue:4, tx_time_mc:1, tx_time_est:10;
	union {
		struct {
			struct ieee80211_tx_rate rates[IEEE80211_TX_MAX_RATES];
			struct ieee80211_vif *vif;
			struct ieee80211_key_conf *hw_key;
			u32 flags;
		} control;
		struct {
			struct ieee80211_tx_rate rates[IEEE80211_TX_MAX_RATES];
			s32 ack_signal;
			u16 tx_time;
			u8 flags;
			u8 link_valid:1, link_id:4;
		} status;
		void *driver_data[IEEE80211_TX_INFO_DRIVER_DATA_SIZE / sizeof(void *)];
	};
};

/* lives in skb->cb */
struct ieee80211_rx_status {
	u64 mactime;
	u64 boottime_ns;
	u32 ampdu_reference;
	u32 flag;
	u16 freq:13, freq_offset:1;
	u8 enc_flags;
	u8 encoding:3, bw:4;
	union {
		struct { u8 he_ru:3, he_gi:2, he_dcm:1; };
		struct { u8 ru:4, gi:2; } eht;
	};
	u8 rate_idx;
	u8 nss;
	u8 band;
	s8 signal;
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	u8 link_valid:1, link_id:4;
};

static inline struct ieee80211_tx_info *IEEE80211_SKB_CB(struct sk_buff *skb)
{
	_Static_assert(sizeof(struct ieee80211_tx_info) <= sizeof(skb->cb), "tx_info fits cb");
	return (struct ieee80211_tx_info *)skb->cb;
}
static inline struct ieee80211_rx_status *IEEE80211_SKB_RXCB(struct sk_buff *skb)
{
	_Static_assert(sizeof(struct ieee80211_rx_status) <= sizeof(skb->cb), "rx_status fits cb");
	return (struct ieee80211_rx_status *)skb->cb;
}
static inline void ieee80211_tx_info_clear_status(struct ieee80211_tx_info *info)
{
	for (int i = 0; i < IEEE80211_TX_MAX_RATES; i++)
		info->status.rates[i].count = 0;
	memset((u8 *)&info->status + offsetofend(__typeof__(info->status), rates), 0,
	       sizeof(info->status) - offsetofend(__typeof__(info->status), rates));
}

struct ieee80211_ops {
	void (*tx)(struct ieee80211_hw *hw, struct ieee80211_tx_control *control, struct sk_buff *skb);
	int (*start)(struct ieee80211_hw *hw);
	void (*stop)(struct ieee80211_hw *hw, bool suspend);
	int (*suspend)(struct ieee80211_hw *hw, struct cfg80211_wowlan *wowlan);
	int (*resume)(struct ieee80211_hw *hw);
	void (*set_wakeup)(struct ieee80211_hw *hw, bool enabled);
	int (*add_interface)(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
	int (*change_interface)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, enum nl80211_iftype new_type, bool p2p);
	void (*remove_interface)(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
	int (*config)(struct ieee80211_hw *hw, int radio_idx, u32 changed);
	void (*vif_cfg_changed)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u64 changed);
	void (*link_info_changed)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_bss_conf *info, u64 changed);
	int (*start_ap)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_bss_conf *link_conf);
	void (*stop_ap)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_bss_conf *link_conf);
	void (*configure_filter)(struct ieee80211_hw *hw, unsigned int changed_flags, unsigned int *total_flags, u64 multicast);
	int (*set_tim)(struct ieee80211_hw *hw, struct ieee80211_sta *sta, bool set);
	int (*set_key)(struct ieee80211_hw *hw, enum set_key_cmd cmd, struct ieee80211_vif *vif, struct ieee80211_sta *sta, struct ieee80211_key_conf *key);
	void (*set_rekey_data)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct cfg80211_gtk_rekey_data *data);
	int (*hw_scan)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_scan_request *req);
	void (*cancel_hw_scan)(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
	void (*sw_scan_start)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, const u8 *mac_addr);
	void (*sw_scan_complete)(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
	int (*set_rts_threshold)(struct ieee80211_hw *hw, int radio_idx, u32 value);
	int (*sta_state)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta, enum ieee80211_sta_state old_state, enum ieee80211_sta_state new_state);
	void (*link_sta_rc_update)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_link_sta *link_sta, u32 changed);
	void (*sta_statistics)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta, struct station_info *sinfo);
	int (*conf_tx)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, unsigned int link_id, u16 ac, const struct ieee80211_tx_queue_params *params);
	int (*ampdu_action)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_ampdu_params *params);
	int (*get_survey)(struct ieee80211_hw *hw, int idx, struct survey_info *survey);
	void (*rfkill_poll)(struct ieee80211_hw *hw);
	void (*flush)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u32 queues, bool drop);
	int (*set_antenna)(struct ieee80211_hw *hw, int radio_idx, u32 tx_ant, u32 rx_ant);
	int (*get_antenna)(struct ieee80211_hw *hw, int radio_idx, u32 *tx_ant, u32 *rx_ant);
	int (*remain_on_channel)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_channel *chan, int duration, enum ieee80211_roc_type type);
	int (*cancel_remain_on_channel)(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
	int (*set_bitrate_mask)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, const struct cfg80211_bitrate_mask *mask);
	int (*add_chanctx)(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx);
	void (*remove_chanctx)(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx);
	void (*change_chanctx)(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx, u32 changed);
	int (*assign_vif_chanctx)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_bss_conf *link_conf, struct ieee80211_chanctx_conf *ctx);
	void (*unassign_vif_chanctx)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_bss_conf *link_conf, struct ieee80211_chanctx_conf *ctx);
	int (*switch_vif_chanctx)(struct ieee80211_hw *hw, struct ieee80211_vif_chanctx_switch *vifs, int n_vifs, enum ieee80211_chanctx_switch_mode mode);
	void (*reconfig_complete)(struct ieee80211_hw *hw, enum ieee80211_reconfig_type reconfig_type);
	void (*channel_switch_beacon)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct cfg80211_chan_def *chandef);
	void (*wake_tx_queue)(struct ieee80211_hw *hw, struct ieee80211_txq *txq);
	int (*set_tid_config)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta, struct cfg80211_tid_config *tid_conf);
	int (*set_sar_specs)(struct ieee80211_hw *hw, const struct cfg80211_sar_specs *sar);
	bool (*can_activate_links)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 active_links);
	int (*change_vif_links)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 old_links, u16 new_links, struct ieee80211_bss_conf *old[IEEE80211_MLD_MAX_NUM_LINKS]);
	int (*change_sta_links)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta, u16 old_links, u16 new_links);
};

struct ieee80211_hw {
	struct ieee80211_conf conf;
	struct wiphy *wiphy;
	void *priv;
	unsigned long flags[BITS_TO_LONGS(NUM_IEEE80211_HW_FLAGS)];
	unsigned int extra_tx_headroom;
	int vif_data_size;
	int sta_data_size;
	int chanctx_data_size;
	int txq_data_size;
	u16 queues;
	u16 max_rx_aggregation_subframes;
	u16 max_tx_aggregation_subframes;
	u8 max_rx_aggregation_subframes_unused;
	u8 radiotap_mcs_details;
	u16 radiotap_vht_details;
	struct { int units_pos; s16 accuracy; } radiotap_timestamp;
	u8 uapsd_queues;
	u8 uapsd_max_sp_len;
	s8 max_signal;
};

#define ieee80211_hw_set(hw, flg) __set_bit(IEEE80211_HW_##flg, (hw)->flags)
#define ieee80211_hw_check(hw, flg) test_bit(IEEE80211_HW_##flg, (hw)->flags)
#define SET_IEEE80211_DEV(hw, d) ((hw)->wiphy->dev.parent = (d))
#define SET_IEEE80211_PERM_ADDR(hw, a) memcpy((hw)->wiphy->perm_addr, (a), ETH_ALEN)

/* ---------- frame helpers (frame_control is little endian on the air and on this host) ---------- */
#define __lkpi_fc_is(fc, mask, val) (((fc) & (mask)) == (val))
static inline bool ieee80211_has_tods(__le16 fc) { return fc & IEEE80211_FCTL_TODS; }
static inline bool ieee80211_has_fromds(__le16 fc) { return fc & IEEE80211_FCTL_FROMDS; }
static inline bool ieee80211_has_a4(__le16 fc)
{ return __lkpi_fc_is(fc, IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS, IEEE80211_FCTL_TODS | IEEE80211_FCTL_FROMDS); }
static inline bool ieee80211_has_pm(__le16 fc) { return fc & IEEE80211_FCTL_PM; }
static inline bool ieee80211_has_protected(__le16 fc) { return fc & IEEE80211_FCTL_PROTECTED; }
static inline bool ieee80211_has_morefrags(__le16 fc) { return fc & IEEE80211_FCTL_MOREFRAGS; }
static inline bool ieee80211_has_order(__le16 fc) { return fc & IEEE80211_FCTL_ORDER; }
static inline bool ieee80211_is_mgmt(__le16 fc) { return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE, IEEE80211_FTYPE_MGMT); }
static inline bool ieee80211_is_ctl(__le16 fc) { return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE, IEEE80211_FTYPE_CTL); }
static inline bool ieee80211_is_data(__le16 fc) { return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE, IEEE80211_FTYPE_DATA); }
static inline bool ieee80211_is_data_qos(__le16 fc)
{ return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA, IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA); }
static inline bool ieee80211_is_data_present(__le16 fc)
{ return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE | 0x40, IEEE80211_FTYPE_DATA); }
#define __LKPI_IS_STYPE(name, ft, st) \
	static inline bool ieee80211_is_##name(__le16 fc) \
	{ return __lkpi_fc_is(fc, IEEE80211_FCTL_FTYPE | IEEE80211_FCTL_STYPE, IEEE80211_FTYPE_##ft | IEEE80211_STYPE_##st); }
__LKPI_IS_STYPE(assoc_req, MGMT, ASSOC_REQ)
__LKPI_IS_STYPE(assoc_resp, MGMT, ASSOC_RESP)
__LKPI_IS_STYPE(reassoc_req, MGMT, REASSOC_REQ)
__LKPI_IS_STYPE(reassoc_resp, MGMT, REASSOC_RESP)
__LKPI_IS_STYPE(probe_req, MGMT, PROBE_REQ)
__LKPI_IS_STYPE(probe_resp, MGMT, PROBE_RESP)
__LKPI_IS_STYPE(beacon, MGMT, BEACON)
__LKPI_IS_STYPE(disassoc, MGMT, DISASSOC)
__LKPI_IS_STYPE(auth, MGMT, AUTH)
__LKPI_IS_STYPE(deauth, MGMT, DEAUTH)
__LKPI_IS_STYPE(action, MGMT, ACTION)
__LKPI_IS_STYPE(pspoll, CTL, PSPOLL)
__LKPI_IS_STYPE(trigger, CTL, TRIGGER)
__LKPI_IS_STYPE(back_req, CTL, BACK_REQ)
__LKPI_IS_STYPE(nullfunc, DATA, NULLFUNC)
__LKPI_IS_STYPE(qos_nullfunc, DATA, QOS_NULLFUNC)
static inline bool ieee80211_is_any_nullfunc(__le16 fc) { return ieee80211_is_nullfunc(fc) || ieee80211_is_qos_nullfunc(fc); }

static inline unsigned int ieee80211_hdrlen(__le16 fc)
{
	unsigned int len;

	if (ieee80211_is_mgmt(fc))
		return 24 + (ieee80211_has_order(fc) ? IEEE80211_HT_CTL_LEN : 0);
	if (ieee80211_is_data(fc)) {
		len = ieee80211_has_a4(fc) ? 30 : 24;
		if (ieee80211_is_data_qos(fc))
			len += IEEE80211_QOS_CTL_LEN + (ieee80211_has_order(fc) ? IEEE80211_HT_CTL_LEN : 0);
		return len;
	}
	/* control frames: CTS and ACK are 10 bytes, the rest carry a TA */
	return (fc & 0x00E0) == 0x00C0 ? 10 : 16;
}
static inline u8 *ieee80211_get_qos_ctl(struct ieee80211_hdr *hdr)
{ return (u8 *)hdr + (ieee80211_has_a4(hdr->frame_control) ? 30 : 24); }
static inline u8 ieee80211_get_tid(struct ieee80211_hdr *hdr)
{ return ieee80211_get_qos_ctl(hdr)[0] & IEEE80211_QOS_CTL_TID_MASK; }
static inline u16 ieee80211_get_sn(struct ieee80211_hdr *hdr) { return (hdr->seq_ctrl & IEEE80211_SCTL_SEQ) >> 4; }
static inline bool ieee80211_sn_less(u16 a, u16 b)
{ return ((a - b) & IEEE80211_SN_MASK) > (IEEE80211_SN_MODULO >> 1); }
static inline u16 ieee80211_sn_inc(u16 sn) { return (sn + 1) & IEEE80211_SN_MASK; }
static inline u16 ieee80211_sn_sub(u16 a, u16 b) { return (a - b) & IEEE80211_SN_MASK; }
static inline unsigned long ieee80211_tu_to_usec(unsigned long tu) { return tu * 1024; }

/* ---------- mac80211 entry points (src/lkpi/mac80211.c) ---------- */
struct ieee80211_hw *ieee80211_alloc_hw(size_t priv_data_len, const struct ieee80211_ops *ops);
int ieee80211_register_hw(struct ieee80211_hw *hw);
void ieee80211_unregister_hw(struct ieee80211_hw *hw);
void ieee80211_free_hw(struct ieee80211_hw *hw);
/* lkpi: bring the single station interface up (start + add_interface) / down */
int lkpi80211_up(struct ieee80211_hw *hw);
void lkpi80211_down(struct ieee80211_hw *hw);
struct ieee80211_hw *wiphy_to_ieee80211_hw(struct wiphy *wiphy);
void ieee80211_restart_hw(struct ieee80211_hw *hw);
void ieee80211_queue_work(struct ieee80211_hw *hw, struct work_struct *work);
void ieee80211_queue_delayed_work(struct ieee80211_hw *hw, struct delayed_work *dwork, unsigned long delay);
void ieee80211_stop_queues(struct ieee80211_hw *hw);
void ieee80211_wake_queues(struct ieee80211_hw *hw);

void ieee80211_rx_napi(struct ieee80211_hw *hw, struct ieee80211_link_sta *link_sta, struct sk_buff *skb,
		       struct napi_struct *napi);
void ieee80211_tx_status_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb);
void ieee80211_free_txskb(struct ieee80211_hw *hw, struct sk_buff *skb);
void ieee80211_purge_tx_queue(struct ieee80211_hw *hw, struct sk_buff_head *skbs);

struct ieee80211_txq *ieee80211_next_txq(struct ieee80211_hw *hw, u8 ac);
void ieee80211_return_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq, bool force);
void ieee80211_schedule_txq(struct ieee80211_hw *hw, struct ieee80211_txq *txq);
void ieee80211_txq_schedule_start(struct ieee80211_hw *hw, u8 ac);
void ieee80211_txq_schedule_end(struct ieee80211_hw *hw, u8 ac);
struct sk_buff *ieee80211_tx_dequeue_ni(struct ieee80211_hw *hw, struct ieee80211_txq *txq);
void ieee80211_txq_get_depth(struct ieee80211_txq *txq, unsigned long *frame_cnt, unsigned long *byte_cnt);

void ieee80211_iterate_active_interfaces_atomic(struct ieee80211_hw *hw, u32 iter_flags,
						void (*iterator)(void *data, u8 *mac, struct ieee80211_vif *vif),
						void *data);
void ieee80211_iterate_stations_atomic(struct ieee80211_hw *hw,
				       void (*iterator)(void *data, struct ieee80211_sta *sta), void *data);
void ieee80211_iter_keys(struct ieee80211_hw *hw, struct ieee80211_vif *vif,
			 void (*iter)(struct ieee80211_hw *hw, struct ieee80211_vif *vif, struct ieee80211_sta *sta,
				      struct ieee80211_key_conf *key, void *data),
			 void *iter_data);
struct ieee80211_sta *ieee80211_find_sta(struct ieee80211_vif *vif, const u8 *addr);
struct ieee80211_sta *__ieee80211_iterate_stations(struct ieee80211_hw *hw, struct ieee80211_sta *prev);
#define for_each_station(sta, hw) \
	for (sta = __ieee80211_iterate_stations(hw, NULL); sta; sta = __ieee80211_iterate_stations(hw, sta))

void ieee80211_scan_completed(struct ieee80211_hw *hw, struct cfg80211_scan_info *info);
void ieee80211_ready_on_channel(struct ieee80211_hw *hw);
void ieee80211_remain_on_channel_expired(struct ieee80211_hw *hw);
void ieee80211_beacon_loss(struct ieee80211_vif *vif);
void ieee80211_connection_loss(struct ieee80211_vif *vif);
void ieee80211_cqm_rssi_notify(struct ieee80211_vif *vif, enum nl80211_cqm_rssi_threshold_event rssi_event,
			       s32 rssi_level, gfp_t gfp);
void ieee80211_csa_finish(struct ieee80211_vif *vif, unsigned int link_id);
bool ieee80211_beacon_cntdwn_is_complete(struct ieee80211_vif *vif, unsigned int link_id);
int ieee80211_set_active_links(struct ieee80211_vif *vif, u16 active_links);

struct sk_buff *ieee80211_beacon_get_tim(struct ieee80211_hw *hw, struct ieee80211_vif *vif, u16 *tim_offset,
					 u16 *tim_length, unsigned int link_id);
struct sk_buff *ieee80211_nullfunc_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif, int link_id, bool qos_ok);
struct sk_buff *ieee80211_probereq_get(struct ieee80211_hw *hw, const u8 *src_addr, const u8 *ssid,
				       size_t ssid_len, size_t tailroom);
struct sk_buff *ieee80211_proberesp_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif);
struct sk_buff *ieee80211_pspoll_get(struct ieee80211_hw *hw, struct ieee80211_vif *vif);

int ieee80211_start_tx_ba_session(struct ieee80211_sta *sta, u16 tid, u16 timeout);
int ieee80211_stop_tx_ba_session(struct ieee80211_sta *sta, u16 tid);
void ieee80211_start_tx_ba_cb_irqsafe(struct ieee80211_vif *vif, const u8 *ra, u16 tid);
void ieee80211_stop_tx_ba_cb_irqsafe(struct ieee80211_vif *vif, const u8 *ra, u16 tid);
void ieee80211_sta_ps_transition(struct ieee80211_sta *sta, bool start);
void ieee80211_sta_pspoll(struct ieee80211_sta *sta);
void ieee80211_sta_uapsd_trigger(struct ieee80211_sta *sta, u8 tid);
void ieee80211_sta_recalc_aggregates(struct ieee80211_sta *sta);

int ieee80211_emulate_add_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx);
void ieee80211_emulate_remove_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx);
void ieee80211_emulate_change_chanctx(struct ieee80211_hw *hw, struct ieee80211_chanctx_conf *ctx, u32 changed);
int ieee80211_emulate_switch_vif_chanctx(struct ieee80211_hw *hw, struct ieee80211_vif_chanctx_switch *vifs,
					 int n_vifs, enum ieee80211_chanctx_switch_mode mode);
