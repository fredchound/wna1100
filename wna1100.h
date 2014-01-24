struct ath9k_htc_priv {
//	struct device *dev;
	struct ieee80211_hw *hw;
/*
	struct ath_hw *ah;
	struct htc_target *htc;
	struct wmi *wmi;

	u16 fw_version_major;
	u16 fw_version_minor;

	enum htc_endpoint_id wmi_cmd_ep;
	enum htc_endpoint_id beacon_ep;
	enum htc_endpoint_id cab_ep;
	enum htc_endpoint_id uapsd_ep;
	enum htc_endpoint_id mgmt_ep;
	enum htc_endpoint_id data_be_ep;
	enum htc_endpoint_id data_bk_ep;
	enum htc_endpoint_id data_vi_ep;
	enum htc_endpoint_id data_vo_ep;

	u8 vif_slot;
	u8 mon_vif_idx;
	u8 sta_slot;
	u8 vif_sta_pos[ATH9K_HTC_MAX_VIF];
	u8 num_ibss_vif;
	u8 num_mbss_vif;
	u8 num_sta_vif;
	u8 num_sta_assoc_vif;
	u8 num_ap_vif;

	u16 curtxpow;
	u16 txpowlimit;
	u16 nvifs;
	u16 nstations;
	bool rearm_ani;
	bool reconfig_beacon;
	unsigned int rxfilter;
	unsigned long op_flags;

	struct ath9k_hw_cal_data caldata;
	struct ieee80211_supported_band sbands[IEEE80211_NUM_BANDS];

	spinlock_t beacon_lock;
	struct htc_beacon_config cur_beacon_conf;

	struct ath9k_htc_rx rx;
	struct ath9k_htc_tx tx;

	struct tasklet_struct swba_tasklet;
	struct tasklet_struct rx_tasklet;
	struct delayed_work ani_work;
	struct tasklet_struct tx_failed_tasklet;
	struct work_struct ps_work;
	struct work_struct fatal_work;

	struct mutex htc_pm_lock;
	unsigned long ps_usecount;
	bool ps_enabled;
	bool ps_idle;

#ifdef CONFIG_MAC80211_LEDS
	enum led_brightness brightness;
	bool led_registered;
	char led_name[32];
	struct led_classdev led_cdev;
	struct work_struct led_work;
#endif

	int beaconq;
	int cabq;
	int hwq_map[IEEE80211_NUM_ACS];

#ifdef CONFIG_ATH9K_BTCOEX_SUPPORT
	struct ath_btcoex btcoex;
#endif

	struct delayed_work coex_period_work;
	struct delayed_work duty_cycle_work;
#ifdef CONFIG_ATH9K_HTC_DEBUGFS
	struct ath9k_debug debug;
#endif
	struct mutex mutex;
*/
};

