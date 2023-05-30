/*	$NetBSD: if_runvar.h,v 1.9 2020/06/06 13:53:43 gson Exp $	*/
/*	$OpenBSD: if_runvar.h,v 1.8 2010/02/08 18:46:47 damien Exp $	*/

/*-
 * Copyright (c) 2008,2009 Damien Bergamini <damien.bergamini@free.fr>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define RUN_MAX_RXSZ			\
	4096
#if 0
	(sizeof(uint32_t) +		\
	 sizeof(struct rt2860_rxwi) +	\
	 sizeof(uint16_t) +		\
	 MCLBYTES +			\
	 sizeof(struct rt2870_rxd))
#endif
/* NB: "11" is the maximum number of padding bytes needed for Tx */
#define RUN_MAX_TXSZ			\
	(sizeof(struct rt2870_txd) +	\
	 sizeof(struct rt2860_txwi) +	\
	 MCLBYTES + 11)

#define RUN_TX_TIMEOUT	5000	/* ms */

#define RUN_RX_RING_COUNT	1
#define RUN_TX_RING_COUNT	8

#define RT2870_WCID_MAX		64
#define RUN_AID2WCID(aid)	((aid) & 0xff)

struct run_rx_radiotap_header {
	struct ieee80211_radiotap_header wr_ihdr;
	uint8_t		wr_flags;
	uint8_t		wr_rate;
	uint16_t	wr_chan_freq;
	uint16_t	wr_chan_flags;
	uint8_t		wr_dbm_antsignal;
	uint8_t		wr_antenna;
	uint8_t		wr_antsignal;
};

#define RUN_RX_RADIOTAP_PRESENT				\
	(1 << IEEE80211_RADIOTAP_FLAGS |		\
	 1 << IEEE80211_RADIOTAP_RATE |			\
	 1 << IEEE80211_RADIOTAP_CHANNEL |		\
	 1 << IEEE80211_RADIOTAP_DBM_ANTSIGNAL |	\
	 1 << IEEE80211_RADIOTAP_ANTENNA |		\
	 1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)

#define	RUN_VAP_MAX	8

struct run_tx_radiotap_header {
	struct ieee80211_radiotap_header wt_ihdr;
	uint8_t		wt_flags;
	uint8_t		wt_rate;
	uint16_t	wt_chan_freq;
	uint16_t	wt_chan_flags;
	uint8_t		wt_hwqueue;
};

#define RUN_TX_RADIOTAP_PRESENT				\
	(1 << IEEE80211_RADIOTAP_FLAGS |		\
	 1 << IEEE80211_RADIOTAP_RATE |			\
	 1 << IEEE80211_RADIOTAP_CHANNEL/* |		\
	 1 << IEEE80211_RADIOTAP_HWQUEUE*/)

struct run_softc;

struct run_host_cmd {
	void	(*cb)(struct run_softc *, void *);
	uint8_t	data[256];
};

struct run_cmd_newstate {
	enum ieee80211_state	state;
	int			arg;
};

struct run_cmd_key {
	struct ieee80211_key	key;
	uint16_t		associd;
};

#define RUN_HOST_CMD_RING_COUNT	32
struct run_host_cmd_ring {
	struct run_host_cmd	cmd[RUN_HOST_CMD_RING_COUNT];
	int			cur;
	int			next;
	int			queued;
};

struct run_node {
	struct ieee80211_node	ni;
	uint8_t			amrr_ridx;
	uint8_t			mgt_ridx;
	uint8_t			fix_ridx;
};

#define	RUN_MAXEPOUT	4

struct run_softc {
	struct usbwifi			sc_uw;
	struct ieee80211_ratectl_tx_stats	 sc_txs;
	/* bits used in sc_uw.uw_flags */
#define RUN_FWLOADED		__BIT(0)
#define RUN_USE_BLOCK_WRITE	__BIT(1)

	uint16_t			wcid_stats[RT2870_WCID_MAX + 1][3];
#define RUN_TXCNT	0
#define RUN_SUCCESS	1
#define RUN_RETRY	2

	int				(*sc_srom_read)(struct run_softc *,
					    uint16_t, uint16_t *);
	uint16_t			mac_ver;
	uint16_t			mac_rev;
	uint16_t			rf_rev;
	uint8_t				freq;
	uint8_t				ntxchains;
	uint8_t				nrxchains;
	uint8_t				fifo_cnt;

	uint8_t				bbp25;
	uint8_t				bbp26;
	uint8_t				rf24_20mhz;
	uint8_t				rf24_40mhz;
	uint8_t				patch_dac;
	uint8_t				rfswitch;
	uint8_t				ext_2ghz_lna;
	uint8_t				ext_5ghz_lna;
	uint8_t				calib_2ghz;
	uint8_t				calib_5ghz;
	uint8_t				txmixgain_2ghz;
	uint8_t				txmixgain_5ghz;
	int8_t				txpow1[54];
	int8_t				txpow2[54];
	int8_t				txpow3[54];
	int8_t				rssi_2ghz[3];
	int8_t				rssi_5ghz[3];
	uint8_t				lna[4];

	struct {
		uint8_t	reg;
		uint8_t	val;
	}				bbp[10], rf[10];
	uint8_t				leds;
	uint16_t			led[3];
	uint32_t			txpow20mhz[5];
	uint32_t			txpow40mhz_2ghz[5];
	uint32_t			txpow40mhz_5ghz[5];

	struct usb_task			sc_task;
	unsigned int			rvp_cnt;
	uint8_t				rvp_bmap;
	uint8_t				ratectl_run;
#define	RUN_RATECTL_OFF	0
	callout_t			ratectl_to;
	
	struct run_host_cmd_ring	cmdq;
	int				sc_tx_timer;
	struct ieee80211_beacon_offsets	sc_bo;

	union {
		struct run_rx_radiotap_header th;
		uint8_t	pad[64];
	}				sc_rxtapu;
#define sc_rxtap	sc_rxtapu.th
	int				sc_rxtap_len;

	union {
		struct run_tx_radiotap_header th;
		uint8_t	pad[64];
	}				sc_txtapu;
#define sc_txtap	sc_txtapu.th
	int				sc_txtap_len;
};
