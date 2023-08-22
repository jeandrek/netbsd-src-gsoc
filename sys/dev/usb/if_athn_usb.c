/*	$NetBSD: if_athn_usb.c,v 1.38 2020/03/14 02:35:33 christos Exp $	*/
/*	$OpenBSD: if_athn_usb.c,v 1.12 2013/01/14 09:50:31 jsing Exp $	*/

/*-
 * Copyright (c) 2011 Damien Bergamini <damien.bergamini@free.fr>
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

/*
 * USB front-end for Atheros AR9271 and AR7010 chipsets.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: if_athn_usb.c,v 1.38 2020/03/14 02:35:33 christos Exp $");

#ifdef	_KERNEL_OPT
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/device.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/kmem.h>

#include <sys/bus.h>
#include <sys/endian.h>
#include <sys/intr.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/if_inarp.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_amrr.h>
#include <net80211/ieee80211_radiotap.h>

#include <dev/firmload.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdevs.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdi_util.h>

#include <dev/usb/usbwifi.h>

#include <dev/ic/athnreg.h>
#include <dev/ic/athnvar.h>
#include <dev/ic/arn9285.h>
#include <dev/usb/if_athn_usb.h>

#define ATHN_USB_SOFTC(ac)	((struct athn_usb_softc *)(ac))
#define ATHN_USB_NODE(ni)	((struct athn_usb_node *)(ni))

#define athn_usb_wmi_cmd(ac, cmd_id) \
	athn_usb_wmi_xcmd(ac, cmd_id, NULL, 0, NULL)

//Static int	athn_usb_activate(device_t, enum devact);
Static int	athn_usb_detach(device_t, int);
Static int	athn_usb_match(device_t, cfdata_t, void *);
Static void	athn_usb_attach(device_t, device_t, void *);

CFATTACH_DECL_NEW(athn_usb, sizeof(struct athn_usb_softc), athn_usb_match,
    athn_usb_attach, athn_usb_detach, usbwifi_activate);

Static int	athn_usb_alloc_tx_cmd(struct athn_usb_softc *);
Static int	athn_usb_alloc_tx_msg(struct athn_usb_softc *);
Static void	athn_usb_attachhook(device_t);
#ifdef notyet
Static void	athn_usb_bcneof(struct usbd_xfer *, void *,
		    usbd_status);
#endif
Static void	athn_usb_abort_pipes(struct athn_usb_softc *);
Static void	athn_usb_close_pipes(struct athn_usb_softc *);
Static int	athn_usb_create_hw_node(struct athn_usb_softc *,
		    struct ar_htc_target_sta *);
Static int	athn_usb_create_node(struct athn_usb_softc *,
		    struct ieee80211_node *);
Static void	athn_usb_do_async(struct athn_usb_softc *,
		    void (*)(struct athn_usb_softc *, void *), void *, int);
Static void	athn_usb_free_tx_cmd(struct athn_usb_softc *);
Static void	athn_usb_free_tx_msg(struct athn_usb_softc *);
Static int	athn_usb_htc_connect_svc(struct athn_usb_softc *, uint16_t,
		    uint8_t, uint8_t, uint8_t *);
Static int	athn_usb_htc_msg(struct athn_usb_softc *, uint16_t, void *,
		    int);
Static int	athn_usb_htc_setup(struct athn_usb_softc *);
//Static int	athn_usb_init(struct athn_usb_softc *);
Static int	athn_usb_init_locked(struct usbwifi *);
Static void	athn_usb_intr(struct usbwifi *, usbd_status, uint32_t);
Static int	athn_usb_load_firmware(struct athn_usb_softc *);
Static const struct athn_usb_type *
		athn_usb_lookup(int, int);
//Static int	athn_usb_media_change(struct ifnet *);
Static void	athn_usb_newassoc(struct ieee80211_node *, int);
Static void	athn_usb_newassoc_cb(struct athn_usb_softc *, void *);
Static int	athn_usb_newstate(struct ieee80211vap *, enum ieee80211_state,
		    int);
Static void	athn_usb_newstate_cb(struct ieee80211vap *, void *);
Static void	athn_usb_node_cleanup(struct ieee80211_node *);
Static void	athn_usb_node_cleanup_cb(struct athn_usb_softc *, void *);
Static int	athn_usb_configure_pipes(struct athn_usb_softc *);
Static uint32_t	athn_usb_read(struct athn_common *, uint32_t);
Static int	athn_usb_remove_hw_node(struct athn_usb_softc *, uint8_t *);
Static void	athn_usb_rx_enable(struct athn_softc *);
Static void	athn_usb_rx_frame(struct athn_usb_softc *, struct mbuf *);
//Static void	athn_usb_rx_radiotap(struct athn_softc *, struct mbuf *,
//		    struct ar_rx_status *);
Static void	athn_usb_rx_wmi_ctrl(struct athn_usb_softc *, uint8_t *, size_t);
Static void	athn_usb_rx_loop(struct usbwifi *, struct usbwifi_chain *,
		    uint32_t);
Static void	athn_usb_stop(struct athn_usb_softc *, int disable);
Static void	athn_usb_stop_locked(struct usbwifi *);
#ifdef notyet
Static void	athn_usb_swba(struct athn_usb_softc *);
#endif
Static int	athn_usb_switch_chan(struct athn_softc *,
		    struct ieee80211_channel *, struct ieee80211_channel *);
Static void	athn_usb_task(void *);
Static unsigned	athn_usb_tx_prepare(struct usbwifi *, struct usbwifi_chain *,
		    uint8_t qid);
//Static void	athn_usb_txeof(struct usbd_xfer *, void *,
//		    usbd_status);
Static void	athn_usb_updateslot(struct ieee80211com *);
Static void	athn_usb_updateslot_cb(struct athn_usb_softc *, void *);
Static void	athn_usb_wait_async(struct athn_usb_softc *);
Static int	athn_usb_wait_msg(struct athn_usb_softc *);
//Static void	athn_usb_watchdog(struct ifnet *);
Static void	athn_usb_set_multi(struct ieee80211com *);
Static void	athn_usb_set_channel(struct ieee80211com *);
Static int	athn_usb_wmi_xcmd(struct athn_usb_softc *, uint16_t, void *,
		    int, void *);
Static void	athn_usb_wmieof(struct usbd_xfer *, void *,
		    usbd_status);
Static void	athn_usb_write(struct athn_common *, uint32_t, uint32_t);
Static void	athn_usb_write_barrier(struct athn_usb_softc *);
Static void	athn_usb_get_radiocaps(struct ieee80211com *, int, int *,
		    struct ieee80211_channel []);
Static struct ieee80211vap *
		athn_usb_vap_create(struct ieee80211com *,  const char [IFNAMSIZ],
		    int, enum ieee80211_opmode, int,
		    const uint8_t [IEEE80211_ADDR_LEN],
		    const uint8_t [IEEE80211_ADDR_LEN]);

/************************************************************************
 * unused/notyet declarations
 */
#ifdef unused
Static int	athn_usb_read_rom(struct athn_softc *);
#endif /* unused */

#ifdef notyet_edca
Static void	athn_usb_updateedca(struct ieee80211com *);
Static void	athn_usb_updateedca_cb(struct athn_usb_softc *, void *);
#endif /* notyet_edca */

#ifdef notyet
Static int	athn_usb_ampdu_tx_start(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
Static void	athn_usb_ampdu_tx_start_cb(struct athn_usb_softc *, void *);
Static void	athn_usb_ampdu_tx_stop(struct ieee80211com *,
		    struct ieee80211_node *, uint8_t);
Static void	athn_usb_ampdu_tx_stop_cb(struct athn_usb_softc *, void *);
Static void	athn_usb_delete_key(struct ieee80211com *,
		    struct ieee80211_node *, struct ieee80211_key *);
Static void	athn_usb_delete_key_cb(struct athn_usb_softc *, void *);
Static int	athn_usb_set_key(struct ieee80211com *,
		    struct ieee80211_node *, struct ieee80211_key *);
Static void	athn_usb_set_key_cb(struct athn_usb_softc *, void *);
#endif /* notyet */
/************************************************************************/

static const struct usbwifi_ops athn_usb_ops = {
	.uwo_stop = athn_usb_stop_locked,
	.uwo_init = athn_usb_init_locked,
	.uwo_rx_loop = athn_usb_rx_loop,
	.uwo_tx_prepare = athn_usb_tx_prepare,
	.uwo_intr = athn_usb_intr
};

struct athn_usb_type {
	struct usb_devno	devno;
	u_int			flags;
};

Static const struct athn_usb_type *
athn_usb_lookup(int vendor, int product)
{
	static const struct athn_usb_type athn_usb_devs[] = {
#define _D(v,p,f) \
		{{ USB_VENDOR_##v, USB_PRODUCT_##p }, ATHN_USB_FLAG_##f }

		_D( ACCTON,	ACCTON_AR9280,		AR7010 ),
		_D( ACTIONTEC,	ACTIONTEC_AR9287,	AR7010 ),
		_D( ATHEROS2,	ATHEROS2_AR9271_1,	NONE ),
		_D( ATHEROS2,	ATHEROS2_AR9271_2,	NONE ),
		_D( ATHEROS2,	ATHEROS2_AR9271_3,	NONE ),
		_D( ATHEROS2,	ATHEROS2_AR9280,	AR7010 ),
		_D( ATHEROS2,	ATHEROS2_AR9287,	AR7010 ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_1,	NONE ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_2,	NONE ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_3,	NONE ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_4,	NONE ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_5,	NONE ),
		_D( AZUREWAVE,	AZUREWAVE_AR9271_6,	NONE ),
		_D( DLINK2,	DLINK2_AR9271,	  	NONE ),
		_D( LITEON,	LITEON_AR9271,	  	NONE ),
		_D( NETGEAR,	NETGEAR_WNA1100,	NONE ),
		_D( NETGEAR,	NETGEAR_WNDA3200,	AR7010 ),
		_D( VIA,	VIA_AR9271,		NONE ),
		_D( MELCO,	MELCO_CEWL_1,		AR7010 ),
		_D( PANASONIC,	PANASONIC_N5HBZ0000055,	AR7010 ),
#undef _D
	};

	return (const void *)usb_lookup(athn_usb_devs, vendor, product);
}

Static int
athn_usb_match(device_t parent, cfdata_t match, void *aux)
{
	struct usb_attach_arg *uaa = aux;

	return athn_usb_lookup(uaa->uaa_vendor, uaa->uaa_product) != NULL ?
	    UMATCH_VENDOR_PRODUCT : UMATCH_NONE;
}

Static void
athn_usb_attach(device_t parent, device_t self, void *aux)
{
	struct athn_usb_softc *usc;
	struct athn_common *ac;
	struct usb_attach_arg *uaa;
	int error;

	usc = device_private(self);
	ac = &usc->usc_ac;
	uaa = aux;
	ac->ac_dev = self;
	ac->ac_ic = usbwifi_ic(&usc->usc_uw);
	ac->ac_softc = usc;
	usc->usc_uw.uw_ac = usc;
	usc->usc_uw.uw_dev = self;
	usc->usc_uw.uw_udev = uaa->uaa_device;
	usc->usc_uw.uw_ops = &athn_usb_ops;
	usc->usc_uw.uw_rx_bufsz = ATHN_USB_RXBUFSZ;
	usc->usc_uw.uw_tx_bufsz = ATHN_USB_TXBUFSZ;
	usc->usc_uw.uw_rx_list_cnt = ATHN_USB_RX_LIST_COUNT;
	usc->usc_uw.uw_tx_list_cnt = ATHN_USB_TX_LIST_COUNT;
	usbwifi_attach(&usc->usc_uw);

	aprint_naive("\n");
	aprint_normal("\n");

	DPRINTFN(DBG_FN, ac, "\n");

	usc->usc_init_state = ATHN_INIT_NONE;
	usc->usc_athn_attached = 0;
	usc->usc_flags = athn_usb_lookup(uaa->uaa_vendor, uaa->uaa_product)->flags;
	ac->ac_flags |= ATHN_FLAG_USB;
#ifdef notyet
	/* Check if it is a combo WiFi+Bluetooth (WB193) device. */
	if (strncmp(product, "wb193", 5) == 0)
		ac->ac_flags |= ATHN_FLAG_BTCOEX3WIRE;
#endif

	ac->ac_ops.read = athn_usb_read;
	ac->ac_ops.write = athn_usb_write;
	ac->ac_ops.write_barrier = athn_usb_write_barrier;

	//mutex_init(&usc->usc_lock, MUTEX_DEFAULT, IPL_NONE);

	cv_init(&usc->usc_wmi_cv, "athnwmi");
	cv_init(&usc->usc_htc_cv, "athnhtc");

	cv_init(&usc->usc_cmd_cv, "athncmd");
	mutex_init(&usc->usc_cmd_mtx, MUTEX_DEFAULT, IPL_SOFTUSB);
	cv_init(&usc->usc_msg_cv, "athnmsg");
	mutex_init(&usc->usc_msg_mtx, MUTEX_DEFAULT, IPL_SOFTUSB);

	cv_init(&usc->usc_task_cv, "athntsk");
	mutex_init(&usc->usc_task_mtx, MUTEX_DEFAULT, IPL_NET);
	mutex_init(&usc->usc_tx_mtx, MUTEX_DEFAULT, IPL_NONE);

	usb_init_task(&usc->usc_task, athn_usb_task, usc, 0);

	if (usbd_set_config_no(usc->usc_uw.uw_udev, 1, 0) != 0) {
		aprint_error_dev(ac->ac_dev,
		    "could not set configuration no\n");
		goto fail;
	}

	/* Get the first interface handle. */
	error = usbd_device2interface_handle(usc->usc_uw.uw_udev, 0, &usc->usc_uw.uw_iface);
	if (error != 0) {
		aprint_error_dev(ac->ac_dev,
		    "could not get interface handle\n");
		goto fail;
	}

	if (athn_usb_configure_pipes(usc) != 0)
		goto fail;

	/* Allocate xfer for firmware commands. */
	if (athn_usb_alloc_tx_cmd(usc) != 0)
		goto fail;

	/* Allocate xfer for firmware commands. */
	if (athn_usb_alloc_tx_msg(usc) != 0)
		goto fail;

	config_mountroot(self, athn_usb_attachhook);

	//usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, usc->usc_uw.uw_udev, ac->ac_dev);
	if (!pmf_device_register(self, NULL, NULL))
		aprint_error_dev(self, "couldn't establish power handler\n");

	usc->usc_init_state = ATHN_INIT_INITED;

	return;

 fail:

	/* Free Tx/Rx buffers. */
	athn_usb_abort_pipes(usc);
	athn_usb_free_tx_cmd(usc);
	athn_usb_free_tx_msg(usc);
	athn_usb_close_pipes(usc);
	usb_rem_task_wait(usc->usc_uw.uw_udev, &usc->usc_task, USB_TASKQ_DRIVER,
	    NULL);

	cv_destroy(&usc->usc_cmd_cv);
	cv_destroy(&usc->usc_msg_cv);

	cv_destroy(&usc->usc_wmi_cv);
	cv_destroy(&usc->usc_htc_cv);
	//mutex_destroy(&usc->usc_lock);

	mutex_destroy(&usc->usc_cmd_mtx);
	mutex_destroy(&usc->usc_msg_mtx);
	mutex_destroy(&usc->usc_tx_mtx);
	mutex_destroy(&usc->usc_task_mtx);
	usbwifi_detach(usc->usc_dev, 0);
}

Static void
athn_usb_node_cleanup_cb(struct athn_usb_softc *usc, void *arg)
{
	uint8_t sta_index = *(uint8_t *)arg;

	DPRINTFN(DBG_FN, usc, "\n");
	DPRINTFN(DBG_NODES, usc, "removing node %u\n", sta_index);
	athn_usb_remove_hw_node(usc, &sta_index);
}

Static void
athn_usb_node_cleanup(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ic->ic_softc);
	uint8_t sta_index;

	DPRINTFN(DBG_FN, usc, "\n");

	if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
		sta_index = ATHN_NODE(ni)->sta_index;
		if (sta_index != 0)
			athn_usb_do_async(usc, athn_usb_node_cleanup_cb,
			    &sta_index, sizeof(sta_index));
	}
	usc->usc_node_cleanup(ni);
}

Static void
athn_usb_attachhook(device_t arg)
{
	struct athn_usb_softc *usc = device_private(arg);
	struct athn_common *ac = &usc->usc_ac;
	struct athn_ops *ops = &ac->ac_ops;
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	size_t i;
	int error;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	/* Load firmware. */
	error = athn_usb_load_firmware(usc);
	if (error != 0) {
		aprint_error_dev(ac->ac_dev,
		    "could not load firmware (%d)\n", error);
		return;
	}

	/* Setup the host transport communication interface. */
	error = athn_usb_htc_setup(usc);
	if (error != 0)
		return;

	/* XXX uw_ac2idx all 0 */

	/* We're now ready to attach the bus agnostic driver. */
	ic->ic_updateslot = athn_usb_updateslot;
	ac->ac_max_aid = AR_USB_MAX_STA;  /* Firmware is limited to 8 STA */
	//ac->ac_media_change = athn_usb_media_change;

	error = athn_attach_common(ac);
	if (error != 0) {
		return;
	}
	usc->usc_athn_attached = 1;

	/* Override some operations for USB. */
	ic->ic_getradiocaps = athn_usb_get_radiocaps;
	ic->ic_vap_create = athn_usb_vap_create;
	//ic->ic_parent = athn_usb_parent;
	//ic->ic_transmit = athn_usb_transmit;
	//ic->ic_raw_xmit = athn_usb_raw_xmit;
	ic->ic_update_mcast = athn_usb_set_multi;
	ic->ic_set_channel = athn_usb_set_channel;

	usbwifi_ic_attach(&usc->usc_uw, ac->ac_ntxchains, ac->ac_nrxchains,
	    usc->usc_ntxpipes, usc->usc_nrxpipes,
	    IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST);

	/* hooks for HostAP association and disassociation */
	ic->ic_newassoc = athn_usb_newassoc;
	usc->usc_node_cleanup = ic->ic_node_cleanup;
	ic->ic_node_cleanup = athn_usb_node_cleanup;

#ifdef notyet_edca
	ic->ic_updateedca = athn_usb_updateedca;
#endif
#ifdef notyet
	ic->ic_set_key = athn_usb_set_key;
	ic->ic_delete_key = athn_usb_delete_key;
	ic->ic_ampdu_tx_start = athn_usb_ampdu_tx_start;
	ic->ic_ampdu_tx_stop = athn_usb_ampdu_tx_stop;
#endif

	ops->rx_enable = athn_usb_rx_enable;

	/* Reset HW key cache entries. */
	for (i = 0; i < ac->ac_kc_entries; i++)
		athn_reset_key(ac, i);

	ops->enable_antenna_diversity(ac);

#ifdef ATHN_BT_COEXISTENCE
	/* Configure bluetooth coexistence for combo chips. */
	if (ac->ac_flags & ATHN_FLAG_BTCOEX)
		athn_btcoex_init(ac);
#endif
	/* Configure LED. */
	athn_led_init(ac);

	usbwifi_attach_finalize(&usc->usc_uw);
}

Static int
athn_usb_detach(device_t self, int flags)
{
	struct athn_usb_softc *usc = device_private(self);
	struct athn_common *ac = &usc->usc_ac;
	int error;

	DPRINTFN(DBG_FN, usc, "\n");

	if (usc->usc_init_state < ATHN_INIT_INITED)
		return 0;

	pmf_device_deregister(self);

	mutex_enter(&usc->usc_cmd_mtx);
	while (usc->usc_wmiactive) {
		error = cv_timedwait(&usc->usc_wmi_cv, &usc->usc_cmd_mtx, hz);

		if (error) {
			mutex_exit(&usc->usc_cmd_mtx);
			return error;
		}
	}
	mutex_exit(&usc->usc_cmd_mtx);

	mutex_enter(&usc->usc_msg_mtx);
	while (usc->usc_htcactive) {
		error = cv_timedwait(&usc->usc_htc_cv, &usc->usc_msg_mtx, hz);

		if (error) {
			mutex_exit(&usc->usc_msg_mtx);
			return error;
		}
	}
	mutex_exit(&usc->usc_msg_mtx);

	athn_usb_wait_async(usc);

	athn_usb_stop(usc, 0);
	usb_rem_task_wait(usc->usc_uw.uw_udev, &usc->usc_task, USB_TASKQ_DRIVER,
	    NULL);

	/* Abort Tx/Rx pipes. */
	athn_usb_abort_pipes(usc);

	if (usc->usc_athn_attached) {
		usc->usc_athn_attached = 0;
		athn_detach_common(ac);
	}

	/* Free Tx/Rx buffers. */
	athn_usb_free_tx_cmd(usc);
	athn_usb_free_tx_msg(usc);

	/* Close Tx/Rx pipes. */
	athn_usb_close_pipes(usc);

	mutex_destroy(&usc->usc_tx_mtx);
	cv_destroy(&usc->usc_task_cv);
	mutex_destroy(&usc->usc_task_mtx);

	mutex_destroy(&usc->usc_cmd_mtx);
	cv_destroy(&usc->usc_cmd_cv);
	mutex_destroy(&usc->usc_msg_mtx);
	cv_destroy(&usc->usc_msg_cv);

	cv_destroy(&usc->usc_wmi_cv);
	//mutex_destroy(&usc->usc_lock);

	//usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, usc->usc_uw.uw_udev, ac->ac_dev);
	usbwifi_detach(usc->usc_dev, 0);
	return 0;
}

#if 0
Static int
athn_usb_activate(device_t self, enum devact act)
{
	struct athn_usb_softc *usc = device_private(self);
	struct athn_common *ac = &usc->usc_ac;

	DPRINTFN(DBG_FN, usc, "\n");

	switch (act) {
	case DVACT_DEACTIVATE:
		if_deactivate(TAILQ_FIRST(&(usbwifi_ic(&usc->usc_uw)->ic_vaps))->iv_ifp);
		return 0;
	default:
		return EOPNOTSUPP;
	}
}
#endif

Static int
athn_usb_configure_pipes(struct athn_usb_softc *usc)
{
	struct usbwifi *uw = &usc->usc_uw;
	struct usbwifi_intr *uwi;
	usb_endpoint_descriptor_t *ed;
	int error;

	DPRINTFN(DBG_FN, usc, "\n");

	/* XXX Can there be more? */
#if 0
	error = usbd_open_pipe(usc->usc_uw.uw_iface, AR_PIPE_TX_DATA, 0,
	    &usc->usc_tx_data_pipe);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "could not open Tx bulk pipe\n");
		goto fail;
	}

	error = usbd_open_pipe(usc->usc_uw.uw_iface, AR_PIPE_RX_DATA, 0,
	    &usc->usc_rx_data_pipe);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "could not open Rx bulk pipe\n");
		goto fail;
	}

	ed = usbd_get_endpoint_descriptor(usc->usc_uw.uw_iface, AR_PIPE_RX_INTR);
	if (ed == NULL) {
		aprint_error_dev(usc->usc_dev,
		    "could not retrieve Rx intr pipe descriptor\n");
		goto fail;
	}
	usc->usc_ibufsize = UGETW(ed->wMaxPacketSize);
	if (usc->usc_ibufsize == 0) {
		aprint_error_dev(usc->usc_dev,
		    "invalid Rx intr pipe descriptor\n");
		goto fail;
	}
	usc->usc_ibuf = kmem_alloc(usc->usc_ibufsize, KM_SLEEP);

	error = usbd_open_pipe_intr(usc->usc_uw.uw_iface, AR_PIPE_RX_INTR,
	    USBD_SHORT_XFER_OK, &usc->usc_rx_intr_pipe, usc, usc->usc_ibuf,
	    usc->usc_ibufsize, athn_usb_intr, USBD_DEFAULT_INTERVAL);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "could not open Rx intr pipe\n");
		goto fail;
	}
#endif
	error = usbd_open_pipe(usc->usc_uw.uw_iface, AR_PIPE_TX_INTR, 0,
	    &usc->usc_tx_intr_pipe);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "could not open Tx intr pipe\n");
		return error;
	}

	usc->usc_ntxpipes = 1;
	usc->usc_nrxpipes = 2;
	uw->uw_ed[0] = AR_PIPE_TX_DATA;
	uw->uw_ed[1] = AR_PIPE_RX_DATA;
	uw->uw_ed[2] = AR_PIPE_RX_INTR;

	ed = usbd_get_endpoint_descriptor(usc->usc_uw.uw_iface, AR_PIPE_RX_INTR);
	if (ed == NULL) {
		aprint_error_dev(usc->usc_dev,
		    "could not retrieve Rx intr pipe descriptor\n");
		goto fail;
	}
	usc->usc_ibufsize = UGETW(ed->wMaxPacketSize);
	if (usc->usc_ibufsize == 0) {
		aprint_error_dev(usc->usc_dev,
		    "invalid Rx intr pipe descriptor\n");
		goto fail;
	}
	usc->usc_ibuf = kmem_alloc(usc->usc_ibufsize, KM_SLEEP);
	uwi = kmem_zalloc(sizeof(*uwi), KM_SLEEP);
	uwi->uwi_buf = usc->usc_ibuf;
	uwi->uwi_bufsz = usc->usc_ibufsize;
	uwi->uwi_interval = USBD_DEFAULT_INTERVAL;
	uwi->uwi_index = 2;
	uw->uw_intr = uwi;
	return 0;
 fail:
	athn_usb_abort_pipes(usc);
	athn_usb_close_pipes(usc);
	return error;
}

static inline void
athn_usb_kill_pipe(struct usbd_pipe **pipeptr)
{
	struct usbd_pipe *pipe;

	CTASSERT(sizeof(pipe) == sizeof(void *));
	pipe = atomic_swap_ptr(pipeptr, NULL);
	if (pipe != NULL) {
		usbd_close_pipe(pipe);
	}
}

Static void
athn_usb_abort_pipes(struct athn_usb_softc *usc)
{
	DPRINTFN(DBG_FN, usc, "\n");

	if (usc->usc_tx_intr_pipe != NULL)
		usbd_abort_pipe(usc->usc_tx_intr_pipe);
}

Static void
athn_usb_close_pipes(struct athn_usb_softc *usc)
{
	uint8_t *ibuf;

	DPRINTFN(DBG_FN, usc, "\n");

	athn_usb_kill_pipe(&usc->usc_tx_intr_pipe);
	/* Move elsewhere? */
	ibuf = atomic_swap_ptr(&usc->usc_ibuf, NULL);
	if (ibuf != NULL)
		kmem_free(ibuf, usc->usc_ibufsize);
	kmem_free(usc->usc_uw.uw_intr, sizeof(*usc->usc_uw.uw_intr));
}

Static int
athn_usb_alloc_tx_cmd(struct athn_usb_softc *usc)
{
	struct athn_usb_tx_data *data = &usc->usc_tx_cmd;

	DPRINTFN(DBG_FN, usc, "\n");

	data->ac = usc;	/* Backpointer for callbacks. */

	int err = usbd_create_xfer(usc->usc_tx_intr_pipe, ATHN_USB_TXCMDSZ,
	    0, 0, &data->xfer);
	if (err) {
		aprint_error_dev(usc->usc_dev,
		    "could not allocate command xfer\n");
		return err;
	}
	data->buf = usbd_get_buffer(data->xfer);

	return 0;
}

Static void
athn_usb_free_tx_cmd(struct athn_usb_softc *usc)
{
	struct usbd_xfer *xfer;

	DPRINTFN(DBG_FN, usc, "\n");

	CTASSERT(sizeof(xfer) == sizeof(void *));
	xfer = atomic_swap_ptr(&usc->usc_tx_cmd.xfer, NULL);
	if (xfer != NULL)
		usbd_destroy_xfer(xfer);
}

Static int
athn_usb_alloc_tx_msg(struct athn_usb_softc *usc)
{
	struct athn_usb_tx_data *data = &usc->usc_tx_msg;

	DPRINTFN(DBG_FN, usc, "\n");

	data->ac = usc;	/* Backpointer for callbacks. */

	int err = usbd_create_xfer(usc->usc_tx_intr_pipe, ATHN_USB_TXCMDSZ,
	    0, 0, &data->xfer);
	if (err) {
		aprint_error_dev(usc->usc_dev,
		    "could not allocate command xfer\n");
		return err;
	}
	data->buf = usbd_get_buffer(data->xfer);

	return 0;
}

Static void
athn_usb_free_tx_msg(struct athn_usb_softc *usc)
{
	struct usbd_xfer *xfer;

	DPRINTFN(DBG_FN, usc, "\n");

	CTASSERT(sizeof(xfer) == sizeof(void *));
	xfer = atomic_swap_ptr(&usc->usc_tx_msg.xfer, NULL);
	if (xfer != NULL)
		usbd_destroy_xfer(xfer);
}

Static void
athn_usb_task(void *arg)
{
	struct athn_usb_softc *usc = arg;
	struct athn_usb_host_cmd_ring *ring = &usc->usc_cmdq;
	struct athn_usb_host_cmd *cmd;

	DPRINTFN(DBG_FN, usc, "\n");

	/* Process host commands. */
	mutex_spin_enter(&usc->usc_task_mtx);
	while (ring->next != ring->cur) {
		cmd = &ring->cmd[ring->next];
		mutex_spin_exit(&usc->usc_task_mtx);

		/* Invoke callback. */
		if (!usbwifi_isdying(&usc->usc_uw))
			cmd->cb(usc, cmd->data);

		mutex_spin_enter(&usc->usc_task_mtx);
		ring->queued--;
		ring->next = (ring->next + 1) % ATHN_USB_HOST_CMD_RING_COUNT;
	}
	cv_broadcast(&usc->usc_task_cv);
	mutex_spin_exit(&usc->usc_task_mtx);
}

Static void
athn_usb_do_async(struct athn_usb_softc *usc,
    void (*cb)(struct athn_usb_softc *, void *), void *arg, int len)
{
	struct athn_usb_host_cmd_ring *ring = &usc->usc_cmdq;
	struct athn_usb_host_cmd *cmd;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	mutex_spin_enter(&usc->usc_task_mtx);
	cmd = &ring->cmd[ring->cur];
	cmd->cb = cb;
	KASSERT(len <= sizeof(cmd->data));
	memcpy(cmd->data, arg, len);
	ring->cur = (ring->cur + 1) % ATHN_USB_HOST_CMD_RING_COUNT;

	/* If there is no pending command already, schedule a task. */
	if (++ring->queued == 1) {
		usb_add_task(usc->usc_uw.uw_udev, &usc->usc_task, USB_TASKQ_DRIVER);
	}
	mutex_spin_exit(&usc->usc_task_mtx);
}

Static void
athn_usb_wait_async(struct athn_usb_softc *usc)
{

	DPRINTFN(DBG_FN, usc, "\n");

	/* Wait for all queued asynchronous commands to complete. */
	mutex_spin_enter(&usc->usc_task_mtx);
	while (usc->usc_cmdq.queued > 0)
		cv_wait(&usc->usc_task_cv, &usc->usc_task_mtx);
	mutex_spin_exit(&usc->usc_task_mtx);
}

Static int
athn_usb_load_firmware(struct athn_usb_softc *usc)
{
	struct athn_common *ac = &usc->usc_ac;
	firmware_handle_t fwh;
	usb_device_descriptor_t *dd;
	usb_device_request_t req;
	const char *name;
	u_char *fw, *ptr;
	size_t size, remain;
	uint32_t addr;
	int mlen, error;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Determine which firmware image to load. */
	if (usc->usc_flags & ATHN_USB_FLAG_AR7010) {
		dd = usbd_get_device_descriptor(usc->usc_uw.uw_udev);
		if (UGETW(dd->bcdDevice) == 0x0202)
			name = "athn-ar7010-11";
		else
			name = "athn-ar7010";
	} else
		name = "athn-ar9271";

	/* Read firmware image from the filesystem. */
	if ((error = firmware_open("if_athn", name, &fwh)) != 0) {
		aprint_error_dev(ac->ac_dev,
		    "failed to open firmware file %s (%d)\n", name, error);
		return error;
	}
	size = firmware_get_size(fwh);
	fw = firmware_malloc(size);
	if (fw == NULL) {
		aprint_error_dev(usc->usc_dev,
		    "failed to allocate firmware memory\n");
		firmware_close(fwh);
		return ENOMEM;
	}
	error = firmware_read(fwh, 0, fw, size);
	firmware_close(fwh);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "failed to read firmware (error %d)\n", error);
		firmware_free(fw, size);
		return error;
	}

	/* Load firmware image. */
	ptr = fw;
	addr = AR9271_FIRMWARE >> 8;
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = AR_FW_DOWNLOAD;
	USETW(req.wIndex, 0);
	remain = size;
	while (remain > 0) {
		mlen = MIN(remain, 4096);

		USETW(req.wValue, addr);
		USETW(req.wLength, mlen);
		error = usbd_do_request(usc->usc_uw.uw_udev, &req, ptr);
		if (error != 0) {
			firmware_free(fw, size);
			return error;
		}
		addr   += mlen >> 8;
		ptr    += mlen;
		remain -= mlen;
	}
	firmware_free(fw, size);

	/* Start firmware. */
	if (usc->usc_flags & ATHN_USB_FLAG_AR7010)
		addr = AR7010_FIRMWARE_TEXT >> 8;
	else
		addr = AR9271_FIRMWARE_TEXT >> 8;
	req.bmRequestType = UT_WRITE_VENDOR_DEVICE;
	req.bRequest = AR_FW_DOWNLOAD_COMP;
	USETW(req.wIndex, 0);
	USETW(req.wValue, addr);
	USETW(req.wLength, 0);

	mutex_enter(&usc->usc_msg_mtx);
	while (usc->usc_htcactive) {
		error = cv_timedwait(&usc->usc_htc_cv, &usc->usc_msg_mtx, hz);

		if (error) {
			mutex_exit(&usc->usc_msg_mtx);
			return error;
		}
	}

	usc->usc_htcactive = true;

	KASSERT(usc->usc_wait_msg_id == 0);
	usc->usc_wait_msg_id = AR_HTC_MSG_READY;
	mutex_exit(&usc->usc_msg_mtx);

	error = usbd_do_request(usc->usc_uw.uw_udev, &req, NULL);

	mutex_enter(&usc->usc_msg_mtx);
	/* Wait at most 1 second for firmware to boot. */
	if (error == 0)
		error = athn_usb_wait_msg(usc);

	usc->usc_htcactive = false;
	cv_broadcast(&usc->usc_htc_cv);
	mutex_exit(&usc->usc_msg_mtx);

	DPRINTFN(DBG_FN, ac, "return %d\n", error);

	return error;
}

Static int
athn_usb_htc_msg(struct athn_usb_softc *usc, uint16_t msg_id, void *buf,
    int len)
{
	struct athn_usb_tx_data *data = &usc->usc_tx_msg;
	struct ar_htc_frame_hdr *htc;
	struct ar_htc_msg_hdr *msg;

	if (usbwifi_isdying(&usc->usc_uw))
		return USBD_CANCELLED;

	DPRINTFN(DBG_FN, usc, "\n");

	htc = (struct ar_htc_frame_hdr *)data->buf;
	memset(htc, 0, sizeof(*htc));
	htc->endpoint_id = 0;
	htc->payload_len = htobe16(sizeof(*msg) + len);

	msg = (struct ar_htc_msg_hdr *)&htc[1];
	msg->msg_id = htobe16(msg_id);

	memcpy(&msg[1], buf, len);

	usbd_setup_xfer(data->xfer, NULL, data->buf,
	    sizeof(*htc) + sizeof(*msg) + len,
	    USBD_SHORT_XFER_OK, ATHN_USB_CMD_TIMEOUT, NULL);
	return usbd_sync_transfer(data->xfer);


}

Static int
athn_usb_htc_setup(struct athn_usb_softc *usc)
{
	struct ar_htc_msg_config_pipe cfg;
	int error;

	mutex_enter(&usc->usc_msg_mtx);
	while (usc->usc_htcactive) {
		error = cv_timedwait(&usc->usc_htc_cv, &usc->usc_msg_mtx, hz);

		if (error) {
			mutex_exit(&usc->usc_msg_mtx);
			return error;
		}
	}
	usc->usc_htcactive = true;
	mutex_exit(&usc->usc_msg_mtx);

	/*
	 * Connect WMI services to USB pipes.
	 */
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_CONTROL,
	    AR_PIPE_TX_INTR, AR_PIPE_RX_INTR, &usc->usc_ep_ctrl);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_BEACON,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_bcn);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_CAB,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_cab);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_UAPSD,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_uapsd);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_MGMT,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_mgmt);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_DATA_BE,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_data[WME_AC_BE]);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_DATA_BK,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_data[WME_AC_BK]);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_DATA_VI,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_data[WME_AC_VI]);
	if (error != 0)
		return error;
	error = athn_usb_htc_connect_svc(usc, AR_SVC_WMI_DATA_VO,
	    AR_PIPE_TX_DATA, AR_PIPE_RX_DATA, &usc->usc_ep_data[WME_AC_VO]);
	if (error != 0)
		return error;

	/* Set credits for WLAN Tx pipe. */
	memset(&cfg, 0, sizeof(cfg));
	cfg.pipe_id = UE_GET_ADDR(AR_PIPE_TX_DATA);
	cfg.credits = (usc->usc_flags & ATHN_USB_FLAG_AR7010) ? 45 : 33;

	mutex_enter(&usc->usc_msg_mtx);

	KASSERT(usc->usc_wait_msg_id == 0);
	usc->usc_wait_msg_id = AR_HTC_MSG_CONF_PIPE_RSP;
	mutex_exit(&usc->usc_msg_mtx);

	error = athn_usb_htc_msg(usc, AR_HTC_MSG_CONF_PIPE, &cfg, sizeof(cfg));

	if (error != 0) {
		aprint_error_dev(usc->usc_dev, "could not request pipe configurations\n");
		return error;
	}

	mutex_enter(&usc->usc_msg_mtx);
	error = athn_usb_wait_msg(usc);
	if (error) {
		mutex_exit(&usc->usc_msg_mtx);
		return error;
	}

	mutex_exit(&usc->usc_msg_mtx);
	error = athn_usb_htc_msg(usc, AR_HTC_MSG_SETUP_COMPLETE, NULL, 0);
	if (error != 0) {
		aprint_error_dev(usc->usc_dev, "could not request complete setup\n");
		return error;
	}
	mutex_enter(&usc->usc_msg_mtx);
	error = athn_usb_wait_msg(usc);
	if (error) {
		mutex_exit(&usc->usc_msg_mtx);
		return error;
	}

	usc->usc_htcactive = false;
	cv_broadcast(&usc->usc_htc_cv);
	mutex_exit(&usc->usc_msg_mtx);

	return 0;
}

Static int
athn_usb_htc_connect_svc(struct athn_usb_softc *usc, uint16_t svc_id,
    uint8_t ul_pipe, uint8_t dl_pipe, uint8_t *endpoint_id)
{
	struct ar_htc_msg_conn_svc msg;
	struct ar_htc_msg_conn_svc_rsp rsp;
	int error;

	DPRINTFN(DBG_FN, usc, "\n");

	memset(&msg, 0, sizeof(msg));
	msg.svc_id = htobe16(svc_id);
	msg.dl_pipeid = UE_GET_ADDR(dl_pipe);
	msg.ul_pipeid = UE_GET_ADDR(ul_pipe);

	mutex_enter(&usc->usc_msg_mtx);
	KASSERT(usc->usc_wait_msg_id == 0);
	usc->usc_msg_conn_svc_rsp = &rsp;
	usc->usc_wait_msg_id = AR_HTC_MSG_CONN_SVC_RSP;
	mutex_exit(&usc->usc_msg_mtx);

	error = athn_usb_htc_msg(usc, AR_HTC_MSG_CONN_SVC, &msg, sizeof(msg));

	mutex_enter(&usc->usc_msg_mtx);
	if (error == 0)
		error = athn_usb_wait_msg(usc);

	mutex_exit(&usc->usc_msg_mtx);

	if (error != 0) {
		aprint_error_dev(usc->usc_dev,
		    "error waiting for service %d connection\n", svc_id);
		return error;
	}
	if (rsp.status != AR_HTC_SVC_SUCCESS) {
		aprint_error_dev(usc->usc_dev,
		    "service %d connection failed, error %d\n",
		    svc_id, rsp.status);
		return EIO;
	}
	DPRINTFN(DBG_INIT, usc,
	    "service %d successfully connected to endpoint %d\n",
	    svc_id, rsp.endpoint_id);

	/* Return endpoint id. */
	*endpoint_id = rsp.endpoint_id;
	return 0;
}

Static int
athn_usb_wait_msg(struct athn_usb_softc *usc)
{
	DPRINTFN(DBG_FN, usc, "\n");

	KASSERT(mutex_owned(&usc->usc_msg_mtx));

	int error = 0;
	while (usc->usc_wait_msg_id)
		error = cv_timedwait(&usc->usc_msg_cv, &usc->usc_msg_mtx, hz);

	return error;
}

Static void
athn_usb_wmieof(struct usbd_xfer *xfer, void * priv,
    usbd_status status)
{
	struct athn_usb_softc *usc = priv;

	DPRINTFN(DBG_FN, usc, "\n");

	if (__predict_false(status == USBD_STALLED))
		usbd_clear_endpoint_stall_async(usc->usc_tx_intr_pipe);
}

Static int
athn_usb_wmi_xcmd(struct athn_usb_softc *usc, uint16_t cmd_id, void *ibuf,
    int ilen, void *obuf)
{
	struct athn_usb_tx_data *data = &usc->usc_tx_cmd;
	struct ar_htc_frame_hdr *htc;
	struct ar_wmi_cmd_hdr *wmi;
	int error = 0;

	if (usbwifi_isdying(&usc->usc_uw))
		return EIO;

 	DPRINTFN(DBG_FN, usc, "cmd_id %#x\n", cmd_id);

	htc = (struct ar_htc_frame_hdr *)data->buf;
	memset(htc, 0, sizeof(*htc));
	htc->endpoint_id = usc->usc_ep_ctrl;
	htc->payload_len = htobe16(sizeof(*wmi) + ilen);

	wmi = (struct ar_wmi_cmd_hdr *)&htc[1];
	wmi->cmd_id = htobe16(cmd_id);
	usc->usc_wmi_seq_no++;
	wmi->seq_no = htobe16(usc->usc_wmi_seq_no);

	memcpy(&wmi[1], ibuf, ilen);

	usbd_setup_xfer(data->xfer, usc, data->buf,
	    sizeof(*htc) + sizeof(*wmi) + ilen,
	    USBD_SHORT_XFER_OK, ATHN_USB_CMD_TIMEOUT,
	    athn_usb_wmieof);

	mutex_enter(&usc->usc_cmd_mtx);
	while (usc->usc_wmiactive) {
		error = cv_timedwait(&usc->usc_wmi_cv, &usc->usc_cmd_mtx, hz);

		if (error) {
			mutex_exit(&usc->usc_cmd_mtx);
			return error;
		}
	}
	usc->usc_wmiactive = true;

	KASSERT(usc->usc_wait_cmd_id == 0);
	usc->usc_wait_cmd_id = cmd_id;
	usc->usc_obuf = obuf;
	mutex_exit(&usc->usc_cmd_mtx);

	error = usbd_sync_transfer(data->xfer);
	if (error) {
	    	DPRINTFN(DBG_FN, usc, "transfer error %d\n", error);

		return error;
	}

	mutex_enter(&usc->usc_cmd_mtx);
	while (usc->usc_wait_cmd_id)
		error = cv_timedwait(&usc->usc_cmd_cv, &usc->usc_cmd_mtx, hz);

	usc->usc_wmiactive = false;
	cv_broadcast(&usc->usc_wmi_cv);
	mutex_exit(&usc->usc_cmd_mtx);

	return 0;
}

#ifdef unused
Static int
athn_usb_read_rom(struct athn_common *ac)
{
	struct athn_usb_softc *usc = ac->ac_softc;
	uint32_t addrs[8], vals[8], addr;
	uint16_t *eep;
	size_t i, j;
	int error = 0;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Read EEPROM by blocks of 16 bytes. */
	eep = ac->ac_eep;
	addr = AR_EEPROM_OFFSET(ac->ac_eep_base);
	for (i = 0; i < ac->ac_eep_size / 16; i++) {
		for (j = 0; j < 8; j++, addr += 4)
			addrs[j] = htobe32(addr);
		error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_REG_READ,
		    addrs, sizeof(addrs), vals);
		if (error != 0)
			break;
		for (j = 0; j < 8; j++)
			*eep++ = be32toh(vals[j]);
	}
	return error;
}
#endif /* unused */

Static uint32_t
athn_usb_read(struct athn_common *ac, uint32_t addr)
{
	struct athn_usb_softc *usc = ac->ac_softc;
	uint32_t val;
	int error;

	if (usbwifi_isdying(&usc->usc_uw))
		return 0;

 	DPRINTFN(DBG_FN, ac, "addr %#x\n", htobe32(addr));

	/* Flush pending writes for strict consistency. */
	athn_usb_write_barrier(usc);

	addr = htobe32(addr);
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_REG_READ,
	    &addr, sizeof(addr), &val);
	if (error != 0) {
		DPRINTFN(DBG_FN, ac, "error %d\n", addr);
		return 0xdeadbeef;
	}
 	DPRINTFN(DBG_FN, ac, "addr %#x return %#x\n", addr, be32toh(val));

	return be32toh(val);
}

Static void
athn_usb_write(struct athn_common *ac, uint32_t addr, uint32_t val)
{
	struct athn_usb_softc *usc = ac->ac_softc;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

 	DPRINTFN(DBG_FN, ac, "addr %#x val %#x\n", addr, val);

	usc->usc_wbuf[usc->usc_wcount].addr = htobe32(addr);
	usc->usc_wbuf[usc->usc_wcount].val  = htobe32(val);
	if (++usc->usc_wcount == AR_MAX_WRITE_COUNT)
		athn_usb_write_barrier(usc);
}

Static void
athn_usb_write_barrier(struct athn_usb_softc *usc)
{
	if (usbwifi_isdying(&usc->usc_uw))
		goto done;

 	DPRINTFN(DBG_FN, ac, "usc_wcount %d\n", usc->usc_wcount);

	if (usc->usc_wcount == 0)
		return;

	(void)athn_usb_wmi_xcmd(usc, AR_WMI_CMD_REG_WRITE,
	    usc->usc_wbuf, usc->usc_wcount * sizeof(usc->usc_wbuf[0]), NULL);
 done:
	usc->usc_wcount = 0;	/* Always flush buffer. */
}

Static void
athn_usb_get_radiocaps(struct ieee80211com *ic,
    int maxchans, int *nchans,
    struct ieee80211_channel chans[])
{
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;
	athn_get_radiocaps_common(ac, ic, maxchans, nchans. chans);
}

#if 0
Static int
athn_usb_media_change(struct ifnet *ifp)
{
	struct athn_softc *sc = ifp->if_softc;
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ac);
	int error;

	if (usbwifi_isdying(&usc->usc_uw))
		return EIO;

	DPRINTFN(DBG_FN, ac, "\n");

	error = ieee80211_media_change(ifp);
	if (error == ENETRESET && IS_UP_AND_RUNNING(ifp)) {
		athn_usb_stop(ifp, 0);
		error = athn_usb_init(ifp);
	}
	return error;
}
#endif

Static int
athn_usb_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate,
    int arg)
{
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(vap->iv_ic->ic_softc);
	struct athn_common *ac = &usc->usc_ac;
	struct athn_usb_cmd_newstate cmd;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Do it in a process context. */
	cmd.state = nstate;
	cmd.arg = arg;
	athn_usb_do_async(vap, athn_usb_newstate_cb, &cmd, sizeof(cmd));
	return 0;
}

Static void
athn_usb_newstate_cb(struct ieee80211vap *vap, void *arg)
{
	struct athn_usb_cmd_newstate *cmd = arg;
	struct ieee80211com *ic = vap->iv_ic;
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;
	struct athn_vap *avap = (struct athn_vap *)vap;
	uint32_t reg, intr_mask;
	int s;

	DPRINTFN(DBG_FN, ac, "\n");

	callout_stop(&ac->ac_calib_to);

	s = splnet();

#if 0
	if (ostate == IEEE80211_S_RUN) {
		uint8_t sta_index;

		sta_index = ATHN_NODE(vap->iv_bss)->sta_index;
		DPRINTFN(DBG_NODES, usc, "removing node %u\n", sta_index);
		athn_usb_remove_hw_node(usc, &sta_index);
	}
#endif

	switch (nstate) {
	case IEEE80211_S_INIT:
		athn_set_led(ac, 0);
		break;
	case IEEE80211_S_SCAN:
		/* Make the LED blink while scanning. */
		athn_set_led(ac, !ac->ac_led_state);
		(void)athn_usb_switch_chan(ac, ic->ic_curchan, NULL);
		if (!usbwifi_isdying(&usc->usc_uw))
			callout_schedule(&ac->ac_scan_to, hz / 5);
		break;
	case IEEE80211_S_AUTH:
		athn_set_led(ac, 0);
		athn_usb_switch_chan(ac, ic->ic_curchan, NULL);
		break;
	case IEEE80211_S_ASSOC:
		break;
	case IEEE80211_S_RUN:
		athn_set_led(ac, 1);

		if (ic->ic_opmode == IEEE80211_M_MONITOR)
			break;

		/* Create node entry for our BSS. */
		DPRINTFN(DBG_NODES, ac, "create node for AID=%#x\n",
		    ic->ic_bss->ni_associd);
		athn_usb_create_node(usc, vap->iv_bss);	/* XXX: handle error? */

		athn_set_bss(ac, vap->iv_bss);
		athn_usb_wmi_cmd(usc, AR_WMI_CMD_DISABLE_INTR);
#ifndef IEEE80211_STA_ONLY
		if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
			athn_set_hostap_timers(vap, ac);
			/* Enable software beacon alert interrupts. */
			intr_mask = htobe32(AR_IMR_SWBA);
		} else
#endif
		{
			athn_set_sta_timers(vap, ac);
			/* Enable beacon miss interrupts. */
			intr_mask = htobe32(AR_IMR_BMISS);

			/* Stop receiving beacons from other BSS. */
			reg = AR_READ(ac, AR_RX_FILTER);
			reg = (reg & ~AR_RX_FILTER_BEACON) |
			    AR_RX_FILTER_MYBEACON;
			AR_WRITE(ac, AR_RX_FILTER, reg);
			AR_WRITE_BARRIER(ac);
		}
		athn_usb_wmi_xcmd(usc, AR_WMI_CMD_ENABLE_INTR,
		    &intr_mask, sizeof(intr_mask), NULL);
		break;
	case IEEE80211_S_CAC:
	case IEEE80211_S_CSA:
	case IEEE80211_S_SLEEP:
		/* XXX -- new during wif refresh ... need new code.. */
		break;
	}
	if (!usbwifi_isdying(&usc->usc_uw))
		(void)avap->ac_newstate(vap, nstate, cmd->arg);
	splx(s);
}

Static void
athn_usb_newassoc(struct ieee80211_node *ni, int isnew)
{
	struct ieee80211com *ic = ni->ni_ic;
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;

	DPRINTFN(DBG_FN, ac, "\n");

	if (ic->ic_opmode != IEEE80211_M_HOSTAP || !isnew)
		return;

	/* Do it in a process context. */
	ieee80211_ref_node(ni);
	athn_usb_do_async(usc, athn_usb_newassoc_cb, &ni, sizeof(ni));
}

Static void
athn_usb_newassoc_cb(struct athn_usb_softc *usc, void *arg)
{
	struct ieee80211_node *ni = *(void **)arg;
	int s;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	/* NB: Node may have left before we got scheduled. */
	if (ni->ni_associd != 0) {
		DPRINTFN(DBG_NODES, usc, "creating node for AID=%#x\n",
		    ni->ni_associd);
		(void)athn_usb_create_node(usc, ni);	/* XXX: handle error? */
	}
	ieee80211_free_node(ni);
	splx(s);
}

#ifdef notyet
Static int
athn_usb_ampdu_tx_start(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;
	struct athn_node *an = ATHN_NODE(ni);
	struct athn_usb_aggr_cmd cmd;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Do it in a process context. */
	cmd.sta_index = an->sta_index;
	cmd.tid = tid;
	athn_usb_do_async(usc, athn_usb_ampdu_tx_start_cb, &cmd, sizeof(cmd));
	return 0;
}

Static void
athn_usb_ampdu_tx_start_cb(struct athn_usb_softc *usc, void *arg)
{
	struct athn_usb_aggr_cmd *cmd = arg;
	struct ar_htc_target_aggr aggr;

	DPRINTFN(DBG_FN, usc, "\n");

	memset(&aggr, 0, sizeof(aggr));
	aggr.sta_index = cmd->sta_index;
	aggr.tidno = cmd->tid;
	aggr.aggr_enable = 1;
	(void)athn_usb_wmi_xcmd(usc, AR_WMI_CMD_TX_AGGR_ENABLE,
	    &aggr, sizeof(aggr), NULL);
}

Static void
athn_usb_ampdu_tx_stop(struct ieee80211com *ic, struct ieee80211_node *ni,
    uint8_t tid)
{
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;
	struct athn_node *an = ATHN_NODE(ni);
	struct athn_usb_aggr_cmd cmd;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Do it in a process context. */
	cmd.sta_index = an->sta_index;
	cmd.tid = tid;
	athn_usb_do_async(usc, athn_usb_ampdu_tx_stop_cb, &cmd, sizeof(cmd));
}

Static void
athn_usb_ampdu_tx_stop_cb(struct athn_usb_softc *usc, void *arg)
{
	struct athn_usb_aggr_cmd *cmd = arg;
	struct ar_htc_target_aggr aggr;

	DPRINTFN(DBG_FN, usc, "\n");

	memset(&aggr, 0, sizeof(aggr));
	aggr.sta_index = cmd->sta_index;
	aggr.tidno = cmd->tid;
	aggr.aggr_enable = 0;
	(void)athn_usb_wmi_xcmd(usc, AR_WMI_CMD_TX_AGGR_ENABLE,
	    &aggr, sizeof(aggr), NULL);
}
#endif /* notyet */

Static int
athn_usb_remove_hw_node(struct athn_usb_softc *usc, uint8_t *sta_idx)
{
	int error;

	DPRINTFN(DBG_FN, usc, "\n");

	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_NODE_REMOVE,
	    sta_idx, sizeof(*sta_idx), NULL);

	DPRINTFN(DBG_NODES, usc, "node=%u error=%d\n",
	    *sta_idx, error);
	return error;
}

Static int
athn_usb_create_hw_node(struct athn_usb_softc *usc,
    struct ar_htc_target_sta *sta)
{
	int error;

	DPRINTFN(DBG_FN, usc, "\n");

	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_NODE_CREATE,
	    sta, sizeof(*sta), NULL);

	DPRINTFN(DBG_NODES, usc, "node=%u error=%d\n",
	    sta->sta_index, error);

	return error;
}

Static int
athn_usb_create_node(struct athn_usb_softc *usc, struct ieee80211_node *ni)
{
	struct athn_node *an = ATHN_NODE(ni);
	struct ar_htc_target_sta sta;
	struct ar_htc_target_rate rate;
	int error;

	DPRINTFN(DBG_FN | DBG_NODES, usc, "AID=%#x\n", ni->ni_associd);

	/*
	 * NB: this is called by ic_newstate and (in HOSTAP mode by)
	 * ic_newassoc.
	 *
	 * The firmware has a limit of 8 nodes.  In HOSTAP mode, we
	 * limit the AID to < 8 and use that value to index the
	 * firmware node table.  Node zero is used for the BSS.
	 *
	 * In STA mode, we simply use node 1 for the BSS.
	 */
	if (usbwifi_ic(&usc->usc_uw)->ic_opmode == IEEE80211_M_HOSTAP)
		an->sta_index = IEEE80211_NODE_AID(ni);
	else
		an->sta_index = 1;

	/* Create node entry on target. */
	memset(&sta, 0, sizeof(sta));
	IEEE80211_ADDR_COPY(sta.macaddr, ni->ni_macaddr);
	IEEE80211_ADDR_COPY(sta.bssid, ni->ni_bssid);

	sta.associd = htobe16(ni->ni_associd);
	sta.valid = 1;
	sta.sta_index = an->sta_index;

	sta.maxampdu = 0xffff;
#ifndef IEEE80211_NO_HT
	if (ni->ni_flags & IEEE80211_NODE_HT)
		sta.flags |= htobe16(AR_HTC_STA_HT);
#endif
	error = athn_usb_create_hw_node(usc, &sta);
	if (error)
		return error;

	/* Setup supported rates. */
	memset(&rate, 0, sizeof(rate));
	rate.sta_index = sta.sta_index;
	rate.isnew = 1;
	rate.lg_rates.rs_nrates = ni->ni_rates.rs_nrates;
	memcpy(rate.lg_rates.rs_rates, ni->ni_rates.rs_rates,
	    ni->ni_rates.rs_nrates);

#ifndef IEEE80211_NO_HT
	if (ni->ni_flags & IEEE80211_NODE_HT) {
		rate.capflags |= htobe32(AR_RC_HT_FLAG);
#ifdef notyet
		/* XXX setup HT rates */
		if (ni->ni_htcaps & IEEE80211_HTCAP_CBW20_40)
			rate.capflags |= htobe32(AR_RC_40_FLAG);
		if (ni->ni_htcaps & IEEE80211_HTCAP_SGI40)
			rate.capflags |= htobe32(AR_RC_SGI_FLAG);
		if (ni->ni_htcaps & IEEE80211_HTCAP_SGI20)
			rate.capflags |= htobe32(AR_RC_SGI_FLAG);
#endif
	}
#endif
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_RC_RATE_UPDATE,
	    &rate, sizeof(rate), NULL);
	return error;
}

Static void
athn_usb_rx_enable(struct athn_common *ac)
{

	DPRINTFN(DBG_FN, ac, "\n");

	AR_WRITE(ac, AR_CR, AR_CR_RXE);
	AR_WRITE_BARRIER(ac);
}

Static int
athn_usb_switch_chan(struct athn_common *ac, struct ieee80211_channel *curchan,
    struct ieee80211_channel *extchan)
{
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ac);
	uint16_t mode;
	int error;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Disable interrupts. */
	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_DISABLE_INTR);
	if (error != 0)
		goto reset;
	/* Stop all Tx queues. */
	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_DRAIN_TXQ_ALL);
	if (error != 0)
		goto reset;
	/* Stop Rx. */
	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_STOP_RECV);
	if (error != 0)
		goto reset;

	/* If band or bandwidth changes, we need to do a full reset. */
	if (curchan->ic_flags != ac->ac_curchan->ic_flags ||
	    ((extchan != NULL) ^ (ac->ac_curchanext != NULL))) {
		DPRINTFN(DBG_RF, ac, "channel band switch\n");
		goto reset;
	}

	error = athn_set_chan(ac, curchan, extchan);
	if (AR_SREV_9271(ac) && error == 0)
		ar9271_load_ani(ac);
	if (error != 0) {
 reset:		/* Error found, try a full reset. */
		DPRINTFN(DBG_RF, ac, "needs a full reset\n");
		error = athn_hw_reset(ac, curchan, extchan, 0);
		if (error != 0)	/* Hopeless case. */
			return error;
	}

	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_START_RECV);
	if (error != 0)
		return error;
	//athn_rx_start(ac);

	mode = htobe16(IEEE80211_IS_CHAN_2GHZ(curchan) ?
	    AR_HTC_MODE_11NG : AR_HTC_MODE_11NA);
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_SET_MODE,
	    &mode, sizeof(mode), NULL);
	if (error != 0)
		return error;

	/* Re-enable interrupts. */
	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_ENABLE_INTR);
	return error;
}

#ifdef notyet_edca
Static void
athn_usb_updateedca(struct ieee80211com *ic)
{
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ic->ic_softc);
	struct athn_common *ac = &usc->usc_ac;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Do it in a process context. */
	athn_usb_do_async(usc, athn_usb_updateedca_cb, NULL, 0);
}

Static void
athn_usb_updateedca_cb(struct athn_usb_softc *usc, void *arg)
{
	int s;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	athn_updateedca(usbwifi_ic(&usc->usc_uw));
	splx(s);
}
#endif /* notyet_edca */

Static void
athn_usb_updateslot(struct ieee80211com *ic)
{
	struct athn_common *ac = ic->ic_softc;
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ac);

	DPRINTFN(DBG_FN, ac, "\n");

	/*
	 * NB: athn_updateslog() needs to be done in a process context
	 * to avoid being called by ieee80211_reset_erp() inside a
	 * spinlock held by ieee80211_free_allnodes().
	 *
	 * XXX: calling this during the athn_attach() causes
	 * usb_insert_transfer() to produce a bunch of "not busy"
	 * messages.  Why?
	 */
	if (usc->usc_athn_attached)
		athn_usb_do_async(usc, athn_usb_updateslot_cb, NULL, 0);
}

Static void
athn_usb_updateslot_cb(struct athn_usb_softc *usc, void *arg)
{
	int s;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	athn_updateslot(usbwifi_ic(&usc->usc_uw));
	splx(s);
}

#ifdef notyet
Static int
athn_usb_set_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ic->ic_softc);
	struct athn_common *ac = &usc->usc_ac;
	struct ifnet *ifp = &usc->usc_ac.sc_if;
	struct athn_usb_cmd_key cmd;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Defer setting of WEP keys until interface is brought up. */
	if (!IS_UP_AND_RUNNING(ifp))
		return 0;

	/* Do it in a process context. */
	cmd.ni = (ni != NULL) ? ieee80211_ref_node(ni) : NULL;
	cmd.key = k;
	athn_usb_do_async(usc, athn_usb_set_key_cb, &cmd, sizeof(cmd));
	return 0;
}

Static void
athn_usb_set_key_cb(struct athn_usb_softc *usc, void *arg)
{
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	struct athn_usb_cmd_key *cmd = arg;
	int s;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	athn_set_key(ic, cmd->ni, cmd->key);
	if (cmd->ni != NULL)
		ieee80211_free_node(cmd->ni);
	splx(s);
}

Static void
athn_usb_delete_key(struct ieee80211com *ic, struct ieee80211_node *ni,
    struct ieee80211_key *k)
{
	struct athn_usb_softc *usc = ATHN_USB_SOFTC(ic->ic_softc);
	struct athn_common *ac = &usc->usc_ac;
	//struct ifnet *ifp = &usc->usc_ac.sc_if;
	struct athn_usb_cmd_key cmd;

	DPRINTFN(DBG_FN, ac, "\n");

	if (!(ifp->if_flags & IFF_RUNNING) ||
	    ic->ic_state != IEEE80211_S_RUN)
		return;	/* Nothing to do. */

	/* Do it in a process context. */
	cmd.ni = (ni != NULL) ? ieee80211_ref_node(ni) : NULL;
	cmd.key = k;
	athn_usb_do_async(usc, athn_usb_delete_key_cb, &cmd, sizeof(cmd));
}

Static void
athn_usb_delete_key_cb(struct athn_usb_softc *usc, void *arg)
{
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	struct athn_usb_cmd_key *cmd = arg;
	int s;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	athn_delete_key(ic, cmd->ni, cmd->key);
	if (cmd->ni != NULL)
		ieee80211_free_node(cmd->ni);
	splx(s);
}
#endif /* notyet */

#ifndef IEEE80211_STA_ONLY
#ifdef notyet
Static void
athn_usb_bcneof(struct usbd_xfer *xfer, void * priv,
    usbd_status status)
{
	struct athn_usb_tx_data *data = priv;
	struct athn_usb_softc *usc = data->ac;

	DPRINTFN(DBG_FN, usc, "\n");

	if (__predict_false(status == USBD_STALLED))
		usbd_clear_endpoint_stall_async(usc->usc_tx_data_pipe);
	usc->usc_tx_bcn = data;
}

/*
 * Process Software Beacon Alert interrupts.
 */
Static void
athn_usb_swba(struct athn_usb_softc *usc)
{
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	struct athn_usb_tx_data *data;
	struct ieee80211_frame *wh;
	struct ar_stream_hdr *hdr;
	struct ar_htc_frame_hdr *htc;
	struct ar_tx_bcn *bcn;
	struct mbuf *m;
	struct ieee80211vap *vap = TAILQ_FIRST(&(ic->ic_vaps));
	int error;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, ac, "\n");

	if (vap->iv_dtim_count == 0)
		vap->iv_dtim_count = vap->iv_dtim_period - 1;
	else
		vap->iv_dtim_count--;

	/* Make sure previous beacon has been sent. */
	if (usc->usc_tx_bcn == NULL)
		return;
	data = usc->usc_tx_bcn;

	/* Get new beacon. */
	m = ieee80211_beacon_alloc(vap->iv_bss);
	if (__predict_false(m == NULL))
		return;
	/* Assign sequence number. */
	/* XXX: use non-QoS tid? */
	wh = mtod(m, struct ieee80211_frame *);
	*(uint16_t *)&wh->i_seq[0] =
	    htole16(vap->iv_bss->ni_txseqs[0] << IEEE80211_SEQ_SEQ_SHIFT);
	vap->iv_bss->ni_txseqs[0]++;

	hdr = (struct ar_stream_hdr *)data->buf;
	hdr->tag = htole16(AR_USB_TX_STREAM_TAG);
	hdr->len = htole16(sizeof(*htc) + sizeof(*bcn) + m->m_pkthdr.len);

	htc = (struct ar_htc_frame_hdr *)&hdr[1];
	memset(htc, 0, sizeof(*htc));
	htc->endpoint_id = usc->usc_ep_bcn;
	htc->payload_len = htobe16(sizeof(*bcn) + m->m_pkthdr.len);

	bcn = (struct ar_tx_bcn *)&htc[1];
	memset(bcn, 0, sizeof(*bcn));
	bcn->vif_idx = 0;

	m_copydata(m, 0, m->m_pkthdr.len, (void *)&bcn[1]);

	usbd_setup_xfer(data->xfer, data, data->buf,
	    sizeof(*hdr) + sizeof(*htc) + sizeof(*bcn) + m->m_pkthdr.len,
	    USBD_SHORT_XFER_OK, ATHN_USB_TX_TIMEOUT,
	    athn_usb_bcneof);

	m_freem(m);
	usc->usc_tx_bcn = NULL;
	error = usbd_transfer(data->xfer);
	if (__predict_false(error != USBD_IN_PROGRESS && error != 0))
		usc->usc_tx_bcn = data;
}
#endif
#endif

Static void
athn_usb_rx_wmi_ctrl(struct athn_usb_softc *usc, uint8_t *buf, size_t len)
{
#ifdef ATHN_DEBUG
	struct ar_wmi_evt_txrate *txrate;
#endif
	struct ar_wmi_cmd_hdr *wmi;
	uint16_t cmd_id;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	if (__predict_false(len < sizeof(*wmi)))
		return;
	wmi = (struct ar_wmi_cmd_hdr *)buf;
	cmd_id = be16toh(wmi->cmd_id);

	if (!(cmd_id & AR_WMI_EVT_FLAG)) {
		mutex_enter(&usc->usc_cmd_mtx);
		if (usc->usc_wait_cmd_id == cmd_id) {

			if (usc->usc_obuf != NULL) {
				/* Copy answer into caller supplied buffer. */
				memcpy(usc->usc_obuf, &wmi[1], len - sizeof(*wmi));
			}
			/* Notify caller of completion. */
			usc->usc_wait_cmd_id = 0;
			cv_broadcast(&usc->usc_cmd_cv);
		}
		mutex_exit(&usc->usc_cmd_mtx);
		return;
	}
	/*
	 * XXX: the Linux 2.6 and 3.7.4 kernels differ on the event numbers!
	 * See the alternate defines in if_athn_usb.h.
	 */
	switch (cmd_id & 0xfff) {
#ifndef IEEE80211_STA_ONLY
#ifdef notyet
	case AR_WMI_EVT_SWBA:
		athn_usb_swba(usc);
		break;
#endif
#endif
	case AR_WMI_EVT_FATAL:
		aprint_error_dev(usc->usc_dev, "fatal firmware error\n");
		break;
	case AR_WMI_EVT_TXRATE:
#ifdef ATHN_DEBUG
		txrate = (struct ar_wmi_evt_txrate *)&wmi[1];
		DPRINTFN(DBG_TX, usc, "txrate=%d\n", be32toh(txrate->txrate));
#endif
		break;
	default:
		DPRINTFN(DBG_TX, usc, "WMI event %#x (%d) ignored\n", cmd_id, cmd_id);
		break;
	}
}

Static void
athn_usb_intr(struct usbwifi *uw, usbd_status status, uint32_t len)
{
	struct athn_usb_softc *usc = usbwifi_softc(uw);
	struct ar_htc_frame_hdr *htc;
	struct ar_htc_msg_hdr *msg;
	uint8_t *buf = usc->usc_ibuf;
	uint16_t msg_id;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	if (__predict_false(status != USBD_NORMAL_COMPLETION)) {
		DPRINTFN(DBG_INTR, usc, "intr status=%d\n", status);
		return;
	}

	/* Skip watchdog pattern if present. */
	if (len >= 4 && *(uint32_t *)buf == htobe32(0x00c60000)) {
		buf += 4;
		len -= 4;
	}
	if (__predict_false(len < (int)sizeof(*htc)))
		return;
	htc = (struct ar_htc_frame_hdr *)buf;
	/* Skip HTC header. */
	buf += sizeof(*htc);
	len -= sizeof(*htc);

	if (htc->endpoint_id != 0) {
		if (__predict_false(htc->endpoint_id != usc->usc_ep_ctrl)) {
			DPRINTFN(DBG_RX, usc, "Rx %d != %d\n",
			    htc->endpoint_id, usc->usc_ep_ctrl);
			return;
		}
		/* Remove trailer if present. */
		if (htc->flags & AR_HTC_FLAG_TRAILER) {
			if (__predict_false(len < htc->control[0])) {
				DPRINTFN(DBG_RX, usc, "Rx trailer %d < %d\n",
				    len,  htc->control[0]);
				return;
			}
			len -= htc->control[0];
		}
		athn_usb_rx_wmi_ctrl(usc, buf, len);
		return;
	}

	/*
	 * Endpoint 0 carries HTC messages.
	 */
	if (__predict_false(len < (int)sizeof(*msg)))
		return;
	msg = (struct ar_htc_msg_hdr *)buf;
	msg_id = be16toh(msg->msg_id);
	DPRINTFN(DBG_RX, usc, "Rx HTC message %d\n", msg_id);
	switch (msg_id) {
	case AR_HTC_MSG_READY:
	case AR_HTC_MSG_CONF_PIPE_RSP:
		mutex_enter(&usc->usc_msg_mtx);
		DPRINTFN(DBG_RX, usc, "AR_HTC_MSG_READY: %d vs %d\n",
		    usc->usc_wait_msg_id, msg_id);
		if (usc->usc_wait_msg_id == msg_id) {
			usc->usc_wait_msg_id = 0;
			cv_broadcast(&usc->usc_msg_cv);
		}
		mutex_exit(&usc->usc_msg_mtx);
		break;
	case AR_HTC_MSG_CONN_SVC_RSP:
		mutex_enter(&usc->usc_msg_mtx);
		DPRINTFN(DBG_RX, usc, "AR_HTC_MSG_CONN_SVC_RSP: %d vs %d\n",
		    usc->usc_wait_msg_id, msg_id);
		if (usc->usc_wait_msg_id == msg_id) {
			if (usc->usc_msg_conn_svc_rsp != NULL) {
				memcpy(usc->usc_msg_conn_svc_rsp, &msg[1],
				    sizeof(*usc->usc_msg_conn_svc_rsp));
			}
			usc->usc_wait_msg_id = 0;
			cv_broadcast(&usc->usc_msg_cv);
		}
		mutex_exit(&usc->usc_msg_mtx);
		break;
	default:
		DPRINTFN(DBG_RX, usc, "HTC message %d ignored\n", msg_id);
		break;
	}
}

#if 0
Static void
athn_usb_rx_radiotap(struct athn_common *ac, struct mbuf *m,
    struct ar_rx_status *rs)
{
	struct athn_rx_radiotap_header *tap = &ac->ac_rxtap;
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	uint8_t rate;

	DPRINTFN(DBG_FN, ac, "\n");

	tap->wr_flags = IEEE80211_RADIOTAP_F_FCS;
	tap->wr_tsft = htole64(be64toh(rs->rs_tstamp));
	tap->wr_chan_freq = htole16(ic->ic_curchan->ic_freq);
	tap->wr_chan_flags = htole16(ic->ic_curchan->ic_flags);
	tap->wr_dbm_antsignal = rs->rs_rssi;
	/* XXX noise. */
	tap->wr_antenna = rs->rs_antenna;
	rate = rs->rs_rate;
	if (rate & 0x80) {		/* HT. */
		/* Bit 7 set means HT MCS instead of rate. */
		tap->wr_rate = rate;
		if (!(rs->rs_flags & AR_RXS_FLAG_GI))
			tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTGI;
	} else if (rate & 0x10) {	/* CCK. */
		if (rate & 0x04)
			tap->wr_flags |= IEEE80211_RADIOTAP_F_SHORTPRE;
		switch (rate & ~0x14) {
		case 0xb: tap->wr_rate =   2; break;
		case 0xa: tap->wr_rate =   4; break;
		case 0x9: tap->wr_rate =  11; break;
		case 0x8: tap->wr_rate =  22; break;
		default:  tap->wr_rate =   0; break;
		}
	} else {			/* OFDM. */
		switch (rate) {
		case 0xb: tap->wr_rate =  12; break;
		case 0xf: tap->wr_rate =  18; break;
		case 0xa: tap->wr_rate =  24; break;
		case 0xe: tap->wr_rate =  36; break;
		case 0x9: tap->wr_rate =  48; break;
		case 0xd: tap->wr_rate =  72; break;
		case 0x8: tap->wr_rate =  96; break;
		case 0xc: tap->wr_rate = 108; break;
		default:  tap->wr_rate =   0; break;
		}
	}
	bpf_mtap2(ac->ac_drvbpf, tap, ac->ac_rxtap_len, m, BPF_D_IN);
}
#endif

Static void
athn_usb_rx_frame(struct athn_usb_softc *usc, struct mbuf *m)
{
	struct ieee80211com *ic = usbwifi_ic(&usc->usc_uw);
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct ar_htc_frame_hdr *htc;
	struct ar_rx_status *rs;
	uint16_t datalen;
	int s;

	DPRINTFN(DBG_FN, ac, "\n");

	if (__predict_false(m->m_len < (int)sizeof(*htc)))
		goto skip;
	htc = mtod(m, struct ar_htc_frame_hdr *);
	if (__predict_false(htc->endpoint_id == 0)) {
		DPRINTFN(DBG_RX, ac, "bad endpoint %d\n", htc->endpoint_id);
		goto skip;
	}
	if (htc->flags & AR_HTC_FLAG_TRAILER) {
		if (m->m_len < htc->control[0])
			goto skip;
		m_adj(m, -(int)htc->control[0]);
	}
	m_adj(m, sizeof(*htc));	/* Strip HTC header. */

	if (__predict_false(m->m_len < (int)sizeof(*rs)))
		goto skip;
	rs = mtod(m, struct ar_rx_status *);

	/* Make sure that payload fits. */
	datalen = be16toh(rs->rs_datalen);
	if (__predict_false(m->m_len < (int)sizeof(*rs) + datalen))
		goto skip;

	/* Ignore runt frames.  Let ACKs be seen by bpf */
	if (__predict_false(datalen <
		sizeof(struct ieee80211_frame_ack) + IEEE80211_CRC_LEN))
		goto skip;

	m_adj(m, sizeof(*rs));	/* Strip Rx status. */

	s = splnet();

	/* Grab a reference to the source node. */
	wh = mtod(m, struct ieee80211_frame *);
	ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)wh);

	/* Remove any HW padding after the 802.11 header. */
	if (!(wh->i_fc[0] & IEEE80211_FC0_TYPE_CTL)) {
		u_int hdrlen = ieee80211_anyhdrsize(wh);
		if (hdrlen & 3) {
			memmove((uint8_t *)wh + 2, wh, hdrlen);
			m_adj(m, 2);
		}
	}
#if 0
	if (__predict_false(ac->ac_drvbpf != NULL))
		athn_usb_rx_radiotap(ac, m, rs);
#endif

	/* Trim 802.11 FCS after radiotap. */
	m_adj(m, -IEEE80211_CRC_LEN);

	/* Send the frame to the 802.11 layer. */
	ieee80211_input(ni, m, rs->rs_rssi + AR_USB_DEFAULT_NF, 0);

	/* Node is no longer needed. */
	ieee80211_free_node(ni);
	splx(s);
	return;
 skip:
	m_freem(m);
}

Static void
athn_usb_rx_loop(struct usbwifi *uw, struct usbwifi_chain *chain,
    uint32_t len)
{
	struct athn_usb_softc *usc = usbwifi_softc(chain->uwc_uw);
	struct athn_usb_rx_stream *stream = &usc->usc_rx_stream;
	uint8_t *buf = chain->uwc_buf;
	struct ar_stream_hdr *hdr;
	struct mbuf *m;
	uint16_t pktlen;
	int off;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	if (stream->left > 0) {
		if (len >= stream->left) {
			/* We have all our pktlen bytes now. */
			if (__predict_true(stream->m != NULL)) {
				memcpy(mtod(stream->m, uint8_t *) +
				    stream->moff, buf, stream->left);
				athn_usb_rx_frame(usc, stream->m);
				stream->m = NULL;
			}
			/* Next header is 32-bit aligned. */
			off = (stream->left + 3) & ~3;
			buf += off;
			len -= off;
			stream->left = 0;
		} else {
			/* Still need more bytes, save what we have. */
			if (__predict_true(stream->m != NULL)) {
				memcpy(mtod(stream->m, uint8_t *) +
				    stream->moff, buf, len);
				stream->moff += len;
			}
			stream->left -= len;
			return;
		}
	}
	KASSERT(stream->left == 0);
	while (len >= (int)sizeof(*hdr)) {
		hdr = (struct ar_stream_hdr *)buf;
		if (hdr->tag != htole16(AR_USB_RX_STREAM_TAG)) {
			DPRINTFN(DBG_RX, usc, "invalid tag %#x\n", hdr->tag);
			break;
		}
		pktlen = le16toh(hdr->len);
		buf += sizeof(*hdr);
		len -= sizeof(*hdr);

		if (__predict_true(pktlen <= MCLBYTES)) {
			/* Allocate an mbuf to store the next pktlen bytes. */
			MGETHDR(m, M_DONTWAIT, MT_DATA);
			if (__predict_true(m != NULL)) {
				m->m_pkthdr.len = m->m_len = pktlen;
				if (pktlen > MHLEN) {
					MCLGET(m, M_DONTWAIT);
					if (!(m->m_flags & M_EXT)) {
						m_free(m);
						m = NULL;
					}
				}
			}
		} else	/* Drop frames larger than MCLBYTES. */
			m = NULL;
		/*
		 * NB: m can be NULL, in which case the next pktlen bytes
		 * will be discarded from the Rx stream.
		 */
		if (pktlen > len) {
			/* Need more bytes, save what we have. */
			stream->m = m;	/* NB: m can be NULL. */
			if (__predict_true(stream->m != NULL)) {
				memcpy(mtod(stream->m, uint8_t *), buf, len);
				stream->moff = len;
			}
			stream->left = pktlen - len;
			return;
		}
		if (__predict_true(m != NULL)) {
			/* We have all the pktlen bytes in this xfer. */
			memcpy(mtod(m, uint8_t *), buf, pktlen);
			athn_usb_rx_frame(usc, m);
		}

		/* Next header is 32-bit aligned. */
		off = (pktlen + 3) & ~3;
		buf += off;
		len -= off;
	}
}

#if 0
Static void
athn_usb_txeof(struct usbd_xfer *xfer, void * priv,
    usbd_status status)
{
	struct athn_usb_tx_data *data = priv;
	struct athn_usb_softc *usc = data->ac;
	struct athn_common *ac = &usc->usc_ac;
	int s;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, usc, "\n");

	s = splnet();
	/* Put this Tx buffer back to our free list. */
	mutex_enter(&usc->usc_tx_mtx);
	TAILQ_INSERT_TAIL(&usc->usc_tx_free_list, data, next);
	mutex_exit(&usc->usc_tx_mtx);

	if (__predict_false(status != USBD_NORMAL_COMPLETION)) {
		DPRINTFN(DBG_TX, ac, "TX status=%d\n", status);
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(usc->usc_tx_data_pipe);
		//if_statinc(ifp, if_oerrors);
		/* XXX */
		ieee80211_stat_add(usbwifi_ic(&usc->usc_uw).ic_oerrors, 1);
		splx(s);
		/* XXX Why return? */
		return;
	}
	ac->ac_tx_timer = 0;

	/* We just released a Tx buffer, notify Tx. */
	if (ac->ac_flags & ATHN_FLAG_TX_BUSY) {
		ac->ac_flags &= ~ATHN_FLAG_TX_BUSY;
		athn_usb_start(usc);
	}
	splx(s);
}
#endif

Static unsigned
athn_usb_tx_prepare(struct usbwifi *uw, struct usbwifi_chain *chain,
    uint8_t qid)
{
	struct athn_usb_softc *usc = usbwifi_softc(uw);
	struct mbuf *m = chain->uwc_mbuf;
	struct ieee80211_node *ni = chain->uwc_ni;
	struct athn_node *an = ATHN_NODE(ni);
	struct ieee80211com *ic = usbwifi_ic(uw);
	struct ieee80211_frame *wh;
	struct ieee80211_key *k = NULL;
	struct ar_stream_hdr *hdr;
	struct ar_htc_frame_hdr *htc;
	struct ar_tx_frame *txf;
	struct ar_tx_mgmt *txm;
	uint8_t *frm;
	uint8_t sta_index, tid;
	int xferlen;

	DPRINTFN(DBG_FN, ac, "\n");

	wh = mtod(m, struct ieee80211_frame *);
	if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED) {
		k = ieee80211_crypto_encap(ni, m);
		if (k == NULL)
			return ENOBUFS;

		/* packet header may have moved, reset our local pointer */
		wh = mtod(m, struct ieee80211_frame *);
	}
#ifdef notyet_edca
	if (ieee80211_has_qos(wh)) {
		uint16_t qos;

		qos = ieee80211_get_qos(wh);
		tid = qos & IEEE80211_QOS_TID;
		qid = ieee80211_up_to_ac(ic, tid);
	} else
#endif /* notyet_edca */
	{
		tid = 0; /* XXX */
		//qid = WME_AC_BE;
	}

#if 0
	/* XXX Change radiotap Tx header for USB (no txrate). */
	if (__predict_false(ac->ac_drvbpf != NULL)) {
		struct athn_tx_radiotap_header *tap = &ac->ac_txtap;

		tap->wt_flags = 0;
		tap->wt_chan_freq = htole16(ic->ic_curchan->ic_freq);
		tap->wt_chan_flags = htole16(ic->ic_curchan->ic_flags);
		if (wh->i_fc[1] & IEEE80211_FC1_PROTECTED)
			tap->wt_flags |= IEEE80211_RADIOTAP_F_WEP;

		bpf_mtap2(ac->ac_drvbpf, tap, ac->ac_txtap_len, m, BPF_D_OUT);
	}
#endif
	sta_index = an->sta_index;

	/* NB: We don't take advantage of USB Tx stream mode for now. */
	hdr = (struct ar_stream_hdr *)chain->uwc_buf;
	hdr->tag = htole16(AR_USB_TX_STREAM_TAG);

	htc = (struct ar_htc_frame_hdr *)&hdr[1];
	memset(htc, 0, sizeof(*htc));
	if ((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) ==
	    IEEE80211_FC0_TYPE_DATA) {
		htc->endpoint_id = usc->usc_ep_data[qid];

		txf = (struct ar_tx_frame *)&htc[1];
		memset(txf, 0, sizeof(*txf));
		txf->data_type = AR_HTC_NORMAL;
		txf->node_idx = sta_index;
		txf->vif_idx = 0;
		txf->tid = tid;
		if (m->m_pkthdr.len + IEEE80211_CRC_LEN
		    > TAILQ_FIRST(&(ic->ic_vaps))->iv_rtsthreshold)
			txf->flags |= htobe32(AR_HTC_TX_RTSCTS);
		else if (ic->ic_flags & IEEE80211_F_USEPROT) {
			if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
				txf->flags |= htobe32(AR_HTC_TX_CTSONLY);
			else if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
				txf->flags |= htobe32(AR_HTC_TX_RTSCTS);
		}
		txf->key_idx = 0xff;
		frm = (uint8_t *)&txf[1];
	} else {
		htc->endpoint_id = usc->usc_ep_mgmt;

		txm = (struct ar_tx_mgmt *)&htc[1];
		memset(txm, 0, sizeof(*txm));
		txm->node_idx = sta_index;
		txm->vif_idx = 0;
		txm->key_idx = 0xff;
		frm = (uint8_t *)&txm[1];
	}
	/* Copy payload. */
	m_copydata(m, 0, m->m_pkthdr.len, (void *)frm);
	frm += m->m_pkthdr.len;

	/* Finalize headers. */
	htc->payload_len = htobe16(frm - (uint8_t *)&htc[1]);
	hdr->len = htole16(frm - (uint8_t *)&hdr[1]);
	xferlen = frm - chain->uwc_buf;
	return xferlen;
}

#if 0
Static void
athn_usb_start(struct athn_usb_softc *usc)
{
	//struct athn_softc *sc = ATHN_SOFTC(usc);
	struct athn_usb_tx_data *data;
	struct ieee80211vap *vap = NULL;
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;
	struct mbuf *m;

	if (usbwifi_isdying(&usc->usc_uw))
		return;

	DPRINTFN(DBG_FN, ac, "\n");

	if (ac->ac_flags & ATHN_FLAG_TX_BUSY)
		return;

	data = NULL;
	for (;;) {
		mutex_enter(&usc->usc_tx_mtx);
		if (data == NULL && !TAILQ_EMPTY(&usc->usc_tx_free_list)) {
			data = TAILQ_FIRST(&usc->usc_tx_free_list);
			TAILQ_REMOVE(&usc->usc_tx_free_list, data, next);
		}
		mutex_exit(&usc->usc_tx_mtx);

		if (data == NULL) {
			ac->ac_flags |= ATHN_FLAG_TX_BUSY;
			return;
		}

		/* Encapsulate and send data frames. */
		IFQ_DEQUEUE(&ac->ac_sendq, m);
		if (m == NULL)
			break;

		ni = M_GETCTX(m, struct ieee80211_node *);
		M_CLEARCTX(m);
		vap = ni->ni_vap;

		if (m->m_len < (int)sizeof(*wh) &&
		    (m = m_pullup(m, sizeof(*wh))) == NULL) {
			if_statinc(vap->iv_ifp, if_oerrors);
			continue;
		}
		wh = mtod(m, struct ieee80211_frame *);
		if (ni == NULL) {
			m_freem(m);
			if_statinc(vap->iv_ifp, if_oerrors);
			continue;
		}

		/* bpf_mtap(ifp, m, BPF_D_OUT); */

		/* bpf_mtap3(ic->ic_rawbpf, m, BPF_D_OUT); */

		if (athn_usb_tx(ac, m, ni, data) != 0) {
			m_freem(m);
			ieee80211_free_node(ni);
			if_statinc(vap->iv_ifp, if_oerrors);
			continue;
		}
		data = NULL;
		m_freem(m);
		ieee80211_free_node(ni);
		ac->ac_tx_timer = 5;
		callout_schedule(&ac->ac_watchdog_to, hz);
	}

	/* Return the Tx buffer to the free list */
	mutex_enter(&usc->usc_tx_mtx);
	TAILQ_INSERT_TAIL(&usc->usc_tx_free_list, data, next);
	mutex_exit(&usc->usc_tx_mtx);
}
#endif

#if 0
Static void
athn_usb_watchdog(struct ifnet *ifp)
{
	struct athn_softc *sc = ifp->if_softc;

	DPRINTFN(DBG_FN, ac, "\n");

	ifp->if_timer = 0;

	if (ac->ac_tx_timer > 0) {
		if (--ac->ac_tx_timer == 0) {
			aprint_error_dev(ac->ac_dev, "device timeout\n");
			/* athn_usb_init(ifp); XXX needs a process context! */
			if_statinc(ifp, if_oerrors);
			return;
		}
		ifp->if_timer = 1;
	}
	ieee80211_watchdog(usbwifi_ic(&usc->usc_uw));
}
#endif

Static void
athn_usb_set_multi(struct ieee80211com *ic);
{
	struct athn_usb_softc *usc = ic->ic_softc;

	athn_set_multi_common(&usc->usc_ac);
}

Static void
athn_usb_set_channel(struct ieee80211com *ic)
{
	struct athn_usb_softc *usc = ic->ic_softc;

	athn_switch_chan(sc, ic->ic_curchan, NULL); /* XXX extchan? */
}

#if 0
Static int
athn_usb_init(struct athn_usb_softc *usc)
{
	usbwifi_lock_ic(&usc->usc_uw);
	int ret = athn_usb_init_locked(&usc->usc_uw);
	usbwifi_unlock_ic(&usc->usc_uw);

	return ret;
}
#endif

Static int
athn_usb_init_locked(struct usbwifi *uw)
{
	struct athn_usb_softc *usc = usbwifi_softc(uw);
	struct athn_common *ac = &usc->usc_ac;
	struct athn_ops *ops = &ac->ac_ops;
	struct ieee80211com *ic = usbwifi_ic(uw);
	struct ieee80211_channel *curchan, *extchan;
	struct ar_htc_target_vif hvif;
	struct ar_htc_target_sta sta;
	struct ar_htc_cap_target hic;
	uint16_t mode;
	int error;

	if (usbwifi_isdying(uw))
		return USBD_CANCELLED;

	DPRINTFN(DBG_FN, ac, "\n");

	/* Init host async commands ring. */
	mutex_spin_enter(&usc->usc_task_mtx);
	usc->usc_cmdq.cur = usc->usc_cmdq.next = usc->usc_cmdq.queued = 0;
	mutex_spin_exit(&usc->usc_task_mtx);

	curchan = ic->ic_curchan;
	extchan = NULL;

	/* In case a new MAC address has been configured. */
	//IEEE80211_ADDR_COPY(ic->ic_macaddr, CLLADDR(ifp->if_sadl));

	error = athn_set_power_awake(ac);
	if (error != 0)
		goto fail;

	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_FLUSH_RECV);
	if (error != 0)
		goto fail;

	error = athn_hw_reset(ac, curchan, extchan, 1);
	if (error != 0)
		goto fail;

	ops->set_txpower(ac, curchan, extchan);

	mode = htobe16(IEEE80211_IS_CHAN_2GHZ(curchan) ?
	    AR_HTC_MODE_11NG : AR_HTC_MODE_11NA);
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_SET_MODE,
	    &mode, sizeof(mode), NULL);
	if (error != 0)
		goto fail;

	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_ATH_INIT);
	if (error != 0)
		goto fail;

	error = athn_usb_wmi_cmd(usc, AR_WMI_CMD_START_RECV);
	if (error != 0)
		goto fail;

	//athn_rx_start(ac);

	/* Create main interface on target. */
	memset(&hvif, 0, sizeof(hvif));
	hvif.index = 0;
	IEEE80211_ADDR_COPY(hvif.myaddr, ic->ic_macaddr);
	switch (ic->ic_opmode) {
	case IEEE80211_M_STA:
		hvif.opmode = htobe32(AR_HTC_M_STA);
		break;
	case IEEE80211_M_MONITOR:
		hvif.opmode = htobe32(AR_HTC_M_MONITOR);
		break;
#ifndef IEEE80211_STA_ONLY
	case IEEE80211_M_IBSS:
		hvif.opmode = htobe32(AR_HTC_M_IBSS);
		break;
	case IEEE80211_M_AHDEMO:
		hvif.opmode = htobe32(AR_HTC_M_AHDEMO);
		break;
	case IEEE80211_M_HOSTAP:
		hvif.opmode = htobe32(AR_HTC_M_HOSTAP);
		break;
#endif
	default:
		break;
	}
	/* hvif.rtsthreshold = htobe16(ic->ic_rtsthreshold); */
	DPRINTFN(DBG_INIT, ac, "creating VAP\n");
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_VAP_CREATE,
	    &hvif, sizeof(hvif), NULL);
	if (error != 0)
		goto fail;

	/* Create a fake node to send management frames before assoc. */
	memset(&sta, 0, sizeof(sta));
	IEEE80211_ADDR_COPY(sta.macaddr, ic->ic_macaddr);
	sta.sta_index = 0;
	sta.is_vif_sta = 1;
	sta.vif_index = hvif.index;
	sta.maxampdu = 0xffff;

	DPRINTFN(DBG_INIT | DBG_NODES, ac, "creating default node %u\n",
	    sta.sta_index);
	error = athn_usb_create_hw_node(usc, &sta);
	if (error != 0)
		goto fail;

	/* Update target capabilities. */
	memset(&hic, 0, sizeof(hic));
	hic.flags = htobe32(0x400c2400);
	hic.flags_ext = htobe32(0x00106080);
	hic.ampdu_limit = htobe32(0x0000ffff);
	hic.ampdu_subframes = 20;
	hic.protmode = 1;	/* XXX */
	hic.lg_txchainmask = ac->ac_txchainmask;
	hic.ht_txchainmask = ac->ac_txchainmask;
	DPRINTFN(DBG_INIT, ac, "updating target configuration\n");
	error = athn_usb_wmi_xcmd(usc, AR_WMI_CMD_TARGET_IC_UPDATE,
	    &hic, sizeof(hic), NULL);
	if (error != 0)
		goto fail;

#if 0
	/* Queue Rx xfers. */
	for (i = 0; i < ATHN_USB_RX_LIST_COUNT; i++) {
		data = &usc->usc_rx_data[i];

		usbd_setup_xfer(data->xfer, data, data->buf,
		    ATHN_USB_RXBUFSZ, USBD_SHORT_XFER_OK,
		    USBD_NO_TIMEOUT, athn_usb_rxeof);
		error = usbd_transfer(data->xfer);
		if (error != 0 && error != USBD_IN_PROGRESS)
			goto fail;
	}
	/* We're ready to go. */
	ifp->if_flags &= ~IFF_OACTIVE;
	ifp->if_flags |= IFF_RUNNING;
#endif

#ifdef notyet
	if (ic->ic_flags & IEEE80211_F_WEPON) {
		/* Install WEP keys. */
		for (i = 0; i < IEEE80211_WEP_NKID; i++)
			athn_usb_set_key(ic, NULL, &ic->ic_nw_keys[i]);
	}
#endif
#ifdef XXX
	if (ic->ic_opmode == IEEE80211_M_HOSTAP)
		ic->ic_max_aid = AR_USB_MAX_STA;  /* Firmware is limited to 8 STA */
	else
		ic->ic_max_aid = ac->ac_max_aid;

	if (ic->ic_opmode == IEEE80211_M_MONITOR)
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
	else
		ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
#endif
	athn_usb_wait_async(usc);
	return 0;
 fail:
	athn_usb_stop(usc, 0);
	return error;
}

Static void
athn_usb_stop(struct athn_usb_softc *usc, int disable)
{
	usbwifi_lock_ic(&usc->usc_uw);
	athn_usb_stop_locked(&usc->usc_uw);
	usbwifi_unlock_ic(&usc->usc_uw);
}

Static void
athn_usb_stop_locked(struct usbwifi *uw)
{
	struct athn_usb_softc *usc = usbwifi_softc(uw);
	struct athn_common *ac = &usc->usc_ac;
	struct ieee80211com *ic = usbwifi_ic(uw);
	struct ar_htc_target_vif hvif;
	struct mbuf *m;
	uint8_t sta_index;
	int s;

	DPRINTFN(DBG_FN, ac, "\n");

	s = splusb();
	//ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
	athn_usb_wait_async(usc);
	splx(s);

	ac->ac_tx_timer = 0;
	//ifp->if_timer = 0;
	//ifp->if_flags &= ~(IFF_RUNNING | IFF_OACTIVE);

	callout_stop(&ac->ac_scan_to);
	callout_stop(&ac->ac_calib_to);

	/* Abort Tx/Rx. */
	//usbd_abort_pipe(usc->usc_tx_data_pipe);
	//usbd_abort_pipe(usc->usc_rx_data_pipe);

	/* Flush Rx stream. */
	CTASSERT(sizeof(m) == sizeof(void *));
	m = atomic_swap_ptr(&usc->usc_rx_stream.m, NULL);
	m_freem(m);
	usc->usc_rx_stream.left = 0;

	/* Remove main interface. */
	memset(&hvif, 0, sizeof(hvif));
	hvif.index = 0;
	IEEE80211_ADDR_COPY(hvif.myaddr, ic->ic_macaddr);
	(void)athn_usb_wmi_xcmd(usc, AR_WMI_CMD_VAP_REMOVE,
	    &hvif, sizeof(hvif), NULL);

	/* Remove default node. */
	sta_index = 0;
	DPRINTFN(DBG_NODES, usc, "removing node %u\n", sta_index);
	(void)athn_usb_remove_hw_node(usc, &sta_index);

	(void)athn_usb_wmi_cmd(usc, AR_WMI_CMD_DISABLE_INTR);
	(void)athn_usb_wmi_cmd(usc, AR_WMI_CMD_DRAIN_TXQ_ALL);
	(void)athn_usb_wmi_cmd(usc, AR_WMI_CMD_STOP_RECV);

	athn_reset(ac, 0);
	athn_init_pll(ac, NULL);
	athn_set_power_awake(ac);
	athn_reset(ac, 1);
	athn_init_pll(ac, NULL);
	athn_set_power_sleep(ac);
}

static struct ieee80211vap *
athn_usb_vap_create(struct ieee80211com *ic,  const char name[IFNAMSIZ],
    int unit, enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t macaddr[IEEE80211_ADDR_LEN])
{
	struct athn_usb_softc *usc = ic->ic_softc;
	struct athn_common *ac = &usc->usc_ac;
	struct ieee80211vap *vap;

	vap = athn_vap_create_common(ac, ic, name, unit, opmode,
		flags, bssid, macaddr);
	vap->iv_newstate = athn_usb_newstate;
	return vap;
}

MODULE(MODULE_CLASS_DRIVER, if_athn_usb, NULL);

#ifdef _MODULE
#include "ioconf.c"
#endif

static int
if_athn_usb_modcmd(modcmd_t cmd, void *aux)
{
	int error = 0;

	switch (cmd) {
	case MODULE_CMD_INIT:
#ifdef _MODULE
		error = config_init_component(cfdriver_ioconf_if_athn_usb,
		    cfattach_ioconf_if_athn_usb, cfdata_ioconf_if_athn_usb);
#endif
		return error;
	case MODULE_CMD_FINI:
#ifdef _MODULE
		error = config_fini_component(cfdriver_ioconf_if_athn_usb,
		    cfattach_ioconf_if_athn_usb, cfdata_ioconf_if_athn_usb);
#endif
		return error;
	default:
		return ENOTTY;
	}
}
