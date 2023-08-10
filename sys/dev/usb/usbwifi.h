/*	$NetBSD: usbwifi.h,v 1.19 2020/10/28 01:51:45 mrg Exp $	*/

/*
 * Copyright (c) 2019 Matthew R. Green
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _DEV_USB_USBWIFI_H
#define _DEV_USB_USBWIFI_H

/*
 * Common code/data shared by all USB wifi drivers (using these routines.)
 *
 * This framework provides the following features for USB wifi drivers:
 *
 * - USB endpoint pipe handling
 * - rx and tx chain handling
 * - interrupt handling
 * - partial autoconf handling
 *
 * Consumers of this interface need to:
 *
 * - replace most softc members with "struct usbwifi" usage, in particular
 *   use usbwifi pointer for ieee80211com and sendq, and device_private
 *   (real softc can be stored in uw_sc member)
 * - usbwifi_attach() to initialise the structure and preset default
 *   callbacks.
 * - usbwifi_ic_attach() to allocate rx/tx chains and add the device to
 *   the list of wifi devices.
 *   caveat: this will overwrite uw->uw_ic.ic_raw_xmit!
 *	     if your driver needs to overwrite this, set the pointer after
 *	     this call.
 * - usbwifi_attach_finalize() to complete attachment
 * - usbwifi_detach() to clean them up
 * - usbwifi_activate() for autoconf
 * - interrupt handling:
 *   - for rx, usbwifi will enable the receive pipes and
 *     call the rx_loop callback to handle device specific processing of
 *     packets, which can use usbwifi_enqueue() to provide data to the
 *     higher layers
 *   - for tx, usbwifi will pull entries out of the
 *     transmit queues and use the 'uwo_tx_prepare' callback for the given
 *     mbuf.
 *     the usb callback will use usbwifi_txeof() for the transmit
 *     completion function (internal to usbwifi)
 *   - there is special interrupt pipe handling
 * - priority handling:
 *   - many wifi chipsets offer multiple tx pipes (with priority).
 *   - there is a separate mbuf queue for each priority (uwp_sendq[prio]
 *     in the framework private data part)
 *   - the mbuf queue index matches the pipe index
 *   - wme priorities are mapped to pipe/mbuf queue indices via uw_ac2idx[]
 *   - the highest priority queue/pipe always has index 0, the last used
 *     index (uw_ic.ic_txstream-1) has the lowest priority
 * - timer/tick:
 *   - the uwo_tick callback will be called once a second if present.
 */

#include <sys/device.h>
#include <sys/mbuf.h>
#include <sys/rndsource.h>
#include <sys/mutex.h>
#include <sys/module.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_media.h>
#include <net80211/ieee80211_netbsd.h>
#include <net80211/ieee80211_var.h>

#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>

#include <dev/usb/usb.h>
#include <dev/usb/usbdi.h>
#include <dev/usb/usbdivar.h>
#include <dev/usb/usbdi_util.h>
#include <dev/usb/usbdevs.h>

/*
 * Per-transfer data.
 */
struct usbwifi;
struct usbwifi_chain {
	struct usbwifi		*uwc_uw;
	struct usbd_xfer	*uwc_xfer;
	uint8_t			*uwc_buf;
	unsigned		uwc_index;	/* which pipe is this on -
						 * index into uw_ed */
	struct mbuf		*uwc_mbuf;
	struct ieee80211_node	*uwc_ni;
};

/* Extend this as necessary. */
#define	USBWIFI_ENDPT_MAX	6

/* Interface stop callback. */
typedef void (*usbwifi_stop_cb)(struct usbwifi *);
/* Initialise device callback. */
typedef int (*usbwifi_init_cb)(struct usbwifi *);

/* Prepare TX packet for USB transfer, returns length. */
typedef unsigned (*usbwifi_tx_prepare_cb)(struct usbwifi *,
					struct usbwifi_chain *,
					uint8_t qid);
/* Receive some packets callback. */
typedef void (*usbwifi_rx_loop_cb)(struct usbwifi *, struct usbwifi_chain *,
				  uint32_t);
/* Tick callback. */
typedef void (*usbwifi_tick_cb)(struct usbwifi *);
/* Interrupt pipe callback. */
typedef void (*usbwifi_intr_cb)(struct usbwifi *, usbd_status, uint32_t);

/*
 * LOCKING
 * =======
 *
 * The following annotations indicate which locks are held when
 * usbwifi_ops functions are invoked:
 *
 * I -> IC LOCK (usbwifi ic_lock aka IEEE80211_LOCK)
 * T -> TX_LOCK (usbwifi tx_lock)
 * R -> RX_LOCK (usbwifi rx_lock)
 * n -> no locks held
 *
 * Note that none of this locks may be taken before usbwifi_ic_attach()
 * has been called, and the IC lock is automatically taken in that
 * function and released at the end of usbwifi_attach_finalize().
 */
struct usbwifi_ops {
	usbwifi_stop_cb		uwo_stop;		/* I */
	usbwifi_init_cb		uwo_init;		/* I */
	usbwifi_tx_prepare_cb	uwo_tx_prepare;		/* T */
	usbwifi_rx_loop_cb	uwo_rx_loop;		/* R */
	usbwifi_tick_cb		uwo_tick;		/* n */
	usbwifi_intr_cb		uwo_intr;		/* n */
};

/*
 * USB interrupt pipe support.  Use this if usbd_open_pipe_intr() should
 * be used for the interrupt pipe.
 */
struct usbwifi_intr {
	/*
	 * Point uw_intr to this structure to use usbd_open_pipe_intr() not
	 * usbd_open_pipe() for uw_ep[uw_intr->uwi_index], with this
	 * buffer, size, and interval. uwi_index should be the last
	 * valid entry in uw_ep.
	 */
	void			*uwi_buf;
	unsigned		uwi_bufsz;
	unsigned		uwi_interval;
	unsigned		uwi_index;	/* index into uw_ed */
};

/*
 * Generic USB wifi structure.
 */
struct usbwifi_private;
struct usbwifi {
	/*
	 * This section should be filled in before calling
	 * usbwifi_attach().
	 */
	void			*uw_sc;			/* real softc */
	device_t		uw_dev;
	struct ieee80211com	uw_ic;			/* common wifi data */
	struct usbd_interface	*uw_iface;
	struct usbd_device	*uw_udev;
	const struct usbwifi_ops *uw_ops;
	struct usbwifi_intr	*uw_intr;

	/* Inputs for rx/tx chain control. */
	unsigned		uw_rx_bufsz;
	unsigned		uw_tx_bufsz;
	unsigned		uw_rx_list_cnt;
	unsigned		uw_tx_list_cnt;
	unsigned		uw_rxpipes;
	unsigned		uw_txpipes;
	uint16_t		uw_rx_xfer_flags;
	uint16_t		uw_tx_xfer_flags;
	uint32_t		uw_rx_xfer_timeout;
	uint32_t		uw_tx_xfer_timeout;

	/*
	 * This section should be filled in before calling
	 * usbwifi_attach_ic().
	 * Sort TX first (high -> low priority), then all RX, then
	 * interrupt. Make sure uw_intr->uwi_index matches the index
	 * of the interrupt entry.
	 */
	uByte			uw_ed[USBWIFI_ENDPT_MAX];
	size_t			uw_ac2idx[WME_NUM_AC];	/* priority mapping */

	/*
	 * This section is for driver to use, not touched by usbwifi.
	 */
	unsigned		uw_flags;

	/*
	 * This section is private to usbwifi. Don't touch.
	 */
	struct usbwifi_private	*uw_pri;
};

/* Various accessors. */
void *usbwifi_softc(struct usbwifi *);
struct ieee80211com *usbwifi_ic(struct usbwifi *);
krndsource_t *usbwifi_rndsrc(struct usbwifi *);
bool usbwifi_isdying(struct usbwifi *);


/*
 * Locking.
 */
static __inline void
usbwifi_lock_ic(struct usbwifi *uw)
{
	IEEE80211_LOCK(&uw->uw_ic);
}

static __inline void
usbwifi_unlock_ic(struct usbwifi *uw)
{
	IEEE80211_UNLOCK(&uw->uw_ic);
}

static __inline kmutex_t *
usbwifi_mutex_ic(struct usbwifi *uw)
{
	return IEEE80211_LOCK_OBJ(&uw->uw_ic);
}

static __inline void
usbwifi_isowned_ic(struct usbwifi *uw)
{
	KASSERT(uw->uw_pri == NULL || mutex_owned(usbwifi_mutex_ic(uw)));
}

/*
 * Endpoint / rx/tx chain management:
 *
 * usbwifi_attach() initialises usbwifi,
 * usbwifi_ic_attach() allocates rx and tx chains and presets default
 * function pointers in the common IC structure, which then may be
 * overwritten by driver specific versions.
 * usbwifi_attach_finalize() announces the radio to the IEEE80211
 * subsystem.
 * After the uwo_init() callback reported success, usbwifi
 * opens all pipes and initialises the rx/tx chains for use.
 * When stopping the hardware, usbwifi
 *  - stops pipes
 *  - calls the uwo_stop callback to stop hardware (unless we are
 *    about to detach)
 *  - closes pipes
 * usbwifi_detach() frees the rx/tx chains.
 *
 * Setup uw_ed[] with valid end points before calling usbwifi_attach().
 */

/* interrupt handling */
void	usbwifi_enqueue(struct usbwifi * un, uint8_t *buf, size_t buflen,
	       int rssi, int csum_flags, uint32_t csum_data, int mbuf_flags);

/* autoconf */
void	usbwifi_attach(struct usbwifi *uw);
void	usbwifi_ic_attach(struct usbwifi *uw, int, int, int, int, int);
void	usbwifi_attach_finalize(struct usbwifi *uw);
int	usbwifi_detach(device_t, int);
int	usbwifi_activate(device_t, devact_t);

/* generic IEEE80211 ic callbacks */
void	usbwifi_parent(struct ieee80211com *);


/* module hook up */

#ifdef _MODULE
#define USBWIFI_INIT(name)						\
	error = config_init_component(cfdriver_ioconf_##name,		\
	    cfattach_ioconf_##name, cfdata_ioconf_##name);
#define USBWIFI_FINI(name)						\
	error = config_fini_component(cfdriver_ioconf_##name,		\
	    cfattach_ioconf_##name, cfdata_ioconf_##name);
#else
#define USBWIFI_INIT(name)
#define USBWIFI_FINI(name)
#endif

#define USBWIFI_MODULE(name)						\
									\
MODULE(MODULE_CLASS_DRIVER, if_##name, "usbwifi");			\
									\
static int								\
if_##name##_modcmd(modcmd_t cmd, void *aux)				\
{									\
	int error = 0;							\
									\
	switch (cmd) {							\
	case MODULE_CMD_INIT:						\
		USBWIFI_INIT(name)					\
		return error;						\
	case MODULE_CMD_FINI:						\
		USBWIFI_FINI(name)					\
		return error;						\
	default:							\
		return ENOTTY;						\
	}								\
}

#endif /* _DEV_USB_USBWIFI_H */
