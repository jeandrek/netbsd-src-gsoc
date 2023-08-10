/*	$NetBSD: usbwifi.c,v 1.39 2020/08/28 17:05:32 riastradh Exp $	*/

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

/*
 * Common code shared between USB wifi network drivers.
 */

#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: usbwifi.c,v 1.39 2020/08/28 17:05:32 riastradh Exp $");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/kmem.h>
#include <sys/module.h>
#include <sys/atomic.h>

#include <net/if_ether.h>

#include <dev/usb/usbwifi.h>
#include <dev/usb/usbhist.h>

struct usbwifi_single_chain_data {
	struct usbwifi_chain	*uwscd_chain;	/* uw_{rx/tx}_list_cnt items */
	int			uwscd_tx_prod;	/* producer index */
	int			uwscd_tx_cnt;	/* active entries in the ring */
};

struct usbwifi_cdata {
	struct usbwifi_single_chain_data	*uwcd_tx_chains;
	struct usbwifi_single_chain_data	*uwcd_rx_chains;
};

struct usbwifi_private {
	/*
	 * - IEEE80211_LOCK protects most of this structure and the public one.
	 * - uwp_rxlock protects the rx path and its data
	 * - uwp_txlock protects the tx path and its data
	 *
	 * the lock ordering is:
	 *	IFNET_LOCK(ifp) -> IEEE80211_LOCK
	 *	    -> uwp_rxlock -> uwp_txlock
	 * - ifnet lock is not needed for any of the locks,
	 *   but if it is involved, it must be taken first.
	 */
	kmutex_t		uwp_rxlock;
	kmutex_t		uwp_txlock;

	struct usbwifi_cdata	uwp_cdata;

	struct usb_task		uwp_ticktask;
	struct callout		uwp_stat_ch;
	/*
	 * Endpoints: all TX first, then RX, then interrupt.
	 * Typically TX pipes are orderd by priority (highest first).
	 * All remaining (unused) entries are zero.
	 */
	struct usbd_pipe	*uwp_ep[USBWIFI_ENDPT_MAX];
	struct ifqueue		uwp_sendq[WME_NUM_AC];	/* send queues */

	volatile bool		uwp_dying;
	bool			uwp_stopping;
	bool			uwp_attached;

	int			uwp_timer;
	unsigned short		uwp_if_flags;
	unsigned		uwp_number;

	krndsource_t		uwp_rndsrc;

	struct timeval		uwp_rx_notice;
	struct timeval		uwp_tx_notice;
	struct timeval		uwp_intr_notice;
};

#define uw_cdata(uw)	(&(uw)->uw_pri->uwp_cdata)

volatile unsigned usbwifi_number;

static int usbwifi_modcmd(modcmd_t, void *);
static void usbwifi_tx_prio_start(struct usbwifi *uw, unsigned prio);

#ifdef USB_DEBUG
#ifndef USBWIFI_DEBUG
#define usbwifidebug 0
#else
static int usbwifidebug = 0;

SYSCTL_SETUP(sysctl_hw_usbwifi_setup, "sysctl hw.usbwifi setup")
{
	int err;
	const struct sysctlnode *rnode;
	const struct sysctlnode *cnode;

	err = sysctl_createv(clog, 0, NULL, &rnode,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE, "usbwifi",
	    SYSCTL_DESCR("usbwifi global controls"),
	    NULL, 0, NULL, 0, CTL_HW, CTL_CREATE, CTL_EOL);

	if (err)
		goto fail;

	/* control debugging printfs */
	err = sysctl_createv(clog, 0, &rnode, &cnode,
	    CTLFLAG_PERMANENT | CTLFLAG_READWRITE, CTLTYPE_INT,
	    "debug", SYSCTL_DESCR("Enable debugging output"),
	    NULL, 0, &usbwifidebug, sizeof(usbwifidebug), CTL_CREATE, CTL_EOL);
	if (err)
		goto fail;

	return;
fail:
	aprint_error("%s: sysctl_createv failed (err = %d)\n", __func__, err);
}

#endif /* USBWIFI_DEBUG */
#endif /* USB_DEBUG */

#define DPRINTF(FMT,A,B,C,D)	USBHIST_LOGN(usbwifidebug,1,FMT,A,B,C,D)
#define DPRINTFN(N,FMT,A,B,C,D)	USBHIST_LOGN(usbwifidebug,N,FMT,A,B,C,D)
#define USBWIFIHIST_FUNC()	USBHIST_FUNC()
#define USBWIFIHIST_CALLED(name)	USBHIST_CALLED(usbwifidebug)
#define USBWIFIHIST_CALLARGS(FMT,A,B,C,D) \
				USBHIST_CALLARGS(usbwifidebug,FMT,A,B,C,D)
#define USBWIFIHIST_CALLARGSN(N,FMT,A,B,C,D) \
				USBHIST_CALLARGSN(usbwifidebug,N,FMT,A,B,C,D)

/* Callback vectors. */

static void
uwo_stop(struct usbwifi *uw)
{
	if (uw->uw_ops->uwo_stop)
		(*uw->uw_ops->uwo_stop)(uw);
}

static int
uwo_init(struct usbwifi *uw)
{
	if (uw->uw_ops->uwo_init)
		return (*uw->uw_ops->uwo_init)(uw);
	return ENXIO;
}

static unsigned
uwo_tx_prepare(struct usbwifi *uw, struct usbwifi_chain *c, uint8_t qid)
{
	KASSERT(mutex_owned(&uw->uw_pri->uwp_txlock));
	return (*uw->uw_ops->uwo_tx_prepare)(uw, c, qid);
}

static void
uwo_rx_loop(struct usbwifi *uw, struct usbwifi_chain *c, uint32_t total_len)
{
	KASSERT(mutex_owned(&uw->uw_pri->uwp_rxlock));
	(*uw->uw_ops->uwo_rx_loop)(uw, c, total_len);
}

static void
uwo_tick(struct usbwifi *un)
{
	if (un->uw_ops->uwo_tick)
		(*un->uw_ops->uwo_tick)(un);
}

static void
uwo_intr(struct usbwifi *un, usbd_status status, uint32_t len)
{
	if (un->uw_ops->uwo_intr)
		(*un->uw_ops->uwo_intr)(un, status, len);
}

/* Interrupt handling. */

static struct mbuf *
usbwifi_newbuf(size_t buflen)
{
	struct mbuf *m;

	if (buflen > MCLBYTES)
		return NULL;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return NULL;

	if (buflen > MHLEN - ETHER_ALIGN) {
		MCLGET(m, M_DONTWAIT);
		if (!(m->m_flags & M_EXT)) {
			m_freem(m);
			return NULL;
		}
	}

	m_adj(m, ETHER_ALIGN);
	m->m_len = m->m_pkthdr.len = buflen;

	return m;
}

/*
 * usbwifi_rxeof() is designed to be the done callback for rx completion.
 * it provides generic setup and finalisation, calls a different usbwifi
 * rx_loop callback in the middle, which can use usbwifi_enqueue() to
 * enqueue a packet for higher levels.
 */
void
usbwifi_enqueue(struct usbwifi * const uw, uint8_t *buf, size_t buflen,
	       int rssi, int csum_flags, uint32_t csum_data, int mbuf_flags)
{
	USBWIFIHIST_FUNC();
	struct usbwifi_private * const uwp __unused = uw->uw_pri;
	struct mbuf *m;
	struct ieee80211com *ic = &uw->uw_ic;

	USBWIFIHIST_CALLARGSN(5, "%jd: enter: len=%ju csf %#jx mbf %#jx",
	    uwp->uwp_number, buflen, csum_flags, mbuf_flags);

	KASSERT(mutex_owned(&uwp->uwp_rxlock));

	m = usbwifi_newbuf(buflen);
	if (m == NULL) {
		DPRINTF("%jd: no memory", uwp->uwp_number, 0, 0, 0);
		ieee80211_stat_add(&ic->ic_ierrors, 1);
		return;
	}

	m->m_pkthdr.csum_flags = csum_flags;
	m->m_pkthdr.csum_data = csum_data;
	m->m_flags |= mbuf_flags;
	memcpy(mtod(m, uint8_t *), buf, buflen);
	ieee80211_rx_enqueue(ic, m, rssi);
}

/*
 * A frame has been uploaded: pass the resulting mbuf chain up to
 * the higher level protocols.
 */
static void
usbwifi_rxeof(struct usbd_xfer *xfer, void *priv, usbd_status status)
{
	USBWIFIHIST_FUNC();
	struct usbwifi_chain * const c = priv;
	struct usbwifi * const uw = c->uwc_uw;
	struct usbwifi_private * const uwp = uw->uw_pri;
	uint32_t total_len = ~0U;

	USBWIFIHIST_CALLARGSN(5, "%jd: enter: status %#jx xfer %#jx",
	    uwp->uwp_number, status, (uintptr_t)xfer, 0);

	mutex_enter(&uwp->uwp_rxlock);

	if (uwp->uwp_dying || uwp->uwp_stopping ||
	    status == USBD_INVAL || status == USBD_NOT_STARTED ||
	    status == USBD_CANCELLED)
		goto out;

	if (status != USBD_NORMAL_COMPLETION) {
		if (usbd_ratecheck(&uwp->uwp_rx_notice))
			aprint_error_dev(uw->uw_dev, "usb errors on rx: %s\n",
			    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(
			    uwp->uwp_ep[c->uwc_index]);
		goto done;
	}

	usbd_get_xfer_status(xfer, NULL, NULL, &total_len, NULL);

	if (total_len > uw->uw_rx_bufsz) {

#if 1	/* XXX remove this block */
		KASSERT(xfer == c->uwc_xfer);
		panic("rxeof: too large transfer (%u > %u) on pipe %u,"
		    " status %x\n",
		    total_len, uw->uw_rx_bufsz, c->uwc_index, status);
#endif

		aprint_error_dev(uw->uw_dev,
		    "rxeof: too large transfer (%u > %u)\n",
		    total_len, uw->uw_rx_bufsz);
		goto done;
	}

	uwo_rx_loop(uw, c, total_len);
	KASSERT(mutex_owned(&uwp->uwp_rxlock));

done:
	if (uwp->uwp_dying || uwp->uwp_stopping)
		goto out;

	/* Setup new transfer. */
	usbd_setup_xfer(xfer, c, c->uwc_buf, uw->uw_rx_bufsz,
	    uw->uw_rx_xfer_flags, uw->uw_rx_xfer_timeout, usbwifi_rxeof);
	usbd_transfer(xfer);
	mutex_exit(&uwp->uwp_rxlock);

	return;

out:
	mutex_exit(&uwp->uwp_rxlock);
}

static void
usbwifi_txeof(struct usbd_xfer *xfer, void *priv, usbd_status status)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();
	struct usbwifi_chain * const c = priv;
	struct usbwifi * const uw = c->uwc_uw;
	struct usbwifi_cdata * const cd = uw_cdata(uw);
	struct usbwifi_private * const uwp = uw->uw_pri;
	struct usbwifi_single_chain_data *s_chain;
	struct ifnet *ifp;

	USBWIFIHIST_CALLARGSN(5, "%jd: enter: status %#jx xfer %#jx",
	    uwp->uwp_number, status, (uintptr_t)xfer, 0);

	mutex_enter(&uwp->uwp_txlock);
	if (uwp->uwp_stopping || uwp->uwp_dying) {
		mutex_exit(&uwp->uwp_txlock);
		return;
	}

	s_chain = &cd->uwcd_tx_chains[c->uwc_index];
	ifp = c->uwc_ni->ni_vap->iv_ifp;
	KASSERT(s_chain->uwscd_tx_cnt > 0);
	s_chain->uwscd_tx_cnt--;

	uwp->uwp_timer = 0;

	switch (status) {
	case USBD_NOT_STARTED:
	case USBD_CANCELLED:
		break;

	case USBD_NORMAL_COMPLETION:
		if_statinc(ifp, if_opackets);
		break;

	default:

		if_statinc(ifp, if_oerrors);
		if (usbd_ratecheck(&uwp->uwp_tx_notice))
			aprint_error_dev(uw->uw_dev, "usb error on tx: %s\n",
			    usbd_errstr(status));
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(
			    uwp->uwp_ep[c->uwc_index]);
		break;
	}

	if (status == USBD_NORMAL_COMPLETION &&
	    !IFQ_IS_EMPTY(&uwp->uwp_sendq[c->uwc_index]))
		usbwifi_tx_prio_start(uw, c->uwc_index);

	mutex_exit(&uwp->uwp_txlock);
}

static void
usbwifi_pipe_intr(struct usbd_xfer *xfer, void *priv, usbd_status status)
{
	USBWIFIHIST_FUNC();
	struct usbwifi * const un = priv;
	struct usbwifi_private * const unp = un->uw_pri;
	struct usbwifi_intr * const uwi = un->uw_intr;
	uint32_t len;

	if (uwi == NULL || unp->uwp_dying || unp->uwp_stopping ||
	    status == USBD_INVAL || status == USBD_NOT_STARTED ||
	    status == USBD_CANCELLED) {
		USBWIFIHIST_CALLARGS("%jd: uwi %#jx d/s %#jx status %#jx",
		    unp->uwp_number, (uintptr_t)uwi,
		    (unp->uwp_dying << 8) | unp->uwp_stopping, status);
		return;
	}

	if (status != USBD_NORMAL_COMPLETION) {
		if (usbd_ratecheck(&unp->uwp_intr_notice)) {
			aprint_error_dev(un->uw_dev, "usb error on intr: %s\n",
			    usbd_errstr(status));
		}
		if (status == USBD_STALLED)
			usbd_clear_endpoint_stall_async(
			    unp->uwp_ep[uwi->uwi_index]);
		USBWIFIHIST_CALLARGS("%jd: not normal status %#jx",
		    unp->uwp_number, status, 0, 0);
		return;
	}

	usbd_get_xfer_status(xfer, NULL, NULL, &len, NULL);
	uwo_intr(un, status, len);
}

/*
 * Chain management.
 *
 * RX and TX are identical. Keep them that way.
 */

/* Start of common RX functions */

static size_t
usbwifi_rx_list_size(struct usbwifi_cdata * const cd, struct usbwifi * const uw)
{
	return sizeof(*cd->uwcd_rx_chains) * uw->uw_rxpipes +
	    sizeof(struct usbwifi_chain) *
	    uw->uw_rx_list_cnt * uw->uw_rxpipes;
}

static void
usbwifi_rx_list_alloc(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	cd->uwcd_rx_chains = kmem_zalloc(usbwifi_rx_list_size(cd, uw),
	    KM_SLEEP);
}

static void
usbwifi_rx_list_free(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	if (cd->uwcd_rx_chains) {
		kmem_free(cd->uwcd_rx_chains, usbwifi_rx_list_size(cd, uw));
		cd->uwcd_rx_chains = NULL;
	}
}

static int
usbwifi_rx_list_init(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);
	struct usbwifi_private * const uwp = uw->uw_pri;
	struct usbwifi_chain *chain =
	    (struct usbwifi_chain*)&cd->uwcd_rx_chains[uw->uw_rxpipes];

	for (size_t i = 0; i < uw->uw_rxpipes; i++) {
		cd->uwcd_rx_chains[i].uwscd_chain = chain;
		chain += uw->uw_rx_list_cnt;
		for (size_t j = 0; j < uw->uw_rx_list_cnt; j++) {
			struct usbwifi_chain *c =
			    &cd->uwcd_rx_chains[i].uwscd_chain[j];

			c->uwc_uw = uw;
			c->uwc_index =  uw->uw_txpipes + i;
			if (c->uwc_xfer == NULL) {
				int err = usbd_create_xfer(
				    uwp->uwp_ep[c->uwc_index],
				    uw->uw_rx_bufsz, 0, 0,
				    &c->uwc_xfer);
				if (err)
					return err;
				c->uwc_buf = usbd_get_buffer(c->uwc_xfer);
			}
		}
	}

	KASSERTMSG((char*)chain - (char*)cd->uwcd_rx_chains ==
	    usbwifi_rx_list_size(cd, uw),
	    "size mismatch: allocated %zu, used %zu\n",
	    usbwifi_rx_list_size(cd, uw),
	    (char*)chain - (char*)cd->uwcd_rx_chains);

	return 0;
}

static void
usbwifi_rx_list_fini(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	if (cd->uwcd_rx_chains[0].uwscd_chain == NULL)
		return;	/* incomplete init */

	for (size_t i = 0; i < uw->uw_rxpipes; i++) {
		for (size_t j = 0; j < uw->uw_rx_list_cnt; j++) {
			struct usbwifi_chain *c =
			    &cd->uwcd_rx_chains[i].uwscd_chain[j];

			if (c->uwc_xfer != NULL) {
				usbd_destroy_xfer(c->uwc_xfer);
				c->uwc_xfer = NULL;
				c->uwc_buf = NULL;
			}
		}
	}
}

/* End of common RX functions */

static void
usbwifi_rx_start_pipes(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);
	struct usbwifi_private * const uwp = uw->uw_pri;

	mutex_enter(&uwp->uwp_rxlock);
	mutex_enter(&uwp->uwp_txlock);
	uwp->uwp_stopping = false;

	for (size_t i = 0; i < uw->uw_rxpipes; i++) {
		for (size_t j = 0; j < uw->uw_rx_list_cnt; j++) {
			struct usbwifi_chain *c =
			    &cd->uwcd_rx_chains[i].uwscd_chain[j];

			usbd_setup_xfer(c->uwc_xfer, c, c->uwc_buf,
			    uw->uw_rx_bufsz, uw->uw_rx_xfer_flags,
			    uw->uw_rx_xfer_timeout, usbwifi_rxeof);
			usbd_transfer(c->uwc_xfer);
		}
	}

	mutex_exit(&uwp->uwp_txlock);
	mutex_exit(&uwp->uwp_rxlock);
}

/* Start of common TX functions */

static size_t
usbwifi_tx_list_size(struct usbwifi_cdata * const cd, struct usbwifi * const uw)
{
	return sizeof(*cd->uwcd_tx_chains) * uw->uw_txpipes +
	    sizeof(struct usbwifi_chain) *
	    uw->uw_tx_list_cnt * uw->uw_txpipes;
}

static void
usbwifi_tx_list_alloc(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	cd->uwcd_tx_chains = kmem_zalloc(usbwifi_tx_list_size(cd, uw), KM_SLEEP);
}

static void
usbwifi_tx_list_free(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	if (cd->uwcd_tx_chains) {
		kmem_free(cd->uwcd_tx_chains, usbwifi_tx_list_size(cd, uw));
		cd->uwcd_tx_chains = NULL;
	}
}

static int
usbwifi_tx_list_init(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);
	struct usbwifi_private * const uwp = uw->uw_pri;
	struct usbwifi_chain *chain =
	    (struct usbwifi_chain*)&cd->uwcd_tx_chains[uw->uw_txpipes];

	for (size_t i = 0; i < uw->uw_txpipes; i++) {
		cd->uwcd_tx_chains[i].uwscd_chain = chain;
		chain += uw->uw_tx_list_cnt;
		for (size_t j = 0; j < uw->uw_tx_list_cnt; j++) {
			struct usbwifi_chain *c =
			    &cd->uwcd_tx_chains[i].uwscd_chain[j];

			c->uwc_uw = uw;
			c->uwc_index = i;
			if (c->uwc_xfer == NULL) {
				int err = usbd_create_xfer(
				    uwp->uwp_ep[c->uwc_index],
				    uw->uw_tx_bufsz, uw->uw_tx_xfer_flags, 0,
				    &c->uwc_xfer);
				if (err)
					return err;
				c->uwc_buf = usbd_get_buffer(c->uwc_xfer);
			}
		}
	}

	KASSERTMSG((char*)chain - (char*)cd->uwcd_tx_chains ==
	    usbwifi_tx_list_size(cd, uw),
	    "size mismatch: allocated %zu, used %zu\n",
	    usbwifi_tx_list_size(cd, uw),
	    (char*)chain - (char*)cd->uwcd_tx_chains);

	return 0;
}

static void
usbwifi_tx_list_fini(struct usbwifi * const uw)
{
	struct usbwifi_cdata * const cd = uw_cdata(uw);

	if (cd->uwcd_tx_chains[0].uwscd_chain == NULL)
		return;	/* incomplete init */

	for (size_t i = 0; i < uw->uw_txpipes; i++) {
		for (size_t j = 0; j < uw->uw_tx_list_cnt; j++) {
			struct usbwifi_chain *c =
			    &cd->uwcd_tx_chains[i].uwscd_chain[j];

			if (c->uwc_xfer != NULL) {
				usbd_destroy_xfer(c->uwc_xfer);
				c->uwc_xfer = NULL;
				c->uwc_buf = NULL;
			}
		}
		cd->uwcd_tx_chains[i].uwscd_tx_prod =
		    cd->uwcd_tx_chains[i].uwscd_tx_cnt = 0;
	}
}

/* End of common TX functions */

/* Endpoint pipe management. */

static void
usbwifi_ep_close_pipes(struct usbwifi * const un)
{
	struct usbwifi_private * const unp = un->uw_pri;

	for (size_t i = 0; i < __arraycount(unp->uwp_ep); i++) {
		if (unp->uwp_ep[i] == NULL)
			continue;
		usbd_close_pipe(unp->uwp_ep[i]);
		unp->uwp_ep[i] = NULL;
	}
}

static usbd_status
usbwifi_ep_open_pipes(struct usbwifi * const uw)
{
	struct usbwifi_intr * const uwi = uw->uw_intr;
	struct usbwifi_private * const uwp = uw->uw_pri;

	for (size_t i = 0; i < __arraycount(uwp->uwp_ep); i++) {
		usbd_status err;

		if (uw->uw_ed[i] == 0)
			continue;

		if (uwi && i == uwi->uwi_index) {
			err = usbd_open_pipe_intr(uw->uw_iface, uw->uw_ed[i],
			    USBD_EXCLUSIVE_USE | USBD_MPSAFE, &uwp->uwp_ep[i],
			    uw, uwi->uwi_buf, uwi->uwi_bufsz,
			    usbwifi_pipe_intr, uwi->uwi_interval);
		} else {
			err = usbd_open_pipe(uw->uw_iface, uw->uw_ed[i],
			    USBD_EXCLUSIVE_USE | USBD_MPSAFE, &uwp->uwp_ep[i]);
		}
		if (err) {
			usbwifi_ep_close_pipes(uw);
			return err;
		}
	}

	return USBD_NORMAL_COMPLETION;
}

static usbd_status
usbwifi_ep_stop_pipes(struct usbwifi * const un)
{
	struct usbwifi_private * const unp = un->uw_pri;
	usbd_status err = USBD_NORMAL_COMPLETION;

	for (size_t i = 0; i < __arraycount(unp->uwp_ep); i++) {
		if (unp->uwp_ep[i] == NULL)
			continue;
		usbd_abort_pipe(unp->uwp_ep[i]);
	}

	return err;
}

static int
usbwifi_init_rx_tx(struct usbwifi * const uw)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();
	struct usbwifi_private * const uwp = uw->uw_pri;
	usbd_status err;
	int error = 0;

	usbwifi_isowned_ic(uw);
	if (uwp->uwp_dying) {
		return EIO;
	}

	/* Open RX and TX pipes. */
	err = usbwifi_ep_open_pipes(uw);
	if (err) {
		aprint_error_dev(uw->uw_dev, "open rx/tx pipes failed: %s\n",
		    usbd_errstr(err));
		error = EIO;
		goto out;
	}

	/* Init RX ring. */
	if (usbwifi_rx_list_init(uw)) {
		aprint_error_dev(uw->uw_dev, "rx list init failed\n");
		error = ENOBUFS;
		goto out;
	}

	/* Init TX ring. */
	if (usbwifi_tx_list_init(uw)) {
		aprint_error_dev(uw->uw_dev, "tx list init failed\n");
		error = ENOBUFS;
		goto out;
	}

	/* Start up the receive pipe(s). */
	usbwifi_rx_start_pipes(uw);

	callout_schedule(&uwp->uwp_stat_ch, hz);

out:
	if (error) {
		usbwifi_rx_list_fini(uw);
		usbwifi_tx_list_fini(uw);
		usbwifi_ep_close_pipes(uw);
	}

	usbwifi_isowned_ic(uw);

	return error;
}

/* push as many pkgs as possible into the tx ring for the given tx prio */
static void
usbwifi_tx_prio_start(struct usbwifi *uw, unsigned prio)
{
	USBWIFIHIST_FUNC();
	struct mbuf *m = NULL;
	struct ieee80211_node *ni;
	struct ieee80211vap *vap;
	struct ieee80211_frame *wh;
	struct usbwifi_cdata *cdata;
	struct usbwifi_single_chain_data *s_chain;
	struct usbwifi_chain *c;
	struct usbwifi_private * const uwp = uw->uw_pri;
	unsigned length, idx, count;
	uint8_t type, qid;
	bool done_transmit = false;

	cdata = uw_cdata(uw);
	s_chain = &cdata->uwcd_tx_chains[prio];
	idx = s_chain->uwscd_tx_prod;

	USBWIFIHIST_CALLARGS("%jd: tx_cnt %jd list_cnt %jd",
	    uwp->uwp_number, s_chain->uwscd_tx_cnt, uw->uw_tx_list_cnt, 0);

	count = 0;
	while (s_chain->uwscd_tx_cnt < uw->uw_tx_list_cnt) {
		if (uwp->uwp_dying || uwp->uwp_stopping)
			break;

		IFQ_POLL(&uwp->uwp_sendq[prio], m);
		if (m == NULL)
			break;

		/* Encapsulate and send data frames. */
		vap = NULL;
		ni = M_GETCTX(m, struct ieee80211_node *);
		if (ni != NULL) {
			M_CLEARCTX(m);
			vap = ni->ni_vap;
		}
		wh = mtod(m, struct ieee80211_frame *);
		type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
		qid = WME_AC_BE;
		if (IEEE80211_QOS_HAS_SEQ(wh)) {
			/* data frames in 11n mode */
			uint8_t *frm, tid;
			uint16_t qos;

			frm = ieee80211_getqos(wh);
			qos = le16toh(*(const uint16_t *)frm);
			tid = qos & IEEE80211_QOS_TID;
			qid = TID_TO_WME_AC(tid);
		} else if (type != IEEE80211_FC0_TYPE_DATA) {
			qid = WME_AC_VO;
		}
		c = &s_chain->uwscd_chain[idx];
		c->uwc_ni = ni;
		c->uwc_mbuf = m;
		length = uwo_tx_prepare(uw, c, qid);
		if (length == 0) {
			DPRINTF("uwo_tx_prepare gave zero length", 0, 0, 0, 0);
			if (vap != NULL)
				if_statinc(vap->iv_ifp, if_oerrors);
			c->uwc_ni = NULL;
			c->uwc_mbuf = NULL;
			break;
		}

		if (__predict_false(c->uwc_xfer == NULL)) {
			DPRINTF("uwc_xfer is NULL", 0, 0, 0, 0);
			if (vap != NULL)
				if_statinc(vap->iv_ifp, if_oerrors);
			ieee80211_tx_complete(ni, m, 1);
			c->uwc_ni = NULL;
			c->uwc_mbuf = NULL;
			break;
		}

		usbd_setup_xfer(c->uwc_xfer, c, c->uwc_buf, length,
		    uw->uw_tx_xfer_flags, uw->uw_tx_xfer_timeout,
		    usbwifi_txeof);

		/* Transmit */
		usbd_status err = usbd_transfer(c->uwc_xfer);
		if (err != USBD_IN_PROGRESS) {
			DPRINTF("usbd_transfer on %#jx for %ju bytes: %jd",
			    (uintptr_t)c->uwc_buf, length, err, 0);
			if (vap != NULL)
				if_statinc(vap->iv_ifp, if_oerrors);
			ieee80211_tx_complete(ni, m, 1);
			break;
		}
		done_transmit = true;

		IFQ_DEQUEUE(&uwp->uwp_sendq[prio], m);

		/*
		 * If there's a BPF listener, bounce a copy of this frame
		 * to him.
		 */
		if (vap != NULL)
			ieee80211_radiotap_tx(vap, m);

		idx = (idx + 1) % uw->uw_tx_list_cnt;
		s_chain->uwscd_tx_cnt++;
		ieee80211_tx_complete(ni, m, 0);
		count++;
	}
	s_chain->uwscd_tx_prod = idx;

	DPRINTF("finished with start; tx_cnt %jd list_cnt %jd",
	    s_chain->uwscd_tx_cnt, uw->uw_tx_list_cnt, 0, 0);

	/*
	 * Set a timeout in case the chip goes out to lunch.
	 */
	if (done_transmit)
		uwp->uwp_timer = 5;

	if (count != 0)
		rnd_add_uint32(&uwp->uwp_rndsrc, count);
}


/* start backend */
static void
usbwifi_start(struct usbwifi *uw)
{
	KASSERT(mutex_owned(&uw->uw_pri->uwp_txlock));
	for (unsigned prio = 0; prio < uw->uw_txpipes; prio++)
		usbwifi_tx_prio_start(uw, prio);
}

/* queue regular packet */
static int
usbwifi_transmit(struct ieee80211com *ic, struct mbuf *m)
{
	struct usbwifi *uw = (struct usbwifi*)ic->ic_softc;
	struct ieee80211_frame *wh;
	unsigned qid, type;

	/* Which queue should this mbuf go on? */
	wh = mtod(m, struct ieee80211_frame *);
	type = wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK;
	qid = WME_AC_BE;
	if (IEEE80211_QOS_HAS_SEQ(wh)) {
		/* data frames in 11n mode */
		uint8_t *frm, tid;
		uint16_t qos;

		frm = ieee80211_getqos(wh);
		qos = le16toh(*(const uint16_t *)frm);
		tid = qos & IEEE80211_QOS_TID;
		qid = TID_TO_WME_AC(tid);
	} else if (type != IEEE80211_FC0_TYPE_DATA) {
		qid = WME_AC_VO;
	}

	/* enque on target prio queue */
	IF_ENQUEUE(&uw->uw_pri->uwp_sendq[uw->uw_ac2idx[qid]], m);

	/* kick off hardware if needed */
	mutex_enter(&uw->uw_pri->uwp_txlock);
	usbwifi_start(uw);
	mutex_exit(&uw->uw_pri->uwp_txlock);

	return 0;
}

/* queue management packet */
static int
usbwifi_raw_xmit(struct ieee80211_node *ni, struct mbuf *m,
    const struct ieee80211_bpf_params *bpfp)
{
	struct ieee80211com *ic = ni->ni_vap->iv_ic;
	struct usbwifi *uw = (struct usbwifi*)ic->ic_softc;

	/* enque on the highest prio queue */
	IF_ENQUEUE(&uw->uw_pri->uwp_sendq[0], m);

	/* kick off hardware if needed */
	mutex_enter(&uw->uw_pri->uwp_txlock);
	usbwifi_tx_prio_start(uw, 0);
	mutex_exit(&uw->uw_pri->uwp_txlock);

	return 0;
}

/*
 * Generic stop network function:
 *	- mark as stopping
 *	- call uwo_stop routine to stop the device
 *	- turn off running, timer, statchg callout, link
 *	- stop transfers
 *	- free RX and TX resources
 *	- close pipes
 */
static void
usbwifi_stop(struct usbwifi *uw)
{
	struct usbwifi_private * const uwp = uw->uw_pri;

	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();

	usbwifi_isowned_ic(uw);

	mutex_enter(&uwp->uwp_rxlock);
	mutex_enter(&uwp->uwp_txlock);
	uwp->uwp_stopping = true;
	uwp->uwp_timer = 0;
	mutex_exit(&uwp->uwp_txlock);
	mutex_exit(&uwp->uwp_rxlock);

	uwp->uwp_timer = 0;

	callout_halt(&uwp->uwp_stat_ch, usbwifi_mutex_ic(uw));
	usb_rem_task_wait(uw->uw_udev, &uwp->uwp_ticktask, USB_TASKQ_DRIVER,
	    usbwifi_mutex_ic(uw));

	/* Stop transfers. */
	usbwifi_ep_stop_pipes(uw);

	/*
	 * Now that the software is quiescent, ask the driver to stop
	 * the hardware.  The driver's uwo_stop routine now has
	 * exclusive access to any registers.
	 *
	 * Don't bother if the device is being detached, though -- if
	 * it's been unplugged then there's no point in trying to touch
	 * the registers.
	 */
	if (!usbwifi_isdying(uw))
		uwo_stop(uw);

	/* Free RX/TX resources. */
	usbwifi_rx_list_fini(uw);
	usbwifi_tx_list_fini(uw);

	/* Close pipes. */
	usbwifi_ep_close_pipes(uw);
}

/*
 * Generic tick task function.
 *
 * usbwifi_tick() is triggered from a callout, and triggers a call to
 * usbwifi_tick_task() from the usb_task subsystem.
 */
static void
usbwifi_tick(void *arg)
{
	USBWIFIHIST_FUNC();
	struct usbwifi * const uw = arg;
	struct usbwifi_private * const uwp = uw->uw_pri;

	USBWIFIHIST_CALLARGSN(10, "%jd: enter", uwp->uwp_number, 0, 0, 0);

	if (uwp != NULL && !uwp->uwp_stopping && !uwp->uwp_dying) {
		/* Perform periodic stuff in process context */
		usb_add_task(uw->uw_udev, &uwp->uwp_ticktask, USB_TASKQ_DRIVER);
	}
}

static void
usbwifi_watchdog(struct usbwifi *uw)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();
	struct usbwifi_private * const uwp = uw->uw_pri;
	struct usbwifi_cdata * const cd = uw_cdata(uw);
	unsigned prio;
	bool found;

	ieee80211_stat_add(&uw->uw_ic.ic_ierrors, 1);
	aprint_error_dev(uw->uw_dev, "watchdog timeout\n");

	for (prio = 0; prio < uw->uw_txpipes; prio++) {
		if (cd->uwcd_tx_chains[prio].uwscd_tx_cnt == 0)
			continue;
		DPRINTF("prio %ju: uwcd_tx_cnt=%ju non zero, "
		    "aborting pipe", prio, 
		    cd->uwcd_tx_chains[prio].uwscd_tx_cnt, 0, 0);
		usbd_abort_pipe(uwp->uwp_ep[prio]);
		if (cd->uwcd_tx_chains[prio].uwscd_tx_cnt > 0) {
			DPRINTF("tx_cnt now %ju", 
			 cd->uwcd_tx_chains[prio].uwscd_tx_cnt,
			 0, 0, 0);
		}
	}

	found = false;
	for (prio = 0; prio < uw->uw_txpipes; prio++) {
		if (!IFQ_IS_EMPTY(&uwp->uwp_sendq[prio])) {
			found = true;
			break;
		}
	}
	if (found) {
		mutex_enter(&uw->uw_pri->uwp_txlock);
		usbwifi_start(uw);
		mutex_exit(&uw->uw_pri->uwp_txlock);
	}
}

static void
usbwifi_tick_task(void *arg)
{
	USBWIFIHIST_FUNC();
	struct usbwifi * const uw = arg;
	struct usbwifi_private * const uwp = uw->uw_pri;

	if (uwp == NULL)
		return;

	USBWIFIHIST_CALLARGSN(8, "%jd: enter", uwp->uwp_number, 0, 0, 0);

	IEEE80211_LOCK(&uw->uw_ic);
	if (uwp->uwp_stopping || uwp->uwp_dying) {
		IEEE80211_UNLOCK(&uw->uw_ic);
		return;
	}

	IEEE80211_UNLOCK(&uw->uw_ic);

	if (uwp->uwp_timer != 0 && --uwp->uwp_timer == 0)
		usbwifi_watchdog(uw);

	/* Call driver if requested. */
	uwo_tick(uw);

	IEEE80211_LOCK(&uw->uw_ic);
	if (!uwp->uwp_stopping && !uwp->uwp_dying)
		callout_schedule(&uwp->uwp_stat_ch, hz);
	IEEE80211_UNLOCK(&uw->uw_ic);
}

/* Various accessors. */

void *
usbwifi_softc(struct usbwifi *uw)
{
	return uw->uw_sc;
}

struct ieee80211com *
usbwifi_ic(struct usbwifi *uw)
{
	return &uw->uw_ic;
}

krndsource_t *
usbwifi_rndsrc(struct usbwifi *uw)
{
	return &uw->uw_pri->uwp_rndsrc;
}

bool
usbwifi_isdying(struct usbwifi *uw)
{
	return uw->uw_pri == NULL ||
	    atomic_load_relaxed(&uw->uw_pri->uwp_dying);
}


/* Autoconf management. */

/*
 * usbwifi_attach(), usbwifi_ic_attach() and usbwifi_attach_finalize()
 * perform setup of the relevant 'usbwifi'.
 *  The first is enough to enable device access (eg, endpoints
 * are connected and commands can be sent), the second prepares the
 * main radio data and initializes defaults, and finally the last connects
 * the device to the system networking.
 *
 * Always call usbwifi_detach(), even if usbwifi_ic_attach() or
 * usbwifi_attach_finalize() have been skippped.
 */
void
usbwifi_attach(struct usbwifi *uw)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();

	/* Required inputs.  */
	KASSERT(uw->uw_ops->uwo_tx_prepare);
	KASSERT(uw->uw_ops->uwo_rx_loop);
	KASSERT(uw->uw_ops->uwo_init);

	/* Unfortunate fact.  */
	KASSERT(uw == device_private(uw->uw_dev));

	/*
	 * Setup the 802.11 device.
	 */
	uw->uw_ic.ic_softc = uw->uw_sc;
	uw->uw_ic.ic_name = device_xname(uw->uw_dev);
	uw->uw_ic.ic_transmit = usbwifi_transmit;
	uw->uw_ic.ic_raw_xmit = usbwifi_raw_xmit;
	uw->uw_ic.ic_phytype = IEEE80211_T_OFDM; /* Not only, but not used. */
	uw->uw_ic.ic_opmode = IEEE80211_M_STA;	/* Default to BSS mode. */
	/*
	 * Provide some default operations, may be overriden by the driver
	 */
	uw->uw_ic.ic_parent = usbwifi_parent;

	/*
	 * Default settings used by many devices
	 */
	uw->uw_rx_xfer_timeout = USBD_NO_TIMEOUT;
	uw->uw_tx_xfer_timeout = USBD_NO_TIMEOUT;
	uw->uw_rx_xfer_flags = USBD_SHORT_XFER_OK;
	uw->uw_tx_xfer_flags = USBD_FORCE_SHORT_XFER;
}

void
usbwifi_ic_attach(struct usbwifi *uw, int num_tx_chains, int num_rx_chains,
    int num_tx_pipes, int num_rx_pipes, int flags)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();

	KASSERT(uw->uw_rx_bufsz);
	KASSERT(uw->uw_tx_bufsz);
	KASSERT(num_tx_chains &&
	    num_tx_chains <= __arraycount(uw->uw_pri->uwp_sendq));
	KASSERT(num_rx_chains);

	uw->uw_txpipes = num_tx_pipes;
	uw->uw_rxpipes = num_rx_pipes;

	struct usbwifi_private * const uwp =
	    kmem_zalloc(sizeof(*uw->uw_pri), KM_SLEEP);

	usb_init_task(&uwp->uwp_ticktask, usbwifi_tick_task, uw, USB_TASKQ_MPSAFE);
	callout_init(&uwp->uwp_stat_ch, CALLOUT_MPSAFE);
	callout_setfunc(&uwp->uwp_stat_ch, usbwifi_tick, uw);

	mutex_init(&uwp->uwp_txlock, MUTEX_DEFAULT, IPL_SOFTUSB);
	mutex_init(&uwp->uwp_rxlock, MUTEX_DEFAULT, IPL_SOFTUSB);

	uw->uw_ic.ic_txstream = num_tx_chains;
	uw->uw_ic.ic_rxstream = num_rx_chains;
	uw->uw_ic.ic_flags = flags;

	/*
	 * For each priority the device has a separate pipe, init
	 * a separate interface queue.
	 * Which one to use is controlled by uw_ac2idx, mapping a WME
	 * quality of service to a pipe index.
	 */
	for (int i = 0; i < uw->uw_txpipes; i++) {
		IFQ_SET_MAXLEN(&uwp->uwp_sendq[i], IFQ_MAXLEN);
		IFQ_LOCK_INIT(&uwp->uwp_sendq[i]);
	}

	ieee80211_ifattach(&uw->uw_ic);

	uw->uw_pri = uwp;
	usbwifi_lock_ic(uw);
	uw->uw_ic.ic_raw_xmit = usbwifi_raw_xmit;

	usbwifi_rx_list_alloc(uw);
	usbwifi_tx_list_alloc(uw);
}

void
usbwifi_attach_finalize(struct usbwifi *uw)
{
	struct usbwifi_private *uwp = uw->uw_pri;
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();

	usbd_add_drv_event(USB_EVENT_DRIVER_ATTACH, uw->uw_udev, uw->uw_dev);
	if (!pmf_device_register(uw->uw_dev, NULL, NULL))
		aprint_error_dev(uw->uw_dev,
		    "couldn't establish power handler\n");

	ieee80211_announce(&uw->uw_ic);

	rnd_attach_source(&uw->uw_pri->uwp_rndsrc, device_xname(uw->uw_dev),
	    RND_TYPE_NET, RND_FLAG_DEFAULT);

	uwp->uwp_number = atomic_inc_uint_nv(&usbwifi_number);
	uwp->uwp_attached = true;

	usbwifi_unlock_ic(uw);
}

int
usbwifi_detach(device_t self, int flags)
{
	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();
	struct usbwifi * const uw = device_private(self);
	struct usbwifi_private * const uwp = uw->uw_pri;

	/* Detached before attached finished, so just bail out. */
	if (uwp == NULL)
		return 0;

	atomic_store_relaxed(&uwp->uwp_dying, true);

	if (uwp->uwp_attached) {
		ieee80211_ifdetach(&uw->uw_ic);
		pmf_device_deregister(uw->uw_dev);
		usbd_add_drv_event(USB_EVENT_DRIVER_DETACH, uw->uw_udev,
		    uw->uw_dev);
	}

	callout_halt(&uwp->uwp_stat_ch, NULL);
	rnd_detach_source(&uwp->uwp_rndsrc);
	usb_rem_task_wait(uw->uw_udev, &uwp->uwp_ticktask, USB_TASKQ_DRIVER,
	    NULL);

	mutex_destroy(&uwp->uwp_rxlock);
	mutex_destroy(&uwp->uwp_txlock);

	/* sendq destroy */
	for (int i = 0; i < uw->uw_txpipes; i++) {
		IFQ_PURGE(&uwp->uwp_sendq[i]);
		IFQ_LOCK_DESTROY(&uwp->uwp_sendq[i]);
	}

	callout_destroy(&uwp->uwp_stat_ch);

	usbwifi_rx_list_free(uw);
	usbwifi_tx_list_free(uw);
	kmem_free(uwp, sizeof(*uwp));
	uw->uw_pri = NULL;

	return 0;
}

/*
 * This is called (with task context) whenever the first VAP
 * is running or the last one stops running.
 */
void
usbwifi_parent(struct ieee80211com *ic)
{
	struct usbwifi *uw = (struct usbwifi*)ic->ic_softc;
	int startall = 0;

	USBWIFIHIST_FUNC(); USBWIFIHIST_CALLED();

	IEEE80211_LOCK(&uw->uw_ic);
	if (ic->ic_nrunning > 0) {
		if (uwo_init(uw) == 0 && usbwifi_init_rx_tx(uw) == 0)
			startall = 1;
	} else {
		usbwifi_stop(uw);
	}
	IEEE80211_UNLOCK(&uw->uw_ic);

	if (startall)
		ieee80211_start_all(ic);
}

int
usbwifi_activate(device_t self, devact_t act)
{
	struct usbwifi *uw = device_private(self);
	struct usbwifi_private * const uwp = uw->uw_pri;
	int err;

	switch (act) {
	case DVACT_DEACTIVATE:
		err =  ieee80211_activate(&uw->uw_ic, act);
		if (err)
			return err;

		atomic_store_relaxed(&uwp->uwp_dying, true);

		mutex_enter(&uwp->uwp_rxlock);
		mutex_enter(&uwp->uwp_txlock);
		uwp->uwp_stopping = true;
		mutex_exit(&uwp->uwp_txlock);
		mutex_exit(&uwp->uwp_rxlock);

		return 0;
	default:
		return EOPNOTSUPP;
	}
	return EOPNOTSUPP;
}

MODULE(MODULE_CLASS_MISC, usbwifi, NULL);

static int
usbwifi_modcmd(modcmd_t cmd, void *arg)
{
	switch (cmd) {
	case MODULE_CMD_INIT:
		return 0;
	case MODULE_CMD_FINI:
		return 0;
	case MODULE_CMD_STAT:
	case MODULE_CMD_AUTOUNLOAD:
	default:
		return ENOTTY;
	}
}
