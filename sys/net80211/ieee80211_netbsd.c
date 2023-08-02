/* $NetBSD: ieee80211_netbsd.c,v 1.31.2.10 2020/04/16 15:30:00 nat Exp $ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003-2009 Sam Leffler, Errno Consulting
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
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifdef __NetBSD__
__KERNEL_RCSID(0, "$NetBSD: ieee80211_netbsd.c,v 1.31.2.10 2020/04/16 15:30:00 nat Exp $");
#endif

/*
 * IEEE 802.11 support (NetBSD-specific code)
 */

#ifdef _KERNEL_OPT
#include "opt_wlan.h"
#endif

#include <sys/atomic.h>
#include <sys/param.h>
#include <sys/systm.h> 
#include <sys/kernel.h>
#include <sys/mbuf.h>   
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <sys/socket.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/route.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_input.h>

#ifdef IEEE80211_DEBUG
int ieee80211_debug = 0;
static int ieee80211_debug_printf = 0;
#endif

int sysctl_ieee80211coms(SYSCTLFN_ARGS);
int ieee80211_sysctl_msecs_ticks(SYSCTLFN_ARGS);
static int ieee80211_sysctl_inact(SYSCTLFN_ARGS);
static int ieee80211_sysctl_parent(SYSCTLFN_ARGS);
static int ieee80211_sysctl_radar(SYSCTLFN_ARGS);
static int ieee80211_sysctl_vap_restart(SYSCTLFN_ARGS);

static void bpf_track(struct bpf_if *, struct ifnet *, int, int);

static const char wlanname[] = "wlan";

static int wlan_clone_create(struct if_clone *, int, size_t, void*);
static int wlan_clone_destroy(struct ifnet*);

static struct if_clone wlan_cloner =
	IF_CLONE_WITH_ARGS_INITIALIZER(wlanname,
	    wlan_clone_create, wlan_clone_destroy);

static void ieee80211_rx_mgmt_cb(void *, int);
static struct ifqueue ieee80211_rx_mgmt;
static struct task ieee80211_mgmt_input;

int
ieee80211_init0(void)
{

	return 0;
}

int
ieee80211_clone_attach(void)
{

	if_clone_attach(&wlan_cloner);
	return 0;
}

/*
 * "taskqueue" support for doing FreeBSD style taskqueue operations using
 * NetBSD's workqueue to do the actual function calls for the work.
 * Many features of the FreeBSD taskqueue are not implemented.   This should
 * be enough features for the 802.11 stack to run its tasks and time delayed
 * tasks.
 */

void
ieee80211_runwork(struct work *work2do, void *arg)
{
	struct task *work_task = (struct task *) work2do;

	mutex_enter(&work_task->t_mutex);
	work_task->t_onqueue = 0;
	mutex_exit(&work_task->t_mutex);
	
	work_task->t_func(work_task->t_arg, 0);
}

void
taskqueue_enqueue(struct workqueue *wq, struct task *task_item)
{
	mutex_enter(&task_item->t_mutex);
	if (!task_item->t_onqueue) {
		workqueue_enqueue(wq, &task_item->t_work, NULL);
		task_item->t_onqueue = 1;
	}
	mutex_exit(&task_item->t_mutex);
}

void
taskqueue_drain(struct workqueue *wq, struct task *task_item)
{

	workqueue_wait(wq, &task_item->t_work);
}

static void
taskqueue_callout_enqueue(void *arg)
{
	struct timeout_task *timeout_task = arg;
	mutex_enter(&timeout_task->to_task.t_mutex);
	timeout_task->to_scheduled = 0;
	mutex_exit(&timeout_task->to_task.t_mutex);

	taskqueue_enqueue(timeout_task->to_wq, (struct task*) timeout_task);
}

int
taskqueue_enqueue_timeout(struct workqueue *queue,
     struct timeout_task *timeout_task, int nticks)
{
	mutex_enter(&timeout_task->to_task.t_mutex);
	if (timeout_task->to_scheduled == -1) {
		/* we are draining the task queue */
		mutex_exit(&timeout_task->to_task.t_mutex);
		return EIO;
	}
	if (timeout_task->to_scheduled == 0) {
		callout_reset(&timeout_task->to_callout, nticks, 
		    taskqueue_callout_enqueue, timeout_task);
		timeout_task->to_scheduled = 1;
	}
	mutex_exit(&timeout_task->to_task.t_mutex);
	
	return 0;
}

int
taskqueue_cancel_timeout(struct workqueue *queue, 
    struct timeout_task *timeout_task, u_int *pendp)
{
	mutex_enter(&timeout_task->to_task.t_mutex);
	callout_stop(&timeout_task->to_callout);
	timeout_task->to_scheduled = 0;
	mutex_exit(&timeout_task->to_task.t_mutex);

	return 0;
}

void
taskqueue_drain_timeout(struct workqueue *wq, 
    struct timeout_task *timeout_task)
{

	mutex_enter(&timeout_task->to_task.t_mutex);
	timeout_task->to_scheduled = -1;
	callout_halt(&timeout_task->to_callout,
	    &timeout_task->to_task.t_mutex);
	workqueue_wait(wq, &timeout_task->to_task.t_work);
	mutex_exit(&timeout_task->to_task.t_mutex);
}


static int
wlan_clone_create(struct if_clone *ifc, int unit, size_t arg_size, void *data)
{
	struct ieee80211_clone_params cp;
	struct ieee80211vap *vap;
	struct ieee80211com *ic;
	int error;

	if (arg_size != sizeof(cp) || data == NULL)
		return EINVAL;

	error = copyin(data, &cp, sizeof(cp));
	if (error)
		return error;

	ic = ieee80211_find_com(cp.icp_parent);
	if (ic == NULL)
		return ENXIO;
	if (cp.icp_opmode >= IEEE80211_OPMODE_MAX) {
		ic_printf(ic, "%s: invalid opmode %d\n", __func__,
		    cp.icp_opmode);
		return EINVAL;
	}
	if ((ic->ic_caps & ieee80211_opcap[cp.icp_opmode]) == 0) {
		ic_printf(ic, "%s mode not supported\n",
		    ieee80211_opmode_name[cp.icp_opmode]);
		return EOPNOTSUPP;
	}
	if ((cp.icp_flags & IEEE80211_CLONE_TDMA) &&
#ifdef IEEE80211_SUPPORT_TDMA
	    (ic->ic_caps & IEEE80211_C_TDMA) == 0
#else
	    (1)
#endif
	) {
		ic_printf(ic, "TDMA not supported\n");
		return EOPNOTSUPP;
	}
	vap = ic->ic_vap_create(ic, wlanname, unit,
			cp.icp_opmode, cp.icp_flags, cp.icp_bssid,
			cp.icp_flags & IEEE80211_CLONE_MACADDR ?
			    cp.icp_macaddr : ic->ic_macaddr);
	if (vap == NULL)
		return EIO;

	ieee80211_com_vincref(vap);
	bpf_register_track_event(&vap->iv_rawbpf, bpf_track);
	return 0;
}

static int
wlan_clone_destroy(struct ifnet *ifp)
{
	struct ieee80211vap *vap = ifp->if_softc;
	struct ieee80211com *ic = vap->iv_ic;

	ic->ic_vap_delete(vap);
	return 0;
}

void
ieee80211_vap_destroy(struct ieee80211vap *vap)
{

	bpf_deregister_track_event(&vap->iv_rawbpf, bpf_track);
	wlan_clone_destroy(vap->iv_ifp);
}

int
ieee80211_sysctl_msecs_ticks(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	int msecs = ticks_to_msecs(*(int *)node.sysctl_data);
	int error, t;

	node.sysctl_data = &msecs;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || (newp == NULL))
		return error;
	t = msecs_to_ticks(msecs);
	*(int *)rnode->sysctl_data = (t < 1) ? 1 : t;

	return 0;
}

static int
ieee80211_sysctl_inact(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	int error, inact = (*(int *)node.sysctl_data) * IEEE80211_INACT_WAIT;

	node.sysctl_data = &inact;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || (newp == NULL))
		return error;
	*(int *)rnode->sysctl_data = inact / IEEE80211_INACT_WAIT;
	return 0;
}

static int
ieee80211_sysctl_parent(SYSCTLFN_ARGS)
{
	struct ieee80211vap *vap;
	char pname[IFNAMSIZ];
	struct sysctlnode node = *rnode;

	vap = node.sysctl_data;
	strlcpy(pname, vap->iv_ic->ic_name, IFNAMSIZ);
	node.sysctl_data = pname;
	return sysctl_lookup(SYSCTLFN_CALL(&node));
}

static int
ieee80211_sysctl_radar(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ieee80211com *ic = node.sysctl_data;
	int t = 0, error;

	node.sysctl_data = &t;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || (newp == NULL))
		return error;

	IEEE80211_LOCK(ic);
	ieee80211_dfs_notify_radar(ic, ic->ic_curchan);
	IEEE80211_UNLOCK(ic);

	return 0;
}

/*
 * For now, just restart everything.
 *
 * Later on, it'd be nice to have a separate VAP restart to
 * full-device restart.
 */
static int
ieee80211_sysctl_vap_restart(SYSCTLFN_ARGS)
{
	struct sysctlnode node = *rnode;
	struct ieee80211vap *vap = node.sysctl_data;
	int t = 0, error;

	node.sysctl_data = &t;
	error = sysctl_lookup(SYSCTLFN_CALL(&node));
	if (error || (newp == NULL))
		return error;

	ieee80211_restart_all(vap->iv_ic);
	return 0;
}

/*
 * Setup sysctl(3) MIB, net.wlan.*
 */
int32_t ieee80211_sysctl_wlan;
static struct sysctllog	*wlan_sysctl_clog;

SYSCTL_SETUP(sysctl_net_wlan_setup, "sysctl net.wlan subtree setup")
{
	int rc;
	const struct sysctlnode *wlan_node;

	if ((rc = sysctl_createv(&wlan_sysctl_clog, 0, NULL, &wlan_node,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE, CTLTYPE_NODE,
	    wlanname, SYSCTL_DESCR("ieee802.11 operation controll"),
	    NULL, 0, NULL, 0,
	    CTL_NET, CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	/* remember the (dynamic) MIB so we can find this node later */
	ieee80211_sysctl_wlan = wlan_node->sysctl_num;

#ifdef notyet
	if ((rc = sysctl_createv(&wlan_sysctl_clog, 0, &wlan_node, NULL,
	    CTLFLAG_PERMANENT, CTLTYPE_NODE,
	    "nodes", SYSCTL_DESCR("client/peer stations"),
	    ieee80211_sysctl_node, 0, NULL, 0, CTL_CREATE, CTL_EOL)) != 0)
		goto err;
#endif

#ifdef IEEE80211_DEBUG
	/* control debugging printfs */
	if ((rc = sysctl_createv(&wlan_sysctl_clog, 0, &wlan_node, NULL,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE, CTLTYPE_INT,
	    "debug", SYSCTL_DESCR("control debugging printfs"),
	    NULL, 0, &ieee80211_debug, 0, CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if ((rc = sysctl_createv(&wlan_sysctl_clog, 0, &wlan_node, NULL,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE, CTLTYPE_INT,
	    "debug_console", SYSCTL_DESCR("debug output goes to kernel console"),
	    NULL, 0, &ieee80211_debug_printf, 0, CTL_CREATE, CTL_EOL)) != 0)
		goto err;
#endif

	/* list of devices */
	if ((rc = sysctl_createv(&wlan_sysctl_clog, 0, &wlan_node, NULL,
	    CTLFLAG_PERMANENT|CTLFLAG_READWRITE, CTLTYPE_STRING,
	    "devices",
	    SYSCTL_DESCR("names of available 802.11 devices"),
	    sysctl_ieee80211coms, 0, NULL, 0, CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	return;
err:
#ifdef IEEE80211_DEBUG
	printf("%s: sysctl_createv failed (rc = %d)\n", __func__, rc);
#endif
	return;
}

void
ieee80211_sysctl_attach(struct ieee80211com *ic)
{
}

void
ieee80211_sysctl_detach(struct ieee80211com *ic)
{
}

void
ieee80211_sysctl_vattach(struct ieee80211vap *vap)
{
	struct ifnet *ifp = vap->iv_ifp;
	struct sysctllog *ctx = NULL;
	int32_t oid;
	int rc;
	const struct sysctlnode *rnode;

	if ((rc = sysctl_createv(&ctx, 0, NULL, &rnode,
	    0, CTLTYPE_NODE, ifp->if_xname, SYSCTL_DESCR("virtual AP"),
	    NULL, 0, NULL, 0,
	    CTL_NET, ieee80211_sysctl_wlan, CTL_CREATE, CTL_EOL)) != 0)
		goto err;
	oid = rnode->sysctl_num;

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READONLY, CTLTYPE_STRING,
	    "parent", SYSCTL_DESCR("parent device"),
	    ieee80211_sysctl_parent, 0, (void *)vap, IFNAMSIZ,
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "driver_caps", SYSCTL_DESCR("driver capabilities"),
	    NULL, 0, &vap->iv_caps, sizeof(vap->iv_caps),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

#ifdef IEEE80211_DEBUG
	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "debug", SYSCTL_DESCR("control debugging printfs"),
	    NULL, 0, &vap->iv_debug, sizeof(vap->iv_debug),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;
#endif

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "bmiss_max",
	    SYSCTL_DESCR("consecutive beacon misses before scanning"),
	    NULL, 0, &vap->iv_bmiss_max, sizeof(vap->iv_bmiss_max),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	/* XXX inherit from tunables */
	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "inact_run",
	    SYSCTL_DESCR("station inactivity timeout (sec)"),
	    ieee80211_sysctl_inact, 0,
	    &vap->iv_inact_run, sizeof(vap->iv_inact_run),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "inact_probe",
	    SYSCTL_DESCR("station inactivity probe timeout (sec)"),
	    ieee80211_sysctl_inact, 0,
	    &vap->iv_inact_probe, sizeof(vap->iv_inact_probe),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "inact_auth",
	    SYSCTL_DESCR("station authentication timeout (sec)"),
	    ieee80211_sysctl_inact, 0,
	    &vap->iv_inact_auth, sizeof(vap->iv_inact_auth),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "inact_init",
	    SYSCTL_DESCR("station initial state timeout (sec)"),
	    ieee80211_sysctl_inact, 0,
	    &vap->iv_inact_init, sizeof(vap->iv_inact_init),
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if (vap->iv_htcaps & IEEE80211_HTC_HT) {
		if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
		    CTLFLAG_READWRITE|CTLFLAG_UNSIGNED, CTLTYPE_INT,
		    "ampdu_mintraffic_bk",
		    SYSCTL_DESCR("BK traffic tx aggr threshold (pps)"),
		    NULL, 0, &vap->iv_ampdu_mintraffic[WME_AC_BK],
		    sizeof(vap->iv_ampdu_mintraffic[WME_AC_BK]),
		    CTL_CREATE, CTL_EOL)) != 0)
			goto err;

		if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
		    CTLFLAG_READWRITE|CTLFLAG_UNSIGNED, CTLTYPE_INT,
		    "ampdu_mintraffic_be",
		    SYSCTL_DESCR("BE traffic tx aggr threshold (pps)"),
		    NULL, 0, &vap->iv_ampdu_mintraffic[WME_AC_BE],
		    sizeof(vap->iv_ampdu_mintraffic[WME_AC_BE]),
		    CTL_CREATE, CTL_EOL)) != 0)
			goto err;

		if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
		    CTLFLAG_READWRITE|CTLFLAG_UNSIGNED, CTLTYPE_INT,
		    "ampdu_mintraffic_vo",
		    SYSCTL_DESCR("VO traffic tx aggr threshold (pps)"),
		    NULL, 0, &vap->iv_ampdu_mintraffic[WME_AC_VO],
		    sizeof(vap->iv_ampdu_mintraffic[WME_AC_VO]),
		    CTL_CREATE, CTL_EOL)) != 0)
			goto err;

		if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
		    CTLFLAG_READWRITE|CTLFLAG_UNSIGNED, CTLTYPE_INT,
		    "ampdu_mintraffic_vi",
		    SYSCTL_DESCR("VI traffic tx aggr threshold (pps)"),
		    NULL, 0, &vap->iv_ampdu_mintraffic[WME_AC_VI],
		    sizeof(vap->iv_ampdu_mintraffic[WME_AC_VI]),
		    CTL_CREATE, CTL_EOL)) != 0)
			goto err;
	}

	if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
	    CTLFLAG_READWRITE, CTLTYPE_INT,
	    "force_restart",
	    SYSCTL_DESCR("force a VAP restart"),
	    ieee80211_sysctl_vap_restart, 0, (void*)vap, 0,
	    CTL_CREATE, CTL_EOL)) != 0)
		goto err;

	if (vap->iv_caps & IEEE80211_C_DFS) {
		if ((rc = sysctl_createv(&ctx, 0, &rnode, NULL,
		    CTLFLAG_READWRITE, CTLTYPE_INT,
		    "radar",
		    SYSCTL_DESCR("simulate radar even"),
		    ieee80211_sysctl_radar, 0, (void*)vap->iv_ic, 0,
		    CTL_CREATE, CTL_EOL)) != 0)
			goto err;
	}

	vap->iv_sysctl = ctx;
	vap->iv_oid = oid;
	return;
err:
	printf("%s: sysctl_createv failed, rc = %d\n", __func__, rc);
}

void
ieee80211_sysctl_vdetach(struct ieee80211vap *vap)
{
	if (vap->iv_sysctl != NULL) {
		sysctl_teardown(&vap->iv_sysctl);
		vap->iv_sysctl = NULL;
	}
}

#define	MS(_v, _f)	(((_v) & _f##_M) >> _f##_S)
int
ieee80211_com_vincref(struct ieee80211vap *vap)
{
	uint32_t ostate;

	ostate = atomic_add_32_nv(&vap->iv_com_state, IEEE80211_COM_REF_ADD);

	if (ostate & IEEE80211_COM_DETACHED) {
		atomic_add_32(&vap->iv_com_state, -IEEE80211_COM_REF_ADD);
		return (ENETDOWN);
	}

	if (MS(ostate, IEEE80211_COM_REF) == IEEE80211_COM_REF_MAX) {
		atomic_add_32(&vap->iv_com_state, -IEEE80211_COM_REF_ADD);
		return (EOVERFLOW);
	}

	return (0);
}

void
ieee80211_com_vdecref(struct ieee80211vap *vap)
{
	uint32_t ostate __diagused;

	ostate = atomic_add_32_nv(&vap->iv_com_state, -IEEE80211_COM_REF_ADD);

	KASSERTMSG(MS(ostate, IEEE80211_COM_REF) != 0,
	    "com reference counter underflow: %u", ostate);
}

void
ieee80211_com_vdetach(struct ieee80211vap *vap)
{
	int sleep_time;

	sleep_time = msecs_to_ticks(250);
	atomic_swap_32(&vap->iv_com_state, IEEE80211_COM_DETACHED);
	while (MS(atomic_load_relaxed(&vap->iv_com_state), IEEE80211_COM_REF) != 0)
		kpause("comref", false, sleep_time, NULL);
}
#undef	MS

int
ieee80211_node_dectestref(struct ieee80211_node *ni)
{
	/* XXX need equivalent of atomic_dec_and_test */
	atomic_subtract_int(&ni->ni_refcnt, 1);
	return atomic_cas_uint(&ni->ni_refcnt, 0, 1) == 0;
}

void
ieee80211_drain_ifq(struct ifqueue *ifq)
{
	struct ieee80211_node *ni;
	struct mbuf *m;

	for (;;) {
		IF_DEQUEUE(ifq, m);
		if (m == NULL)
			break;

		ni = IEEE80211_MBUF_GETNODE(m, struct ieee80211_node *);
		KASSERTMSG(ni != NULL, "frame w/o node");
		ieee80211_free_node(ni);
		ieee80211_free_mbuf(m);
	}
}

void
ieee80211_flush_ifq(struct ifqueue *ifq, struct ieee80211vap *vap)
{
	struct ieee80211_node *ni;
	struct mbuf *m, **mprev;

	IFQ_LOCK(ifq);
	mprev = &ifq->ifq_head;
	while ((m = *mprev) != NULL) {
		ni = IEEE80211_MBUF_GETNODE(m, struct ieee80211_node *);
		if (ni != NULL && ni->ni_vap == vap) {
			*mprev = m->m_nextpkt;		/* remove from list */
			ifq->ifq_len--;

			ieee80211_free_node(ni);	/* reclaim ref */
			ieee80211_free_mbuf(m);
		} else
			mprev = &m->m_nextpkt;
	}
	/* recalculate tail ptr */
	m = ifq->ifq_head;
	for (; m != NULL && m->m_nextpkt != NULL; m = m->m_nextpkt)
		;
	ifq->ifq_tail = m;
	IFQ_UNLOCK(ifq);
}

/*
 * As above, for mbufs allocated with m_gethdr/MGETHDR
 * or initialized by M_COPY_PKTHDR.
 */
#define	MC_ALIGN(m, len)						\
do {									\
	(m)->m_data += rounddown2(MCLBYTES - (len), sizeof(long));	\
} while (/* CONSTCOND */ 0)

/*
 * Allocate and setup a management frame of the specified
 * size.  We return the mbuf and a pointer to the start
 * of the contiguous data area that's been reserved based
 * on the packet length.  The data area is forced to 32-bit
 * alignment and the buffer length to a multiple of 4 bytes.
 * This is done mainly so beacon frames (that require this)
 * can use this interface too.
 */
struct mbuf *
ieee80211_getmgtframe(uint8_t **frm, int headroom, int pktlen)
{
	struct mbuf *m;
	u_int len;

	/*
	 * NB: we know the mbuf routines will align the data area
	 *     so we don't need to do anything special.
	 */
	len = roundup2(headroom + pktlen, 4);
	KASSERTMSG(len <= MCLBYTES, "802.11 mgt frame too large: %u", len);

	/*
	 * XXX - recheck after next FreeBSD update!
	 *
	 * Upstream is reworking the interface to waste less space,
	 * for now just do the simple thing: use a single hdr mbuf
	 * if all data fits (it always does on MSIZE=512 architectures
	 * like amd64) and wast a full cluster on all others.
	 */
	if (len <= MHLEN) {
		m = m_gethdr(M_NOWAIT, MT_DATA);
		/*
		 * Align the data in case additional headers are added.
		 * This should only happen when a WEP header is added
		 * which only happens for shared key authentication mgt
		 * frames which all fit in MHLEN.
		 */
		if (m != NULL)
			m_align(m, len);
	} else {
		m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
		if (m != NULL)
			MC_ALIGN(m, len);
	}
	if (m != NULL) {
		m->m_data += headroom;
		*frm = m->m_data;
	}
	return m;
}

#ifndef __NO_STRICT_ALIGNMENT
/*
 * Re-align the payload in the mbuf.  This is mainly used (right now)
 * to handle IP header alignment requirements on certain architectures.
 */
struct mbuf *
ieee80211_realign(struct ieee80211vap *vap, struct mbuf *m, size_t align)
{
	int pktlen, space;
	struct mbuf *n;

	pktlen = m->m_pkthdr.len;
	space = pktlen + align;
	n = m_gethdr(M_NOWAIT, MT_DATA);
	if (space >= MINCLSIZE)
		MCLGET(n, M_NOWAIT);
	if (__predict_true(n != NULL)) {
		m_move_pkthdr(n, m);
		n->m_data = (caddr_t)(ALIGN(n->m_data + align) - align);
		m_copydata(m, 0, pktlen, mtod(n, caddr_t));
		n->m_len = pktlen;
	} else {
		IEEE80211_DISCARD(vap, IEEE80211_MSG_ANY,
		    mtod(m, const struct ieee80211_frame *), NULL,
		    "%s", "no mbuf to realign");
		vap->iv_stats.is_rx_badalign++;
	}
	m_freem(m);
	return n;
}
#endif /* !__NO_STRICT_ALIGNMENT */

int
ieee80211_add_callback(struct mbuf *m,
	void (*func)(struct ieee80211_node *, void *, int), void *arg)
{
	struct m_tag *mtag;
	struct ieee80211_cb *cb;

	mtag = m_tag_get(/*MTAG_ABI_NET80211*/ NET80211_TAG_CALLBACK,
			sizeof(struct ieee80211_cb), M_NOWAIT);
	if (mtag == NULL)
		return 0;

	cb = (struct ieee80211_cb *)(mtag+1);
	cb->func = func;
	cb->arg = arg;
	m_tag_prepend(m, mtag);
	m->m_flags |= M_TXCB;
	return 1;
}

int
ieee80211_add_xmit_params(struct mbuf *m,
    const struct ieee80211_bpf_params *params)
{
	struct m_tag *mtag;
	struct ieee80211_tx_params *tx;

	mtag = m_tag_get(/*MTAG_ABI_NET80211*/ NET80211_TAG_XMIT_PARAMS,
	    sizeof(struct ieee80211_tx_params), M_NOWAIT);
	if (mtag == NULL)
		return (0);

	tx = (struct ieee80211_tx_params *)(mtag+1);
	memcpy(&tx->params, params, sizeof(struct ieee80211_bpf_params));
	m_tag_prepend(m, mtag);
	return (1);
}

int
ieee80211_get_xmit_params(struct mbuf *m,
    struct ieee80211_bpf_params *params)
{
	struct m_tag *mtag;
	struct ieee80211_tx_params *tx;

	mtag = m_tag_find(m, /*MTAG_ABI_NET80211,*/ NET80211_TAG_XMIT_PARAMS);
	if (mtag == NULL)
		return (-1);
	tx = (struct ieee80211_tx_params *)(mtag + 1);
	memcpy(params, &tx->params, sizeof(struct ieee80211_bpf_params));
	return (0);
}

void
ieee80211_process_callback(struct ieee80211_node *ni,
	struct mbuf *m, int status)
{
	struct m_tag *mtag;

	mtag = m_tag_find(m, /*MTAG_ABI_NET80211,*/ NET80211_TAG_CALLBACK);
	if (mtag != NULL) {
		struct ieee80211_cb *cb = (struct ieee80211_cb *)(mtag+1);
		cb->func(ni, cb->arg, status);
	}
}

/*
 * Add RX parameters to the given mbuf.
 *
 * Returns 1 if OK, 0 on error.
 */
int
ieee80211_add_rx_params(struct mbuf *m, const struct ieee80211_rx_stats *rxs)
{
	struct m_tag *mtag;
	struct ieee80211_rx_params *rx;

	mtag = m_tag_get(/*MTAG_ABI_NET80211,*/ NET80211_TAG_RECV_PARAMS,
	    sizeof(struct ieee80211_rx_stats), M_NOWAIT);
	if (mtag == NULL)
		return (0);

	rx = (struct ieee80211_rx_params *)(mtag + 1);
	memcpy(&rx->params, rxs, sizeof(*rxs));
	m_tag_prepend(m, mtag);
	return (1);
}

int
ieee80211_get_rx_params(struct mbuf *m, struct ieee80211_rx_stats *rxs)
{
	struct m_tag *mtag;
	struct ieee80211_rx_params *rx;

	mtag = m_tag_find(m, /*MTAG_ABI_NET80211,*/ NET80211_TAG_RECV_PARAMS);
	if (mtag == NULL)
		return (-1);
	rx = (struct ieee80211_rx_params *)(mtag + 1);
	memcpy(rxs, &rx->params, sizeof(*rxs));
	return (0);
}

const struct ieee80211_rx_stats *
ieee80211_get_rx_params_ptr(struct mbuf *m)
{
	struct m_tag *mtag;
	struct ieee80211_rx_params *rx;

	mtag = m_tag_find(m, /*MTAG_ABI_NET80211,*/ NET80211_TAG_RECV_PARAMS);
	if (mtag == NULL)
		return (NULL);
	rx = (struct ieee80211_rx_params *)(mtag + 1);
	return (&rx->params);
}


/*
 * Add TOA parameters to the given mbuf.
 */
int
ieee80211_add_toa_params(struct mbuf *m, const struct ieee80211_toa_params *p)
{
	struct m_tag *mtag;
	struct ieee80211_toa_params *rp;

	mtag = m_tag_get(/*MTAG_ABI_NET80211,*/ NET80211_TAG_TOA_PARAMS,
	    sizeof(struct ieee80211_toa_params), M_NOWAIT);
	if (mtag == NULL)
		return (0);

	rp = (struct ieee80211_toa_params *)(mtag + 1);
	memcpy(rp, p, sizeof(*rp));
	m_tag_prepend(m, mtag);
	return (1);
}

int
ieee80211_get_toa_params(struct mbuf *m, struct ieee80211_toa_params *p)
{
	struct m_tag *mtag;
	struct ieee80211_toa_params *rp;

	mtag = m_tag_find(m, /*MTAG_ABI_NET80211,*/ NET80211_TAG_TOA_PARAMS);
	if (mtag == NULL)
		return (0);
	rp = (struct ieee80211_toa_params *)(mtag + 1);
	if (p != NULL)
		memcpy(p, rp, sizeof(*p));
	return (1);
}

/*
 * Transmit a frame to the parent interface.
 */
int
ieee80211_parent_xmitpkt(struct ieee80211com *ic, struct mbuf *m)
{
	struct ieee80211_node *ni;
	struct ifnet *ifp;
	size_t pktlen = m->m_pkthdr.len;
	int error;
	bool mcast = (m->m_flags & M_MCAST) != 0;

	ni = IEEE80211_MBUF_GETNODE(m, struct ieee80211_node *);
	ifp = ni->ni_vap->iv_ifp;

	/*
	 * Assert the IC TX lock is held - this enforces the
	 * processing -> queuing order is maintained
	 */
	IEEE80211_TX_LOCK_ASSERT(ic);
	error = ic->ic_transmit(ic, m);
	if (error) {
		/* XXX number of fragments */
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		ieee80211_free_node(ni);
		ieee80211_free_mbuf(m);
	} else {
		net_stat_ref_t nsr = IF_STAT_GETREF(ifp);
		if_statadd_ref(nsr, if_obytes, pktlen);
		if (mcast)
			if_statinc_ref(nsr, if_omcasts);
		IF_STAT_PUTREF(ni->ni_vap->iv_ifp);
	}
	return (error);
}

/*
 * Transmit a frame to the VAP interface.
 */
int
ieee80211_vap_xmitpkt(struct ieee80211vap *vap, struct mbuf *m)
{
	struct ifnet *ifp = vap->iv_ifp;

	/*
	 * When transmitting via the VAP, we shouldn't hold
	 * any IC TX lock as the VAP TX path will acquire it.
	 */
	IEEE80211_TX_UNLOCK_ASSERT(vap->iv_ic);

	return (ifp->if_transmit(ifp, m));

}

void
get_random_bytes(void *p, size_t n)
{
	uint8_t *dp = p;

	while (n > 0) {
		uint32_t v = arc4random();
		size_t nb = n > sizeof(uint32_t) ? sizeof(uint32_t) : n;
		bcopy(&v, dp, n > sizeof(uint32_t) ? sizeof(uint32_t) : n);
		dp += sizeof(uint32_t), n -= nb;
	}
}

/*
 * Helper function for events that pass just a single mac address.
 */
static void
notify_macaddr(struct ifnet *ifp, int op, const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct ieee80211_join_event iev;

	CURVNET_SET(ifp->if_vnet);
	memset(&iev, 0, sizeof(iev));
	IEEE80211_ADDR_COPY(iev.iev_addr, mac);
	rt_ieee80211msg(ifp, op, &iev, sizeof(iev));
	CURVNET_RESTORE();
}

void
ieee80211_notify_node_join(struct ieee80211_node *ni, int newassoc)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	CURVNET_SET_QUIET(ifp->if_vnet);
	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%snode join",
	    (ni == vap->iv_bss) ? "bss " : "");

	if (ni == vap->iv_bss) {
		notify_macaddr(ifp, newassoc ?
		    RTM_IEEE80211_ASSOC : RTM_IEEE80211_REASSOC, ni->ni_bssid);
		if_link_state_change(ifp, LINK_STATE_UP);
	} else {
		notify_macaddr(ifp, newassoc ?
		    RTM_IEEE80211_JOIN : RTM_IEEE80211_REJOIN, ni->ni_macaddr);
	}
	CURVNET_RESTORE();
}

void
ieee80211_notify_node_leave(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	CURVNET_SET_QUIET(ifp->if_vnet);
	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%snode leave",
	    (ni == vap->iv_bss) ? "bss " : "");

	if (ni == vap->iv_bss) {
		rt_ieee80211msg(ifp, RTM_IEEE80211_DISASSOC, NULL, 0);
		if_link_state_change(ifp, LINK_STATE_DOWN);
	} else {
		/* fire off wireless event station leaving */
		notify_macaddr(ifp, RTM_IEEE80211_LEAVE, ni->ni_macaddr);
	}
	CURVNET_RESTORE();
}

void
ieee80211_notify_scan_done(struct ieee80211vap *vap)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_DPRINTF(vap, IEEE80211_MSG_SCAN, "%s\n", "notify scan done");

	/* dispatch wireless event indicating scan completed */
	CURVNET_SET(ifp->if_vnet);
	rt_ieee80211msg(ifp, RTM_IEEE80211_SCAN, NULL, 0);
	CURVNET_RESTORE();
}

void
ieee80211_notify_replay_failure(struct ieee80211vap *vap,
	const struct ieee80211_frame *wh, const struct ieee80211_key *k,
	u_int64_t rsc, int tid)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO, wh->i_addr2,
	    "%s replay detected tid %d <rsc %ju, csc %ju, keyix %u rxkeyix %u>",
	    k->wk_cipher->ic_name, tid, (intmax_t) rsc,
	    (intmax_t) k->wk_keyrsc[tid],
	    k->wk_keyix, k->wk_rxkeyix);

	if (ifp != NULL) {		/* NB: for cipher test modules */
		struct ieee80211_replay_event iev;

		IEEE80211_ADDR_COPY(iev.iev_dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(iev.iev_src, wh->i_addr2);
		iev.iev_cipher = k->wk_cipher->ic_cipher;
		if (k->wk_rxkeyix != IEEE80211_KEYIX_NONE)
			iev.iev_keyix = k->wk_rxkeyix;
		else
			iev.iev_keyix = k->wk_keyix;
		iev.iev_keyrsc = k->wk_keyrsc[tid];
		iev.iev_rsc = rsc;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_REPLAY, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

void
ieee80211_notify_michael_failure(struct ieee80211vap *vap,
	const struct ieee80211_frame *wh, u_int keyix)
{
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO, wh->i_addr2,
	    "michael MIC verification failed <keyix %u>", keyix);
	vap->iv_stats.is_rx_tkipmic++;

	if (ifp != NULL) {		/* NB: for cipher test modules */
		struct ieee80211_michael_event iev;

		IEEE80211_ADDR_COPY(iev.iev_dst, wh->i_addr1);
		IEEE80211_ADDR_COPY(iev.iev_src, wh->i_addr2);
		iev.iev_cipher = IEEE80211_CIPHER_TKIP;
		iev.iev_keyix = keyix;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_MICHAEL, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

void
ieee80211_notify_wds_discover(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	notify_macaddr(ifp, RTM_IEEE80211_WDS, ni->ni_macaddr);
}

void
ieee80211_notify_csa(struct ieee80211com *ic,
	const struct ieee80211_channel *c, int mode, int count)
{
	struct ieee80211_csa_event iev;
	struct ieee80211vap *vap;
	struct ifnet *ifp;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
	iev.iev_mode = mode;
	iev.iev_count = count;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		ifp = vap->iv_ifp;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_CSA, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

void
ieee80211_notify_radar(struct ieee80211com *ic,
	const struct ieee80211_channel *c)
{
	struct ieee80211_radar_event iev;
	struct ieee80211vap *vap;
	struct ifnet *ifp;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		ifp = vap->iv_ifp;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_RADAR, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

void
ieee80211_notify_cac(struct ieee80211com *ic,
	const struct ieee80211_channel *c, enum ieee80211_notify_cac_event type)
{
	struct ieee80211_cac_event iev;
	struct ieee80211vap *vap;
	struct ifnet *ifp;

	memset(&iev, 0, sizeof(iev));
	iev.iev_flags = c->ic_flags;
	iev.iev_freq = c->ic_freq;
	iev.iev_ieee = c->ic_ieee;
	iev.iev_type = type;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		ifp = vap->iv_ifp;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_CAC, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

void
ieee80211_notify_node_deauth(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%s", "node deauth");

	notify_macaddr(ifp, RTM_IEEE80211_DEAUTH, ni->ni_macaddr);
}

void
ieee80211_notify_node_auth(struct ieee80211_node *ni)
{
	struct ieee80211vap *vap = ni->ni_vap;
	struct ifnet *ifp = vap->iv_ifp;

	IEEE80211_NOTE(vap, IEEE80211_MSG_NODE, ni, "%s", "node auth");

	notify_macaddr(ifp, RTM_IEEE80211_AUTH, ni->ni_macaddr);
}

void
ieee80211_notify_country(struct ieee80211vap *vap,
	const uint8_t bssid[IEEE80211_ADDR_LEN], const uint8_t cc[2])
{
	struct ifnet *ifp = vap->iv_ifp;
	struct ieee80211_country_event iev;

	memset(&iev, 0, sizeof(iev));
	IEEE80211_ADDR_COPY(iev.iev_addr, bssid);
	iev.iev_cc[0] = cc[0];
	iev.iev_cc[1] = cc[1];
	CURVNET_SET(ifp->if_vnet);
	rt_ieee80211msg(ifp, RTM_IEEE80211_COUNTRY, &iev, sizeof(iev));
	CURVNET_RESTORE();
}

void
ieee80211_notify_radio(struct ieee80211com *ic, int state)
{
	struct ieee80211_radio_event iev;
	struct ieee80211vap *vap;
	struct ifnet *ifp;

	memset(&iev, 0, sizeof(iev));
	iev.iev_state = state;
	TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next) {
		ifp = vap->iv_ifp;
		CURVNET_SET(ifp->if_vnet);
		rt_ieee80211msg(ifp, RTM_IEEE80211_RADIO, &iev, sizeof(iev));
		CURVNET_RESTORE();
	}
}

#ifdef notyet
void
ieee80211_load_module(const char *modname)
{
	struct thread *td = curthread;

	if (suser(td) == 0 && securelevel_gt(td->td_ucred, 0) == 0) {
		mtx_lock(&Giant);
		(void) linker_load_module(modname, NULL, NULL, NULL, NULL);
		mtx_unlock(&Giant);
	}
}
#endif

static void
bpf_track(struct bpf_if *bpf, struct ifnet *ifp, int dlt, int event)
{

	if (dlt == DLT_IEEE802_11_RADIO &&
	    ifp->if_init == ieee80211_init) {
		struct ieee80211vap *vap = ifp->if_softc;

		/*
		 * Track bpf radiotap listener state.  We mark the vap
		 * to indicate if any listener is present and the com
		 * to indicate if any listener exists on any associated
		 * vap.  This flag is used by drivers to prepare radiotap
		 * state only when needed.
		 */
		if (event == BPF_TRACK_EVENT_ATTACH) {
			ieee80211_syncflag_ext(vap, IEEE80211_FEXT_BPF);
			if (vap->iv_opmode == IEEE80211_M_MONITOR)
				atomic_add_int(&vap->iv_ic->ic_montaps, 1);
		} else if (event == BPF_TRACK_EVENT_DETACH &&
		    !bpf_peers_present(vap->iv_rawbpf)) {
			ieee80211_syncflag_ext(vap, -IEEE80211_FEXT_BPF);
			if (vap->iv_opmode == IEEE80211_M_MONITOR)
				atomic_subtract_int(&vap->iv_ic->ic_montaps, 1);
		}
	}
}

#ifdef notyet
/*
 * Change MAC address on the vap (if was not started).
 */
static void
wlan_iflladdr(void *arg __unused, struct ifnet *ifp)
{
	/* NB: identify vap's by if_init */  // NNN wont work on urtwn 
	if (ifp->if_init == ieee80211_init &&
	    (ifp->if_flags & IFF_UP) == 0) {
		struct ieee80211vap *vap = ifp->if_softc;

		IEEE80211_ADDR_COPY(vap->iv_myaddr, IF_LLADDR(ifp));
	}
}
#endif

int64_t
if_get_counter_default(struct ifnet * ifp, ift_counter cnt)
{
	struct if_data if_stats;
	int64_t result;

	if_stats_to_if_data(ifp, &if_stats, false);

	result = (cnt == IFCOUNTER_OERRORS ? if_stats.ifi_oerrors :
	    (cnt == IFCOUNTER_IERRORS ? if_stats.ifi_ierrors : 0 ));

	return result;
}

#ifdef notyet
/*
 * Module glue.
 *
 * NB: the module name is "wlan" for compatibility with NetBSD.
 */
static int
wlan_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		if (bootverbose)
			printf("wlan: <802.11 Link Layer>\n");
		wlan_bpfevent = EVENTHANDLER_REGISTER(bpf_track,
		    bpf_track, 0, EVENTHANDLER_PRI_ANY);
		wlan_ifllevent = EVENTHANDLER_REGISTER(iflladdr_event,
		    wlan_iflladdr, NULL, EVENTHANDLER_PRI_ANY);
		wlan_cloner = if_clone_simple(wlanname, wlan_clone_create,
		    wlan_clone_destroy, 0);
		return 0;
	case MOD_UNLOAD:
		if_clone_detach(wlan_cloner);
		EVENTHANDLER_DEREGISTER(bpf_track, wlan_bpfevent);
		EVENTHANDLER_DEREGISTER(iflladdr_event, wlan_ifllevent);
		return 0;
	}
	return EINVAL;
}

static moduledata_t wlan_mod = {
	wlanname,
	wlan_modevent,
	0
};
DECLARE_MODULE(wlan, wlan_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);
MODULE_VERSION(wlan, 1);
MODULE_DEPEND(wlan, ether, 1, 1, 1);
#endif

#ifdef	IEEE80211_ALQ
MODULE_DEPEND(wlan, alq, 1, 1, 1);
#endif	/* IEEE80211_ALQ */

/* Missing support for if_printf in NetBSD ... */
int
if_printf(struct ifnet *ifp, const char *fmt, ...)
{
        char if_fmt[256];
        va_list ap;

        snprintf(if_fmt, sizeof(if_fmt), "%s: %s", ifp->if_xname, fmt);
#ifdef IEEE80211_DEBUG
	if (ieee80211_debug_printf) {
	        va_start(ap, fmt);
		vprintf(if_fmt, ap);
	        va_end(ap);
	} else {
#else
	{
#endif
	        va_start(ap, fmt);
        	vlog(LOG_INFO, if_fmt, ap);
	        va_end(ap);
	}
        return 0;
}

/*
 * Append the specified data to the indicated mbuf chain,
 * Extend the mbuf chain if the new data does not fit in
 * existing space.
 *
 * Return 1 if able to complete the job; otherwise 0.
 */
int
m_append(struct mbuf *m0, int len, const void *cpv)
{
	struct mbuf *m, *n;
	int remainder, space;
	const char *cp = cpv;

	KASSERT(len != M_COPYALL);
	for (m = m0; m->m_next != NULL; m = m->m_next)
		continue;
	remainder = len;
	space = M_TRAILINGSPACE(m);
	if (space > 0) {
		/*
		 * Copy into available space.
		 */
		if (space > remainder)
			space = remainder;
		memmove(mtod(m, char *) + m->m_len, cp, space);
		m->m_len += space;
		cp = cp + space, remainder -= space;
	}
	while (remainder > 0) {
		/*
		 * Allocate a new mbuf; could check space
		 * and allocate a cluster instead.
		 */
		n = m_get(M_DONTWAIT, m->m_type);
		if (n == NULL)
			break;
		n->m_len = uimin(MLEN, remainder);
		memmove(mtod(n, void *), cp, n->m_len);
		cp += n->m_len, remainder -= n->m_len;
		m->m_next = n;
		m = n;
	}
	if (m0->m_flags & M_PKTHDR)
		m0->m_pkthdr.len += len - remainder;
	return (remainder == 0);
}

/*
 * Create a writable copy of the mbuf chain.  While doing this
 * we compact the chain with a goal of producing a chain with
 * at most two mbufs.  The second mbuf in this chain is likely
 * to be a cluster.  The primary purpose of this work is to create
 * a writable packet for encryption, compression, etc.  The
 * secondary goal is to linearize the data so the data can be
 * passed to crypto hardware in the most efficient manner possible.
 */
struct mbuf *
m_unshare(struct mbuf *m0, int how)
{
	struct mbuf *m, *mprev;
	struct mbuf *n, *mfirst, *mlast;
	int len, off;

	mprev = NULL;
	for (m = m0; m != NULL; m = mprev->m_next) {
		/*
		 * Regular mbufs are ignored unless there's a cluster
		 * in front of it that we can use to coalesce.  We do
		 * the latter mainly so later clusters can be coalesced
		 * also w/o having to handle them specially (i.e. convert
		 * mbuf+cluster -> cluster).  This optimization is heavily
		 * influenced by the assumption that we're running over
		 * Ethernet where MCLBYTES is large enough that the max
		 * packet size will permit lots of coalescing into a
		 * single cluster.  This in turn permits efficient
		 * crypto operations, especially when using hardware.
		 */
		if ((m->m_flags & M_EXT) == 0) {
			if (mprev && (mprev->m_flags & M_EXT) &&
			    m->m_len <= M_TRAILINGSPACE(mprev)) {
				/* XXX: this ignores mbuf types */
				memcpy(mtod(mprev, __uint8_t *) + mprev->m_len,
				    mtod(m, __uint8_t *), m->m_len);
				mprev->m_len += m->m_len;
				mprev->m_next = m->m_next;	/* unlink from chain */
				m_free(m);			/* reclaim mbuf */
			} else {
				mprev = m;
			}
			continue;
		}
		/*
		 * Writable mbufs are left alone (for now).
		 */
		if (!M_READONLY(m)) {
			mprev = m;
			continue;
		}

		/*
		 * Not writable, replace with a copy or coalesce with
		 * the previous mbuf if possible (since we have to copy
		 * it anyway, we try to reduce the number of mbufs and
		 * clusters so that future work is easier).
		 */
		KASSERTMSG(m->m_flags & M_EXT, "m_flags 0x%x", m->m_flags);
		/* NB: we only coalesce into a cluster or larger */
		if (mprev != NULL && (mprev->m_flags & M_EXT) &&
		    m->m_len <= M_TRAILINGSPACE(mprev)) {
			/* XXX: this ignores mbuf types */
			memcpy(mtod(mprev, __uint8_t *) + mprev->m_len,
			    mtod(m, __uint8_t *), m->m_len);
			mprev->m_len += m->m_len;
			mprev->m_next = m->m_next;	/* unlink from chain */
			m_free(m);			/* reclaim mbuf */
			continue;
		}

		/*
		 * Allocate new space to hold the copy and copy the data.
		 * We deal with jumbo mbufs (i.e. m_len > MCLBYTES) by
		 * splitting them into clusters.  We could just malloc a
		 * buffer and make it external but too many device drivers
		 * don't know how to break up the non-contiguous memory when
		 * doing DMA.
		 */
		n = m_getcl(how, m->m_type, m->m_flags & M_COPYFLAGS);
		if (n == NULL) {
			m_freem(m0);
			return (NULL);
		}
		if (mprev == NULL && m->m_flags & M_PKTHDR) {
			KASSERTMSG(mprev == NULL, "%s: m0 %p, m %p has M_PKTHDR",
			    __func__, m0, m);
			m_move_pkthdr(n, m);
		}
		len = m->m_len;
		off = 0;
		mfirst = n;
		mlast = NULL;
		for (;;) {
			int cc = uimin(len, MCLBYTES);
			memcpy(mtod(n, __uint8_t *), mtod(m, __uint8_t *) + off, cc);
			n->m_len = cc;
			if (mlast != NULL)
				mlast->m_next = n;
			mlast = n;
#if 0
			newipsecstat.ips_clcopied++;
#endif

			len -= cc;
			if (len <= 0)
				break;
			off += cc;

			n = m_getcl(how, m->m_type, m->m_flags & M_COPYFLAGS);
			if (n == NULL) {
				m_freem(mfirst);
				m_freem(m0);
				return (NULL);
			}
		}
		n->m_next = m->m_next;
		if (mprev == NULL)
			m0 = mfirst;		/* new head of chain */
		else
			mprev->m_next = mfirst;	/* replace old mbuf */
		m_free(m);			/* release old mbuf */
		mprev = mfirst;
	}
	return (m0);
}


int
ieee80211_activate(struct ieee80211com *ic, enum devact act)
{
	struct ieee80211vap *vap;

	switch (act) {
	case DVACT_DEACTIVATE:
		TAILQ_FOREACH(vap, &ic->ic_vaps, iv_next)
			if_deactivate(vap->iv_ifp);
		return 0;
	default:
		return EOPNOTSUPP;
	}
}

/*
 * If we have not yet initialized the ifq/task for global defered
 * processing of mgmt/ctrl frames, do it now.
 */
void
ieee80211_init_mgmt_wqueue(void)
{
	if (ieee80211_rx_mgmt.ifq_maxlen != 0)
		return;	/* been here before */

	IFQ_SET_MAXLEN(&ieee80211_rx_mgmt, IFQ_MAXLEN);
	IFQ_LOCK_INIT(&ieee80211_rx_mgmt);
	TASK_INIT(&ieee80211_mgmt_input, 0, ieee80211_rx_mgmt_cb, 0);
}

/*
 * The last VAP is gone, free taskquee and IFQ resources
 */
void
ieee80211_deinit_mgmt_wqueue(void)
{

	IFQ_LOCK_DESTROY(&ieee80211_rx_mgmt);
	TASK_DESTROY(&ieee80211_mgmt_input);
	memset(&ieee80211_rx_mgmt, 0, sizeof ieee80211_rx_mgmt);
	memset(&ieee80211_mgmt_input, 0, sizeof ieee80211_mgmt_input);
}

/*
 * utility function to handle RX mbuf:
 *  - classifies input and uses proper API to pass it further up the stack
 *  - may queue and process input later in thread context, if input needs
 *    more work than we are allowed in softint context
 */
void
ieee80211_rx_enqueue(struct ieee80211com *ic, struct mbuf *m, int rssi)
{
	struct ieee80211_frame *wh;
	struct ieee80211_node *ni;

	wh = mtod(m, struct ieee80211_frame *);
	ni = ieee80211_find_rxnode(ic, (struct ieee80211_frame_min *)wh);

	if (IEEE80211_IS_DATA(wh)) {
		/*
		 * Just pass it up, it will be enqueued on the VAPs ifqueue
		*/
		if (ni != NULL) {
			if (ni->ni_vap == NULL) {
				ieee80211_free_node(ni);
				return;
			}
			ieee80211_input(ni, m, rssi, 0);
			ieee80211_free_node(ni);
		} else {
			/* XXX will this ever happen? */
			ieee80211_input_all(ic, m, rssi, 0);
		}
	} else {
		/*
		 * We might need to take "heavy" locks during
		 * further processing (like the IC lock), and can
		 * not do this from softint or callout context.
		 */
		M_SETCTX(m, ic);
		m_append(m, sizeof(rssi), &rssi);
		IF_ENQUEUE(&ieee80211_rx_mgmt, m);
		taskqueue_enqueue(ic->ic_tq, &ieee80211_mgmt_input);
	}
}

static void
ieee80211_rx_mgmt_cb(void *a0, int a1)
{
	struct mbuf *m, *ml;
	struct ieee80211com *ic;
	struct ieee80211_node *ni;
	struct ieee80211_frame *wh;
	int rssi;

	for (;;) {
		IF_DEQUEUE(&ieee80211_rx_mgmt, m);
		if (!m)
			return;
		ic = M_GETCTX(m, struct ieee80211com *);
		M_SETCTX(m, NULL);
		/*
		 * usually this will be a single mbuf
		 */
		for (ml = m; ml->m_next != NULL; ml = ml->m_next)
			;
		memcpy(&rssi, mtod(m, char *) + m->m_len - sizeof(rssi),
		    sizeof(rssi));
		m_adj(m, -(ssize_t)sizeof(rssi));


		wh = mtod(m, struct ieee80211_frame *);
		ni = ieee80211_find_rxnode(ic,
		    (struct ieee80211_frame_min *)wh);

		if (ni != NULL) {
			if (ni->ni_vap == NULL) {
				ieee80211_free_node(ni);
				return;
			}
			ieee80211_input(ni, m, rssi, 0);
			ieee80211_free_node(ni);
		} else {
			ieee80211_input_all(ic, m, rssi, 0);
		}
	}
}

