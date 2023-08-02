/* $NetBSD: ieee80211_netbsd.h,v 1.23 2020/03/15 23:04:51 thorpej Exp $ */

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003-2008 Sam Leffler, Errno Consulting
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
 *
 * $FreeBSD:  ieee80211_freebsd.h$
 */
#ifndef _NET80211_IEEE80211_NETBSD_H_
#define _NET80211_IEEE80211_NETBSD_H_

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/cprng.h>
#include <sys/cpu.h>
#include <sys/device.h>
#include <sys/kmem.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/mallocvar.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/sysctl.h>
#include <sys/workqueue.h>

// #include <net80211/_ieee80211.h>

#include <net/if.h>

#ifdef IEEE80211_DEBUG
extern int	ieee80211_debug;
#endif
extern int32_t ieee80211_sysctl_wlan;
/*
 * Defines to make the FreeBSD code work on NetBSD
 */

#define PI_NET IPL_NET
#define EDOOFUS EINVAL
#define IFF_PPROMISC IFF_PROMISC

#define __offsetof(type, field)  __builtin_offsetof(type, field)
#define arc4random  cprng_fast32
#define atomic_subtract_int(var,val) atomic_add_int(var,-(val))
#define caddr_t void *
#define callout_drain(x)  callout_halt(x, NULL)
#define m_catpkt(x,y)    m_cat(x,y)
#define mtx_lock(mtx) 		mutex_enter(mtx)
#define mtx_unlock(mtx)		mutex_exit(mtx)
#define mtx_owned(mtx)		mutex_owned(mtx)
#define mtx_destroy(mtx)	mutex_destroy(mtx)
#define mtx_sleep(ident, mtx, prio, wmesg, timo)	\
	mtsleep(ident, prio, wmesg, timo, mtx)
#define nitems(x)    (sizeof((x)) / sizeof((x)[0]))
#define ovbcopy(dst,src,size)  memmove(dst,src,size)
#define ticks   getticks()

/*
 * task stuff needs major work NNN! 
 */

typedef void task_fn_t(void *context, int pending);

/*
 * We assume that on architectures with 64 bit atomics incrementing a 64bit
 * counter is cheap and that other architectures do not care about error
 * count wrap arrounds after 2^32 errors.
 */
#ifdef __HAVE_ATOMIC64_LOADSTORE
typedef uint64_t counter_u64_t;
#else
typedef uint32_t counter_u64_t;		/* yes, the 64 is a lie! */
#endif
#define	ieee80211_stat_add(PTR,ADD)	\
	atomic_store_relaxed((PTR), (ADD) + atomic_load_relaxed(PTR))

// NNN use more standard feature for getting pointers from fields ...???
struct task {
	struct work t_work;    /* Must be first so we can cast a work to a task */
	task_fn_t  *t_func;
	void       *t_arg;
	kmutex_t    t_mutex;
	int         t_onqueue;
	const char *t_func_name;
};

struct timeout_task { 
	/* Must be first so we can cast to a task. */
	struct task		to_task;
	struct workqueue 	*to_wq;
	callout_t 		to_callout;
	int	    		to_scheduled;	/* 0 inactive,
						 * 1 pending,
						 * -1 draining
						 */
};


static __inline int dummy(void);
static __inline int dummy(void) { return 0; }

void ieee80211_runwork(struct work *, void *);
void taskqueue_enqueue(struct workqueue *, struct task *);
void taskqueue_drain(struct workqueue *, struct task *);

int  taskqueue_enqueue_timeout(struct workqueue	*queue,
	 struct	timeout_task *timeout_task, int	nticks);
int  taskqueue_cancel_timeout(struct workqueue *queue,
	 struct	timeout_task *timeout_task, u_int *pendp);
void taskqueue_drain_timeout(struct workqueue *queue,
	 struct	timeout_task *timeout_task);
int  ieee80211_clone_attach(void);
void ieee80211_init_mgmt_wqueue(void);
void ieee80211_deinit_mgmt_wqueue(void);


#define TASK_INIT(var, pri, func, arg) do { \
	(var)->t_func = func; \
        (var)->t_arg = arg; \
	mutex_init(&(var)->t_mutex, MUTEX_DEFAULT, IPL_SOFTNET);\
	(var)->t_onqueue = 0;\
	(var)->t_func_name = #func; \
} while(0)

#define TASK_DESTROY(var) do { \
	mutex_destroy(&(var)->t_mutex);\
} while(0)

#define TIMEOUT_TASK_INIT(queue, task, pri, func, arg) do { \
	(task)->to_task.t_func = func; \
        (task)->to_task.t_arg = arg; \
	mutex_init(&(task)->to_task.t_mutex, MUTEX_DEFAULT, IPL_SOFTNET);\
	(task)->to_task.t_onqueue = 0;\
	(task)->to_task.t_func_name = #func; \
	(task)->to_wq = queue;\
	callout_init(&(task)->to_callout, CALLOUT_MPSAFE);\
	(task)->to_scheduled = 0;\
} while (0)

#define TIMEOUT_TASK_DESTROY(task) do { \
	mutex_destroy(&(task)->to_task.t_mutex);\
	callout_destroy(&(task)->to_callout);\
} while (0)

#define taskqueue workqueue
#define taskqueue_free(queue)         workqueue_destroy(queue)

#define taskqueue_block(queue)        /* */
#define taskqueue_unblock(queue)      /* */

struct epoch_tracker { } __unused;
#define	NET_EPOCH_ENTER(E)	/* */
#define	NET_EPOCH_EXIT(E)	/* */

/* VNET defines to remove them ... NNN may need a lot of work! */

#define CURVNET_SET(x)		/* */
#define CURVNET_RESTORE() 	/* */
#define CURVNET_SET_QUIET(x) 	/* */

#define	ift_counter		if_stat_t
#define	IFCOUNTER_IPACKETS	if_ipackets
#define	IFCOUNTER_IERRORS	if_ierrors
#define	IFCOUNTER_OPACKETS	if_opackets
#define	IFCOUNTER_OERRORS	if_oerrors
#define	IFCOUNTER_COLLISIONS	if_collisions
#define	IFCOUNTER_IBYTES	if_ibytes
#define	IFCOUNTER_OBYTES	if_obytes
#define	IFCOUNTER_IMCASTS	if_imcasts
#define	IFCOUNTER_OMCASTS	if_omcasts
#define	IFCOUNTER_IQDROPS	if_iqdrops
#define	IFCOUNTER_OQDROPS	/* not available */
#define	IFCOUNTER_NOPROTO	if_noproto
#define	if_inc_counter(IFP,COUNTER,ONE)	if_statinc(IFP,COUNTER)
int64_t if_get_counter_default(struct ifnet * ifp, ift_counter cnt);

#define IF_LLADDR(ifp)     (((struct ieee80211vap *)ifp->if_softc)->iv_myaddr)

/* Scanners ... needed because no module support; */
extern const struct ieee80211_scanner sta_default;
extern const struct ieee80211_scanner ap_default;
extern const struct ieee80211_scanner adhoc_default;
extern const struct ieee80211_scanner mesh_default;

/*
 *  Sysctl support??? NNN
 */

#define SYSCTL_INT(a1, a2, a3, a4, a5, a6, a7)  /* notyet */
#define SYSCTL_PROC(a1, a2, a3, a4, a5, a6, a7, a8, a9)  /* notyet */
#undef SYSCTL_NODE
#define SYSCTL_NODE(a1, a2, a3, a4, a5, a6) int a2 __unused

/* another unknown macro ... at least notyet */
#define SYSINIT(a1, a2, a3, a4, a5)  /* notyet */
#define TEXT_SET(set, sym)   /* notyet ... linker magic, supported?  */

/*
 * Common state locking definitions.
 */
typedef kmutex_t ieee80211_com_lock_t;
#define	IEEE80211_LOCK_INIT(_ic, _name)					\
	mutex_init(&(_ic)->ic_comlock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_LOCK_OBJ(_ic)	(&(_ic)->ic_comlock)
#define	IEEE80211_LOCK_DESTROY(_ic) mutex_destroy(IEEE80211_LOCK_OBJ(_ic))
#define	IEEE80211_LOCK(_ic)	   					\
	mutex_enter(IEEE80211_LOCK_OBJ(_ic))
#define	IEEE80211_UNLOCK(_ic)	   mutex_exit(IEEE80211_LOCK_OBJ(_ic))
#define	IEEE80211_LOCK_ASSERT(_ic)    \
        KASSERTMSG(mutex_owned(IEEE80211_LOCK_OBJ(_ic)), "Lock is not owned")
#define	IEEE80211_UNLOCK_ASSERT(_ic)  /* can not assert !mutex_owned() */

/*
 * Transmit lock.
 *
 * This is a (mostly) temporary lock designed to serialise all of the
 * transmission operations throughout the stack.
 */
typedef kmutex_t ieee80211_tx_lock_t;
#define	IEEE80211_TX_LOCK_INIT(_ic, _name) 				\
	mutex_init(&(_ic)->ic_txlock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_TX_LOCK_OBJ(_ic)	(&(_ic)->ic_txlock)
#define	IEEE80211_TX_LOCK_DESTROY(_ic) mutex_destroy(IEEE80211_TX_LOCK_OBJ(_ic))
#define	IEEE80211_TX_LOCK(_ic)	   mutex_enter(IEEE80211_TX_LOCK_OBJ(_ic))
#define	IEEE80211_TX_UNLOCK(_ic)	   mutex_exit(IEEE80211_TX_LOCK_OBJ(_ic))
#define	IEEE80211_TX_LOCK_ASSERT(_ic) \
	KASSERTMSG(mutex_owned(IEEE80211_TX_LOCK_OBJ(_ic)), "lock not owned")
#define	IEEE80211_TX_UNLOCK_ASSERT(_ic) \
	KASSERTMSG(!mutex_owned(IEEE80211_TX_LOCK_OBJ(_ic)), "lock is owned")

/*
 * Stageq / ni_tx_superg lock
 */
typedef kmutex_t ieee80211_ff_lock_t;
#define IEEE80211_FF_LOCK_INIT(_ic, _name)				\
	mutex_init(&(_ic)->ic_fflock)
#define IEEE80211_FF_LOCK_OBJ(_ic)	(&(_ic)->ic_fflock)
#define IEEE80211_FF_LOCK_DESTROY(_ic)	mutex_destroy(IEEE80211_FF_LOCK_OBJ(_ic))
#define IEEE80211_FF_LOCK(_ic)		mutex_enter(IEEE80211_FF_LOCK_OBJ(_ic))
#define IEEE80211_FF_UNLOCK(_ic)	mutex_exit(IEEE80211_FF_LOCK_OBJ(_ic))
#define IEEE80211_FF_LOCK_ASSERT(_ic) \
	KASSERTMSG(mutex_owned(IEEE80211_FF_LOCK_OBJ(_ic)), "lock not owned")

/*
 * Node locking definitions.
 */
typedef kmutex_t ieee80211_node_lock_t;
#define	IEEE80211_NODE_LOCK_INIT(_nt, _name)				\
	mutex_init(&(_nt)->nt_nodelock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_NODE_LOCK_OBJ(_nt)	(&(_nt)->nt_nodelock)
#define	IEEE80211_NODE_LOCK_DESTROY(_nt) \
	mutex_destroy(IEEE80211_NODE_LOCK_OBJ(_nt))
#define	IEEE80211_NODE_LOCK(_nt) \
	mutex_enter(IEEE80211_NODE_LOCK_OBJ(_nt))
#define	IEEE80211_NODE_IS_LOCKED(_nt) \
	mtx_owned(IEEE80211_NODE_LOCK_OBJ(_nt))
#define	IEEE80211_NODE_UNLOCK(_nt) \
	mutex_exit(IEEE80211_NODE_LOCK_OBJ(_nt))
#define	IEEE80211_NODE_LOCK_ASSERT(_nt)	\
	KASSERTMSG(mutex_owned(IEEE80211_NODE_LOCK_OBJ(_nt)), "lock not owned")

/*
 * Power-save queue definitions. 
 */
typedef kmutex_t ieee80211_psq_lock_t;
#define	IEEE80211_PSQ_INIT(_psq, _name) \
	mutex_init(&(_psq)->psq_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_PSQ_DESTROY(_psq)	mutex_destroy(&(_psq)->psq_lock)
#define	IEEE80211_PSQ_LOCK(_psq)	mutex_enter(&(_psq)->psq_lock)
#define	IEEE80211_PSQ_UNLOCK(_psq)	mutex_exit(&(_psq)->psq_lock)

#ifndef IF_PREPEND_LIST
#define _IF_PREPEND_LIST(ifq, mhead, mtail, mcount) do {	\
	(mtail)->m_nextpkt = (ifq)->ifq_head;			\
	if ((ifq)->ifq_tail == NULL)				\
		(ifq)->ifq_tail = (mtail);			\
	(ifq)->ifq_head = (mhead);				\
	(ifq)->ifq_len += (mcount);				\
} while (0)
#define IF_PREPEND_LIST(ifq, mhead, mtail, mcount) do {		\
	IF_LOCK(ifq);						\
	_IF_PREPEND_LIST(ifq, mhead, mtail, mcount);		\
	IF_UNLOCK(ifq);						\
} while (0)
#endif /* IF_PREPEND_LIST */
 
/*
 * Age queue definitions.
 */
typedef kmutex_t ieee80211_ageq_lock_t;
#define	IEEE80211_AGEQ_INIT(_aq, _name) \
	mutex_init(&(_aq)->aq_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_AGEQ_DESTROY(_aq)	mutex_destroy(&(_aq)->aq_lock)
#define	IEEE80211_AGEQ_LOCK(_aq)	mutex_enter(&(_aq)->aq_lock)
#define	IEEE80211_AGEQ_UNLOCK(_aq)	mutex_exit(&(_aq)->aq_lock)

/*
 * 802.1x MAC ACL database locking definitions.
 */
typedef kmutex_t acl_lock_t;
#define	ACL_LOCK_INIT(_as, _name) \
	mutex_init(&(_as)->as_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	ACL_LOCK_DESTROY(_as)		mutex_destroy(&(_as)->as_lock)
#define	ACL_LOCK(_as)			mutex_enter(&(_as)->as_lock)
#define	ACL_UNLOCK(_as)			mutex_exit(&(_as)->as_lock)
#define	ACL_LOCK_ASSERT(_as) \
	KASSERTMSG(mutex_owned((&(_as)->as_lock)), "lock not owned")

/*
 * Scan table definitions.
 */
typedef kmutex_t ieee80211_scan_table_lock_t;
#define	IEEE80211_SCAN_TABLE_LOCK_INIT(_st, _name) \
	mutex_init(&(_st)->st_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_SCAN_TABLE_LOCK_DESTROY(_st)	mutex_destroy(&(_st)->st_lock)
#define	IEEE80211_SCAN_TABLE_LOCK(_st)		mutex_enter(&(_st)->st_lock)
#define	IEEE80211_SCAN_TABLE_UNLOCK(_st)	mutex_exit(&(_st)->st_lock)

typedef kmutex_t ieee80211_scan_iter_lock_t;
#define	IEEE80211_SCAN_ITER_LOCK_INIT(_st, _name) \
	mutex_init(&(_st)->st_scanlock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	IEEE80211_SCAN_ITER_LOCK_DESTROY(_st)	mutex_destroy(&(_st)->st_scanlock)
#define	IEEE80211_SCAN_ITER_LOCK(_st)		mutex_enter(&(_st)->st_scanlock)
#define	IEEE80211_SCAN_ITER_UNLOCK(_st)	mutex_exit(&(_st)->st_scanlock)

/*
 * Mesh node/routing definitions.
 */
typedef kmutex_t ieee80211_rte_lock_t;
#define	MESH_RT_ENTRY_LOCK_INIT(_rt, _name) \
	mutex_init(&(rt)->rt_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	MESH_RT_ENTRY_LOCK_DESTROY(_rt) \
	mutex_destroy(&(_rt)->rt_lock)
#define	MESH_RT_ENTRY_LOCK(rt)	mutex_enter(&(rt)->rt_lock)
#define	MESH_RT_ENTRY_LOCK_ASSERT(rt)   \
	KASSERTMSG(mutex_owned(&(rt)->rt_lock), "mutex not owned")
#define	MESH_RT_ENTRY_UNLOCK(rt)	mutex_exit(&(rt)->rt_lock)

typedef kmutex_t ieee80211_rt_lock_t;
#define	MESH_RT_LOCK(ms)	mutex_enter(&(ms)->ms_rt_lock)
#define	MESH_RT_LOCK_ASSERT(ms)	\
	KASSERTMSG(mutex_owned(&(ms)->ms_rt_lock), "lock not owned")
#define	MESH_RT_UNLOCK(ms)	mutex_exit(&(ms)->ms_rt_lock)
#define	MESH_RT_LOCK_INIT(ms, name) \
	mutex_init(&(ms)->ms_rt_lock, MUTEX_DEFAULT, IPL_SOFTNET)
#define	MESH_RT_LOCK_DESTROY(ms) \
	mutex_destroy(&(ms)->ms_rt_lock)

struct ieee80211vap;
int	ieee80211_com_vincref(struct ieee80211vap *);
void	ieee80211_com_vdecref(struct ieee80211vap *);
void	ieee80211_com_vdetach(struct ieee80211vap *);

/*
 * Node reference counting definitions.
 *
 * ieee80211_node_initref	initialize the reference count to 1
 * ieee80211_node_incref	add a reference
 * ieee80211_node_decref	remove a reference
 * ieee80211_node_dectestref	remove a reference and return 1 if this
 *				is the last reference, otherwise 0
 * ieee80211_node_refcnt	reference count for printing (only)
 */

#define ieee80211_node_initref(_ni) \
	do { ((_ni)->ni_refcnt = 1); } while (0)
#define ieee80211_node_incref(_ni) \
	atomic_add_int(&(_ni)->ni_refcnt, 1)
#define	ieee80211_node_decref(_ni) \
	atomic_subtract_int(&(_ni)->ni_refcnt, 1)
struct ieee80211_node;
int	ieee80211_node_dectestref(struct ieee80211_node *ni);
#define	ieee80211_node_refcnt(_ni)	(_ni)->ni_refcnt

/*
 * Media locking definitions.
 */
typedef kmutex_t ieee80211_media_lock_t;

/*
 * Media locking definitions.
 */
typedef kmutex_t ieee80211_media_lock_t;

/*
 * FreeBSD uses STAILQs of mbufs very similar to struct ifqueue,
 * but without the ifq_lock. Try to map it 1:1 for now...
 */
struct mbufq {
	struct ifqueue q;
};
 
static inline void
mbufq_init(struct mbufq *mq, int maxlen)
{

	KASSERT(maxlen <= IFQ_MAXLEN);
	memset(mq, 0, sizeof(*mq));
	IFQ_SET_MAXLEN(&mq->q, maxlen);
	mq->q.ifq_len = 0;
}

static inline struct mbuf *
mbufq_flush(struct mbufq *mq)
{
	struct mbuf *m;

	if (IF_IS_EMPTY(&mq->q))
		return NULL;

	IF_POLL(&mq->q, m);
	memset(mq, 0, sizeof(*mq));
	mq->q.ifq_len = 0;
	return m;
}

static inline void
mbufq_drain(struct mbufq *mq)
{
	struct mbuf *m, *n;

	n = mbufq_flush(mq);
	while ((m = n) != NULL) {
		n = m->m_nextpkt;
		m_freem(m);
	}
}

static inline struct mbuf *
mbufq_first(const struct mbufq *mq)
{
	struct mbuf *m;

	IF_POLL(&mq->q, m);
	return m;
}

static inline struct mbuf *
mbufq_last(const struct mbufq *mq)
{
	struct mbuf *m;

	m = mq->q.ifq_tail;
	return m;
}

static inline int
mbufq_full(const struct mbufq *mq)
{

	return IF_QFULL(&mq->q);
}

static inline int
mbufq_len(const struct mbufq *mq)
{

	return mq->q.ifq_len;
}

static inline int
mbufq_maxlen(const struct mbufq *mq)
{

	return mq->q.ifq_maxlen;
}

static inline int
mbufq_enqueue(struct mbufq *mq, struct mbuf *m)
{

	if (mbufq_full(mq))
		return ENOBUFS;
	IF_ENQUEUE(&mq->q, m);
	return 0;
}

static inline struct mbuf *
mbufq_dequeue(struct mbufq *mq)
{
	struct mbuf *m;

	IF_DEQUEUE(&mq->q, m);
	return m;
}

static inline void
mbufq_prepend(struct mbufq *mq, struct mbuf *m)
{

	IF_PREPEND(&mq->q, m);
}

/*
 * Note: this doesn't enforce the maximum list size for dst.
 */
static inline void
mbufq_concat(struct mbufq *mq_dst, struct mbufq *mq_src)
{

	struct mbuf *m;

	for (;;) {
		IF_DEQUEUE(&mq_src->q, m);
		if (m == NULL)
			break;
		IF_ENQUEUE(&mq_dst->q, m);
	}
}

struct ifqueue;
struct ieee80211vap;
void	ieee80211_drain_ifq(struct ifqueue *);
void	ieee80211_flush_ifq(struct ifqueue *, struct ieee80211vap *);

void	ieee80211_vap_destroy(struct ieee80211vap *);

#define	IFNET_IS_UP_RUNNING(_ifp) \
	(((_ifp)->if_flags & IFF_UP) && \
	 ((_ifp)->if_flags & IFF_RUNNING))

/*
 * Convert times to ticks and back.
 * Result will be uint32_t, but we expand to uint64_t to avoid
 * overflow/underflow. Result will always be at least 1.
 */
#define	msecs_to_ticks(m)			\
	ulmax(1, (uint32_t)(			\
		(hz == 1000) ? (m) :		\
		(hz == 100) ? ((m)/10) :	\
			((uint64_t)(m) * (uint64_t)hz)/(uint64_t)1000))
#define	ticks_to_msecs(t)			\
	ulmax(1, (uint32_t)(			\
		(hz == 1000) ? (t) :		\
		(hz == 100) ? ((t)*10) :	\
			(((uint64_t)(t) * (uint64_t)1000)/(uint64_t)hz)))
#define	ticks_to_secs(t)	(uint)((t) / hz)

#define ieee80211_time_after(a,b) 	((long)(b) - (long)(a) < 0)
#define ieee80211_time_before(a,b)	ieee80211_time_after(b,a)
#define ieee80211_time_after_eq(a,b)	((long)(a) - (long)(b) >= 0)
#define ieee80211_time_before_eq(a,b)	ieee80211_time_after_eq(b,a)

struct mbuf *ieee80211_getmgtframe(uint8_t **frm, int headroom, int pktlen);

/* tx path usage */
#define	M_ENCAP		M_LINK0		/* 802.11 encap done */
#define	M_EAPOL		M_LINK3		/* PAE/EAPOL frame */
#define	M_PWR_SAV	M_LINK4		/* bypass PS handling */
#define	M_MORE_DATA	M_LINK5		/* more data frames to follow */
#define	M_FF		M_LINK6		/* fast frame / A-MSDU */
#define	M_TXCB		M_LINK7		/* do tx complete callback */
#define	M_AMPDU_MPDU	M_LINK8		/* ok for A-MPDU aggregation */
#define	M_FRAG		M_LINK9		/* frame fragmentation */
#define	M_FIRSTFRAG	M_LINK10	/* first frame fragment */
#define	M_LASTFRAG	M_LINK11	/* last frame fragment */

#define	M_80211_TX \
	(M_ENCAP|M_EAPOL|M_PWR_SAV|M_MORE_DATA|M_FF|M_TXCB| \
	 M_AMPDU_MPDU|M_FRAG|M_FIRSTFRAG|M_LASTFRAG)

/* rx path usage */
#define	M_AMPDU		M_LINK1		/* A-MPDU subframe */
#define	M_WEP		M_LINK2		/* WEP done by hardware */
#if 0
#define	M_AMPDU_MPDU	M_LINK8		/* A-MPDU re-order done */
#endif
#define	M_80211_RX	(M_AMPDU|M_WEP|M_AMPDU_MPDU)

#define	IEEE80211_MBUF_TX_FLAG_BITS \
	M_FLAG_BITS \
	"\15M_ENCAP\17M_EAPOL\20M_PWR_SAV\21M_MORE_DATA\22M_FF\23M_TXCB" \
	"\24M_AMPDU_MPDU\25M_FRAG\26M_FIRSTFRAG\27M_LASTFRAG"

#define	IEEE80211_MBUF_RX_FLAG_BITS \
	M_FLAG_BITS \
	"\15M_AMPDU\16M_WEP\24M_AMPDU_MPDU"

/*
 * Store WME access control bits in the vlan tag.
 * This is safe since it's done after the packet is classified
 * (where we use any previous tag) and because it's passed
 * directly in to the driver and there's no chance someone
 * else will clobber them on us.
 */
#define	M_WME_SETAC(m, ac) \
	((m)->m_pkthdr.ether_vtag = (ac))
#define	M_WME_GETAC(m)	((m)->m_pkthdr.ether_vtag)

/*
 * Store a node pointer in the mbuf context
 *
 * FreeBSD version: 
 *	(M)->m_pkthdr.rcvif = (void *)(N);
 *	(T)(M)->m_pkthdr.rcvif
 */
#define IEEE80211_MBUF_SETNODE(M, N)	M_SETCTX(M, N)
#define	IEEE80211_MBUF_GETNODE(M, T)	M_GETCTX(M, T)

/*
 * Mbufs on the power save queue are tagged with an age and
 * timed out.  We reuse the hardware checksum field in the
 * mbuf packet header to store this data.
 */
#define	M_AGE_SET(m,v)		(m->m_pkthdr.csum_data = v)
#define	M_AGE_GET(m)		(m->m_pkthdr.csum_data)
#define	M_AGE_SUB(m,adj)	(m->m_pkthdr.csum_data -= adj)

/*
 * Store the sequence number.  XXX?  correct to use segsz?
 */
#define	M_SEQNO_SET(m, seqno) \
	((m)->m_pkthdr.segsz = (seqno))
#define	M_SEQNO_GET(m)	((m)->m_pkthdr.segsz)

#define	MTAG_ABI_NET80211	1132948340	/* net80211 ABI */

struct ieee80211_cb {
	void	(*func)(struct ieee80211_node *, void *, int status);
	void	*arg;
};
#define	NET80211_TAG_CALLBACK	0	/* xmit complete callback */
int	ieee80211_add_callback(struct mbuf *m,
		void (*func)(struct ieee80211_node *, void *, int), void *arg);
void	ieee80211_process_callback(struct ieee80211_node *, struct mbuf *, int);

#define	NET80211_TAG_XMIT_PARAMS	1
/* See below; this is after the bpf_params definition */

#define	NET80211_TAG_RECV_PARAMS	2

#define	NET80211_TAG_TOA_PARAMS		3

struct ieee80211com;
int	ieee80211_parent_xmitpkt(struct ieee80211com *, struct mbuf *);
int	ieee80211_vap_xmitpkt(struct ieee80211vap *, struct mbuf *);

void	net80211_get_random_bytes(void *, size_t);

void	ieee80211_sysctl_attach(struct ieee80211com *);
void	ieee80211_sysctl_detach(struct ieee80211com *);
void	ieee80211_sysctl_vattach(struct ieee80211vap *);
void	ieee80211_sysctl_vdetach(struct ieee80211vap *);

#if notyet
SYSCTL_DECL(_net_wlan);
int	ieee80211_sysctl_msecs_ticks(SYSCTL_HANDLER_ARGS);
#endif 


#ifdef notyet

/*
 * A "policy module" is an adjunct module to net80211 that provides
 * functionality that typically includes policy decisions.  This
 * modularity enables extensibility and vendor-supplied functionality.
 */
#define	_IEEE80211_POLICY_MODULE(policy, name, version)			\
typedef void (*policy##_setup)(int);					\
SET_DECLARE(policy##_set, policy##_setup);				\
static int								\
wlan_##name##_modevent(module_t mod, int type, void *unused)		\
{									\
	policy##_setup * const *iter, f;				\
	switch (type) {							\
	case MOD_LOAD:							\
		SET_FOREACH(iter, policy##_set) {			\
			f = (void*) *iter;				\
			f(type);					\
		}							\
		return 0;						\
	case MOD_UNLOAD:						\
	case MOD_QUIESCE:						\
		if (nrefs) {						\
			printf("wlan_" #name ": still in use "		\
				"(%u dynamic refs)\n", nrefs);		\
			return EBUSY;					\
		}							\
		if (type == MOD_UNLOAD) {				\
			SET_FOREACH(iter, policy##_set) {		\
				f = (void*) *iter;			\
				f(type);				\
			}						\
		}							\
		return 0;						\
	}								\
	return EINVAL;							\
}									\
static moduledata_t name##_mod = {					\
	"wlan_" #name,							\
	wlan_##name##_modevent,						\
	0								\
};									\
DECLARE_MODULE(wlan_##name, name##_mod, SI_SUB_DRIVERS, SI_ORDER_FIRST);\
MODULE_VERSION(wlan_##name, version);					\
MODULE_DEPEND(wlan_##name, wlan, 1, 1, 1)

/*
 * Crypto modules implement cipher support.
 */
#define	IEEE80211_CRYPTO_MODULE(name, version)				\
_IEEE80211_POLICY_MODULE(crypto, name, version);			\
static void								\
name##_modevent(int type)						\
{									\
	if (type == MOD_LOAD)						\
		ieee80211_crypto_register(&name);			\
	else								\
		ieee80211_crypto_unregister(&name);			\
}									\
TEXT_SET(crypto##_set, name##_modevent)

/*
 * Scanner modules provide scanning policy.
 */
#define	IEEE80211_SCANNER_MODULE(name, version)				\
	_IEEE80211_POLICY_MODULE(scanner, name, version)

#define	IEEE80211_SCANNER_ALG(name, alg, v)				\
static void								\
name##_modevent(int type)						\
{									\
	if (type == MOD_LOAD)						\
		ieee80211_scanner_register(alg, &v);			\
	else								\
		ieee80211_scanner_unregister(alg, &v);			\
}									\
TEXT_SET(scanner_set, name##_modevent);					\

/*
 * ACL modules implement acl policy.
 */
#define	IEEE80211_ACL_MODULE(name, alg, version)			\
_IEEE80211_POLICY_MODULE(acl, name, version);				\
static void								\
alg##_modevent(int type)						\
{									\
	if (type == MOD_LOAD)						\
		ieee80211_aclator_register(&alg);			\
	else								\
		ieee80211_aclator_unregister(&alg);			\
}									\
TEXT_SET(acl_set, alg##_modevent);					\

/*
 * Authenticator modules handle 802.1x/WPA authentication.
 */
#define	IEEE80211_AUTH_MODULE(name, version)				\
	_IEEE80211_POLICY_MODULE(auth, name, version)

#define	IEEE80211_AUTH_ALG(name, alg, v)				\
static void								\
name##_modevent(int type)						\
{									\
	if (type == MOD_LOAD)						\
		ieee80211_authenticator_register(alg, &v);		\
	else								\
		ieee80211_authenticator_unregister(alg);		\
}									\
TEXT_SET(auth_set, name##_modevent)

/*
 * Rate control modules provide tx rate control support.
 */
#define	IEEE80211_RATECTL_MODULE(alg, version)				\
	_IEEE80211_POLICY_MODULE(ratectl, alg, version);		\

#define	IEEE80211_RATECTL_ALG(name, alg, v)				\
static void								\
alg##_modevent(int type)						\
{									\
	if (type == MOD_LOAD)						\
		ieee80211_ratectl_register(alg, &v);			\
	else								\
		ieee80211_ratectl_unregister(alg);			\
}									\
TEXT_SET(ratectl##_set, alg##_modevent)

#else
/* NNN This looks like module load/unload support ... notyet supported  */
#define _IEEE80211_POLICY_MODULE(policy, name, version)	/* unsupported */
#define IEEE80211_CRYPTO_MODULE(name, version) 		/* unsupported */
#define IEEE80211_SCANNER_MODULE(name, version) 	/* unsupported */
#define IEEE80211_SCANNER_ALG(name, alg, v) 		/* unsupported */
#define IEEE80211_ACL_MODULE(name, alg, version) 	const void *const temp = &alg
#define IEEE80211_AUTH_MODULE(name, version)          	/* unsupported */
#define IEEE80211_AUTH_ALG(name, alg, v) 		/* unsupported */
#define IEEE80211_RATECTL_MODULE(alg, version)          /* unsupported */
#define IEEE80211_RATECTL_ALG(name, alg, v)  		/* unsupported */
#endif

/*
 * IOCTL support
 */

struct ieee80211req;

typedef int ieee80211_ioctl_getfunc(struct ieee80211vap *,  struct ieee80211req *);
#if notyet
SET_DECLARE(ieee80211_ioctl_getset, ieee80211_ioctl_getfunc);
#endif 
#define	IEEE80211_IOCTL_GET(_name, _get) TEXT_SET(ieee80211_ioctl_getset, _get)

typedef int ieee80211_ioctl_setfunc(struct ieee80211vap *,  struct ieee80211req *);
#if notyet
SET_DECLARE(ieee80211_ioctl_setset, ieee80211_ioctl_setfunc);
#endif
#define	IEEE80211_IOCTL_SET(_name, _set) TEXT_SET(ieee80211_ioctl_setset, _set)

#endif /* _KERNEL */

/* XXX this stuff belongs elsewhere */
/*
 * Message formats for messages from the net80211 layer to user
 * applications via the routing socket.  These messages are appended
 * to an if_announcemsghdr structure.
 */
struct ieee80211_join_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_leave_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_replay_event {
	uint8_t		iev_src[6];	/* src MAC */
	uint8_t		iev_dst[6];	/* dst MAC */
	uint8_t		iev_cipher;	/* cipher type */
	uint8_t		iev_keyix;	/* key id/index */
	uint64_t	iev_keyrsc;	/* RSC from key */
	uint64_t	iev_rsc;	/* RSC from frame */
};

struct ieee80211_michael_event {
	uint8_t		iev_src[6];	/* src MAC */
	uint8_t		iev_dst[6];	/* dst MAC */
	uint8_t		iev_cipher;	/* cipher type */
	uint8_t		iev_keyix;	/* key id/index */
};

struct ieee80211_wds_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_csa_event {
	uint32_t	iev_flags;	/* channel flags */
	uint16_t	iev_freq;	/* setting in Mhz */
	uint8_t		iev_ieee;	/* IEEE channel number */
	uint8_t		iev_mode;	/* CSA mode */
	uint8_t		iev_count;	/* CSA count */
};

struct ieee80211_cac_event {
	uint32_t	iev_flags;	/* channel flags */
	uint16_t	iev_freq;	/* setting in Mhz */
	uint8_t		iev_ieee;	/* IEEE channel number */
	/* XXX timestamp? */
	uint8_t		iev_type;	/* IEEE80211_NOTIFY_CAC_* */
};

struct ieee80211_radar_event {
	uint32_t	iev_flags;	/* channel flags */
	uint16_t	iev_freq;	/* setting in Mhz */
	uint8_t		iev_ieee;	/* IEEE channel number */
	/* XXX timestamp? */
};

struct ieee80211_auth_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_deauth_event {
	uint8_t		iev_addr[6];
};

struct ieee80211_country_event {
	uint8_t		iev_addr[6];
	uint8_t		iev_cc[2];	/* ISO country code */
};

struct ieee80211_radio_event {
	uint8_t		iev_state;	/* 1 on, 0 off */
};

#define	RTM_IEEE80211_ASSOC	100	/* station associate (bss mode) */
#define	RTM_IEEE80211_REASSOC	101	/* station re-associate (bss mode) */
#define	RTM_IEEE80211_DISASSOC	102	/* station disassociate (bss mode) */
#define	RTM_IEEE80211_JOIN	103	/* station join (ap mode) */
#define	RTM_IEEE80211_LEAVE	104	/* station leave (ap mode) */
#define	RTM_IEEE80211_SCAN	105	/* scan complete, results available */
#define	RTM_IEEE80211_REPLAY	106	/* sequence counter replay detected */
#define	RTM_IEEE80211_MICHAEL	107	/* Michael MIC failure detected */
#define	RTM_IEEE80211_REJOIN	108	/* station re-associate (ap mode) */
#define	RTM_IEEE80211_WDS	109	/* WDS discovery (ap mode) */
#define	RTM_IEEE80211_CSA	110	/* Channel Switch Announcement event */
#define	RTM_IEEE80211_RADAR	111	/* radar event */
#define	RTM_IEEE80211_CAC	112	/* Channel Availability Check event */
#define	RTM_IEEE80211_DEAUTH	113	/* station deauthenticate */
#define	RTM_IEEE80211_AUTH	114	/* station authenticate (ap mode) */
#define	RTM_IEEE80211_COUNTRY	115	/* discovered country code (sta mode) */
#define	RTM_IEEE80211_RADIO	116	/* RF kill switch state change */

/*
 * Structure prepended to raw packets sent through the bpf
 * interface when set to DLT_IEEE802_11_RADIO.  This allows
 * user applications to specify pretty much everything in
 * an Atheros tx descriptor.  XXX need to generalize.
 *
 * XXX cannot be more than 14 bytes as it is copied to a sockaddr's
 * XXX sa_data area.
 */
struct ieee80211_bpf_params {
	uint8_t		ibp_vers;	/* version */
#define	IEEE80211_BPF_VERSION	0
	uint8_t		ibp_len;	/* header length in bytes */
	uint8_t		ibp_flags;
#define	IEEE80211_BPF_SHORTPRE	0x01	/* tx with short preamble */
#define	IEEE80211_BPF_NOACK	0x02	/* tx with no ack */
#define	IEEE80211_BPF_CRYPTO	0x04	/* tx with h/w encryption */
#define	IEEE80211_BPF_FCS	0x10	/* frame incldues FCS */
#define	IEEE80211_BPF_DATAPAD	0x20	/* frame includes data padding */
#define	IEEE80211_BPF_RTS	0x40	/* tx with RTS/CTS */
#define	IEEE80211_BPF_CTS	0x80	/* tx with CTS only */
	uint8_t		ibp_pri;	/* WME/WMM AC+tx antenna */
	uint8_t		ibp_try0;	/* series 1 try count */
	uint8_t		ibp_rate0;	/* series 1 IEEE tx rate */
	uint8_t		ibp_power;	/* tx power (device units) */
	uint8_t		ibp_ctsrate;	/* IEEE tx rate for CTS */
	uint8_t		ibp_try1;	/* series 2 try count */
	uint8_t		ibp_rate1;	/* series 2 IEEE tx rate */
	uint8_t		ibp_try2;	/* series 3 try count */
	uint8_t		ibp_rate2;	/* series 3 IEEE tx rate */
	uint8_t		ibp_try3;	/* series 4 try count */
	uint8_t		ibp_rate3;	/* series 4 IEEE tx rate */
};

#ifdef _KERNEL
struct ieee80211_tx_params {
	struct ieee80211_bpf_params params;
};
int	ieee80211_add_xmit_params(struct mbuf *m,
	    const struct ieee80211_bpf_params *);
int	ieee80211_get_xmit_params(struct mbuf *m,
	    struct ieee80211_bpf_params *);

struct ieee80211_rx_params;
struct ieee80211_rx_stats;

int	ieee80211_add_rx_params(struct mbuf *m,
	    const struct ieee80211_rx_stats *rxs);
int	ieee80211_get_rx_params(struct mbuf *m,
	    struct ieee80211_rx_stats *rxs);
const struct ieee80211_rx_stats * ieee80211_get_rx_params_ptr(struct mbuf *m);

struct ieee80211_toa_params {
	int request_id;
};
int	ieee80211_add_toa_params(struct mbuf *m,
	    const struct ieee80211_toa_params *p);
int	ieee80211_get_toa_params(struct mbuf *m,
	    struct ieee80211_toa_params *p);

#define	IEEE80211_F_SURVEY_TIME		0x00000001
#define	IEEE80211_F_SURVEY_TIME_BUSY	0x00000002
#define	IEEE80211_F_SURVEY_NOISE_DBM	0x00000004
#define	IEEE80211_F_SURVEY_TSC		0x00000008
struct ieee80211_channel_survey {
	uint32_t s_flags;
	uint32_t s_time;
	uint32_t s_time_busy;
	int32_t s_noise;
	uint64_t s_tsc;
};


/*
 * Memory allocation API.  Other BSD operating systems have slightly
 * different malloc/free namings or totaly different allocators.
 *
 * We use the following types of allocations:
 *  IEEE80211_M{Z,}ALLOC	not yet converted old style malloc,
 *				used whenver interrupt and non-interrupt
 *				allocations are mixed or state is unclear
 *	- whenever we can move this type of allocation to one of the
 *	  other types!
 *
 *  IEEE80211_{Z,}ALLOC		allocations known to only happen in
 *				thread context using kmem(9)
 *  IEEE80211_INTR_ZALLOC	fixed size allocations known to only
 *				happen in interrupt context
 *
 * In the macros:
 *  S = size of the allocation
 *  U = use type (e.g. when malloc() is used, the malloc type, or the
 *      pool when pool_cache(9) is used)
 *  F = flags (see below)
 */
#if 0
/*
 * Old style malloc / free
 *   requires different definitions for IEEE80211_M_* flags below!
 */
#define	IEEE80211_MALLOC(S,U,F)		malloc((S),(U),(F))
#define	IEEE80211_MZALLOC(S,U,F)	malloc((S),(U),(F)|M_ZERO)
#define	IEEE80211_MFREE(P,U,S)		do { (void)(S); free((P),(U)); } while(0)
#else
/*
 * Use kmem_intr_* - so we get at least the size matching between
 * allocation and free tested. We will try to move as many uses
 * to one of the other variants whenver possible.
 */
#define	IEEE80211_MALLOC(S,U,F)		kmem_intr_alloc((S), (F))
#define	IEEE80211_MZALLOC(S,U,F)	kmem_intr_zalloc((S), (F))
#define	IEEE80211_MFREE(P,U,S)		kmem_intr_free((P), (S))
#endif
#define	IEEE80211_ALLOC(S,U,F)		kmem_alloc((S), (F))
#define IEEE80211_ZALLOC(S,U,F)		kmem_zalloc((S), (F))
#define	IEEE80211_FREE(P,U,S)		kmem_free((P), (S))
#define IEEE80211_INTR_ZALLOC(S,U,F)	pool_cache_get((U), PR_NOWAIT|PR_ZERO)
#define	IEEE80211_INTR_FREE(P,U,S)	pool_cache_put((U), (P))

/* flags for above */
#define	IEEE80211_M_NOWAIT	KM_NOSLEEP
#define	IEEE80211_M_WAITOK	KM_SLEEP
#define IEEE80211_M_ZERO	M_ZERO

#define	CSUM_SND_TAG		0	/* XXX what is this? */

/* XXX TODO: the type fields */

/*
 * Startup function for NetBSD
 */

int ieee80211_init0(void);


/*
 * Functions FreeBSD uses that NetBSD doesn't have ...
 */

int	if_printf(struct ifnet *ifp, const char *fmt, ...)  __printflike(2, 3);
void	m_align(struct mbuf *m, int len);
int	m_append(struct mbuf *m0, int len, const void *cpv);
struct mbuf * m_unshare(struct mbuf *m0, int how);

static __inline void m_clrprotoflags(struct mbuf *m)
{
	m->m_flags &= ~(M_LINK0|M_LINK1|M_LINK2|M_LINK3|M_LINK4|M_LINK5
	    |M_LINK6|M_LINK7|M_LINK8|M_LINK9|M_LINK10|M_LINK11);
}

int ieee80211_activate(struct ieee80211com *, enum devact act);

/*-
 * Macro for type conversion: convert mbuf pointer to data pointer of correct
 * type:
 *
 * mtod(m, t)   -- Convert mbuf pointer to data pointer of correct type.
 * mtodo(m, o) -- Same as above but with offset 'o' into data.
 */
#define mtod(m, t)      ((t)((m)->m_data))
#define mtodo(m, o)     ((void *)(((m)->m_data) + (o)))

/* Berkeley Packet Filter shim  */

#define BPF_MTAP(_ifp,_m) do {                          \
	bpf_mtap((_ifp), (_m), BPF_D_INOUT);            \
} while (0)

/*  Missing define in net/if_ether.h   */

#define ETHER_IS_BROADCAST(addr) \
        (((addr)[0] & (addr)[1] & (addr)[2] & \
          (addr)[3] & (addr)[4] & (addr)[5]) == 0xff)

/* compatibility / easy driver conversion macros */

#define	ieee80211_has_qos(WH)	IEEE80211_QOS_HAS_SEQ(WH)
#define	ieee80211_get_qos(WH)	\
	(((struct ieee80211_qosframe *)(void*)(WH))->i_qos[0])

/*
 * utility function to handle RX mbuf:
 *  - classifies input and uses proper API to pass it further up the stack
 *  - may queue and process input later in thread context, if input needs
 *    more work than we are allowed in softint context
 */
void ieee80211_rx_enqueue(struct ieee80211com *ic, struct mbuf *m, int rssi);

#endif /* _KERNEL */

#endif /* _NET80211_IEEE80211_NETBSD_H_ */
