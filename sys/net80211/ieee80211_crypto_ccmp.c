/*	$NetBSD: ieee80211_crypto_ccmp.c,v 1.19 2020/11/03 15:06:50 mlelstv Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2002-2008 Sam Leffler, Errno Consulting
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
#ifdef __FreeBSD__
__FBSDID("$FreeBSD: head/sys/net80211/ieee80211_crypto_ccmp.c 326272 2017-11-27 15:23:17Z pfg $$");
#endif
#ifdef __NetBSD__
__KERNEL_RCSID(0, "$NetBSD: ieee80211_crypto_ccmp.c,v 1.19 2020/11/03 15:06:50 mlelstv Exp $");
#endif

/*
 * IEEE 802.11i AES-CCMP crypto support.
 *
 * Part of this module is derived from similar code in the Host
 * AP driver. The code is used with the consent of the author and
 * it's license is included below.
 */
#ifdef _KERNEL_OPT
#include "opt_wlan.h"
#endif

#include <sys/param.h>
#include <sys/systm.h> 
#include <sys/mbuf.h>   
#include <sys/kernel.h>
#include <sys/module.h>

#include <sys/socket.h>

#include <net/if.h>
#include <net/if_media.h>
#if __FreeBSD__
#include <net/ethernet.h>
#endif
#ifdef __NetBSD__
#include <net/route.h>
#include <net/if_ether.h>
#include <sys/once.h>
#include <sys/cpu.h>
#endif

#include <net80211/ieee80211_var.h>

#include <crypto/aes/aes.h>
#include <crypto/aes/aes_ccm.h>
#include <crypto/aes/aes_ccm_mbuf.h>

#define AES_BLOCK_LEN 16

#if 0 // __NetBSD__
static pool_cache_t ieee80211_ccmp_ctx_pool;
#define M_80211_CRYPTO_CCMP	ieee80211_ccmp_ctx_pool
#endif

struct ccmp_ctx {
	struct aesenc	     cc_aes;
	struct ieee80211vap *cc_vap;	/* for diagnostics+statistics */
	struct ieee80211com *cc_ic;
};

static	void *ccmp_attach(struct ieee80211vap *, struct ieee80211_key *);
static	void ccmp_detach(struct ieee80211_key *);
static	int ccmp_setkey(struct ieee80211_key *);
static	void ccmp_setiv(struct ieee80211_key *, uint8_t *);
static	int ccmp_encap(struct ieee80211_key *, struct mbuf *);
static	int ccmp_decap(struct ieee80211_key *, struct mbuf *, int);
static	int ccmp_enmic(struct ieee80211_key *, struct mbuf *, int);
static	int ccmp_demic(struct ieee80211_key *, struct mbuf *, int);

const struct ieee80211_cipher ccmp = {
	.ic_name	= "AES-CCM",
	.ic_cipher	= IEEE80211_CIPHER_AES_CCM,
	.ic_header	= IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
			  IEEE80211_WEP_EXTIVLEN,
	.ic_trailer	= IEEE80211_WEP_MICLEN,
	.ic_miclen	= 0,
	.ic_attach	= ccmp_attach,
	.ic_detach	= ccmp_detach,
	.ic_setkey	= ccmp_setkey,
	.ic_setiv	= ccmp_setiv,
	.ic_encap	= ccmp_encap,
	.ic_decap	= ccmp_decap,
	.ic_enmic	= ccmp_enmic,
	.ic_demic	= ccmp_demic,
};

static	int ccmp_encrypt(struct ieee80211_key *, struct mbuf *, int hdrlen);
static	int ccmp_decrypt(struct ieee80211_key *, u_int64_t pn,
		struct mbuf *, int hdrlen);

/* number of references from net80211 layer */
static	int nrefs = 0;

#if 0 // __NetBSD__
/*
 * Init pool for ccmp contexts (which may be allocated/freed from
 * interrupt context)
 */
static int
ieee80211_ccmp_pool_init(void)
{

	KASSERT(!cpu_intr_p());
	ieee80211_ccmp_ctx_pool = pool_cache_init(sizeof(struct ccmp_ctx),
	    0, 0, 0, "ccmpctx", NULL, IPL_NET, NULL, NULL, NULL);
	return 0;
}
#endif

static void *
ccmp_attach(struct ieee80211vap *vap, struct ieee80211_key *k)
{
	struct ccmp_ctx *ctx;
#if 0 // __NetBSD__
	static ONCE_DECL(ieee80211_ccmp_pool_init_once);

	RUN_ONCE(&ieee80211_ccmp_pool_init_once, ieee80211_ccmp_pool_init);
#endif

	ctx = (struct ccmp_ctx *)IEEE80211_ZALLOC(sizeof(struct ccmp_ctx),
		M_80211_CRYPTO_CCMP, IEEE80211_M_NOWAIT);
	if (ctx == NULL) {
		vap->iv_stats.is_crypto_nomem++;
		return NULL;
	}
	ctx->cc_vap = vap;
	ctx->cc_ic = vap->iv_ic;
	nrefs++;			/* NB: we assume caller locking */
	return ctx;
}

static void
ccmp_detach(struct ieee80211_key *k)
{
	struct ccmp_ctx *ctx = k->wk_private;

	IEEE80211_FREE(ctx, M_80211_CRYPTO_CCMP, sizeof(*ctx));
	KASSERTMSG(nrefs > 0, "imbalanced attach/detach");
	nrefs--;			/* NB: we assume caller locking */
}

static int
ccmp_setkey(struct ieee80211_key *k)
{
	struct ccmp_ctx *ctx = k->wk_private;

	if (k->wk_keylen != (128/NBBY)) {
		IEEE80211_DPRINTF(ctx->cc_vap, IEEE80211_MSG_CRYPTO,
			"%s: Invalid key length %u, expecting %u\n",
			__func__, k->wk_keylen, 128/NBBY);
		return 0;
	}
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT)
		aes_setenckey128(&ctx->cc_aes, k->wk_key);
	return 1;
}

static void
ccmp_setiv(struct ieee80211_key *k, uint8_t *ivp)
{
	struct ccmp_ctx *ctx = k->wk_private;
	struct ieee80211vap *vap = ctx->cc_vap;
	uint8_t keyid;

	keyid = ieee80211_crypto_get_keyid(vap, k) << 6;

	k->wk_keytsc++;
	ivp[0] = k->wk_keytsc >> 0;		/* PN0 */
	ivp[1] = k->wk_keytsc >> 8;		/* PN1 */
	ivp[2] = 0;				/* Reserved */
	ivp[3] = keyid | IEEE80211_WEP_EXTIV;	/* KeyID | ExtID */
	ivp[4] = k->wk_keytsc >> 16;		/* PN2 */
	ivp[5] = k->wk_keytsc >> 24;		/* PN3 */
	ivp[6] = k->wk_keytsc >> 32;		/* PN4 */
	ivp[7] = k->wk_keytsc >> 40;		/* PN5 */
}

/*
 * Add privacy headers appropriate for the specified key.
 */
static int
ccmp_encap(struct ieee80211_key *k, struct mbuf *m)
{
	const struct ieee80211_frame *wh;
	struct ccmp_ctx *ctx = k->wk_private;
	struct ieee80211com *ic = ctx->cc_ic;
	uint8_t *ivp;
	int hdrlen;
	int is_mgmt;

	hdrlen = ieee80211_hdrspace(ic, mtod(m, void *));
	wh = mtod(m, const struct ieee80211_frame *);
	is_mgmt = IEEE80211_IS_MGMT(wh);

	/*
	 * Check to see if we need to insert IV/MIC.
	 *
	 * Some offload devices don't require the IV to be inserted
	 * as part of the hardware encryption.
	 */
	if (is_mgmt && (k->wk_flags & IEEE80211_KEY_NOIVMGT))
		return 1;
	if ((! is_mgmt) && (k->wk_flags & IEEE80211_KEY_NOIV))
		return 1;

	/*
	 * Copy down 802.11 header and add the IV, KeyID, and ExtIV.
	 */
	M_PREPEND(m, ccmp.ic_header, M_NOWAIT);
	if (m == NULL)
		return 0;
	ivp = mtod(m, uint8_t *);
	memmove(ivp, ivp + ccmp.ic_header, hdrlen);
	ivp += hdrlen;

	ccmp_setiv(k, ivp);

	/*
	 * Finally, do software encrypt if needed.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWENCRYPT) &&
	    !ccmp_encrypt(k, m, hdrlen))
		return 0;

	return 1;
}

/*
 * Add MIC to the frame as needed.
 */
static int
ccmp_enmic(struct ieee80211_key *k, struct mbuf *m, int force)
{

	return 1;
}

static __inline uint64_t
READ_6(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3, uint8_t b4, uint8_t b5)
{
	uint32_t iv32 = (b0 << 0) | (b1 << 8) | (b2 << 16) | (b3 << 24);
	uint16_t iv16 = (b4 << 0) | (b5 << 8);
	return (((uint64_t)iv16) << 32) | iv32;
}

/*
 * Validate and strip privacy headers (and trailer) for a
 * received frame. The specified key should be correct but
 * is also verified.
 */
static int
ccmp_decap(struct ieee80211_key *k, struct mbuf *m, int hdrlen)
{
	const struct ieee80211_rx_stats *rxs;
	struct ccmp_ctx *ctx = k->wk_private;
	struct ieee80211vap *vap = ctx->cc_vap;
	struct ieee80211_frame *wh;
	uint8_t *ivp, tid = 0;
	uint64_t pn = 0;

	rxs = ieee80211_get_rx_params_ptr(m);

	if ((rxs != NULL) && (rxs->c_pktflags & IEEE80211_RX_F_IV_STRIP))
		goto finish;

	/*
	 * Header should have extended IV and sequence number;
	 * verify the former and validate the latter.
	 */
	wh = mtod(m, struct ieee80211_frame *);
	ivp = mtod(m, uint8_t *) + hdrlen;
	if ((ivp[IEEE80211_WEP_IVLEN] & IEEE80211_WEP_EXTIV) == 0) {
		/*
		 * No extended IV; discard frame.
		 */
		IEEE80211_NOTE_MAC(vap, IEEE80211_MSG_CRYPTO, wh->i_addr2,
			"%s", "missing ExtIV for AES-CCM cipher");
		vap->iv_stats.is_rx_ccmpformat++;
		return 0;
	}
	tid = ieee80211_gettid(wh);
	pn = READ_6(ivp[0], ivp[1], ivp[4], ivp[5], ivp[6], ivp[7]);
	if (pn <= k->wk_keyrsc[tid] &&
	    (k->wk_flags & IEEE80211_KEY_NOREPLAY) == 0) {
		/*
		 * Replay violation.
		 */
		ieee80211_notify_replay_failure(vap, wh, k, pn, tid);
		vap->iv_stats.is_rx_ccmpreplay++;
		return 0;
	}

	/*
	 * Check if the device handled the decrypt in hardware.
	 * If so we just strip the header; otherwise we need to
	 * handle the decrypt in software.  Note that for the
	 * latter we leave the header in place for use in the
	 * decryption work.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWDECRYPT) &&
	    !ccmp_decrypt(k, pn, m, hdrlen))
		return 0;

finish:
	/*
	 * Copy up 802.11 header and strip crypto bits.
	 */
	if (! ((rxs != NULL) && (rxs->c_pktflags & IEEE80211_RX_F_IV_STRIP))) {
		memmove(mtod(m, uint8_t *) + ccmp.ic_header, mtod(m, uint8_t *),
		    hdrlen);
		m_adj(m, ccmp.ic_header);
	}

	/*
	 * XXX TODO: see if MMIC_STRIP also covers CCMP MIC trailer.
	 */
	if (! ((rxs != NULL) && (rxs->c_pktflags & IEEE80211_RX_F_MMIC_STRIP)))
		m_adj(m, -ccmp.ic_trailer);

	/*
	 * Ok to update rsc now.
	 */
	if (! ((rxs != NULL) && (rxs->c_pktflags & IEEE80211_RX_F_IV_STRIP))) {
		k->wk_keyrsc[tid] = pn;
	}

	return 1;
}

/*
 * Verify and strip MIC from the frame.
 */
static int
ccmp_demic(struct ieee80211_key *k, struct mbuf *m, int force)
{
	return 1;
}

/*
 * Host AP crypt: host-based CCMP encryption implementation for Host AP driver
 *
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See README and COPYING for
 * more details.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 */

static void
ccmp_init_blocks(struct aesenc *ctx, struct ieee80211_frame *wh,
    u_int64_t pn, size_t data_len, struct aes_ccm *aes_ccm)
{
	uint8_t nonce[13];
	uint8_t ad[32];
	uint8_t qos;
	size_t adlen;

#define	IS_4ADDRESS(wh) \
	((wh->i_fc[1] & IEEE80211_FC1_DIR_MASK) == IEEE80211_FC1_DIR_DSTODS)
#define	IS_QOS_DATA(wh)	IEEE80211_QOS_HAS_SEQ(wh)

	/* nonce[0] is qos, determined later */
	IEEE80211_ADDR_COPY(nonce + 1, wh->i_addr2);
	nonce[7] = pn >> 40;
	nonce[8] = pn >> 32;
	nonce[9] = pn >> 24;
	nonce[10] = pn >> 16;
	nonce[11] = pn >> 8;
	nonce[12] = pn >> 0;

	ad[0] = wh->i_fc[0] & 0x8f;	/* XXX magic #s */
	ad[1] = wh->i_fc[1] & 0xc7;	/* XXX magic #s */
	/* NB: we know 3 addresses are contiguous */
	memcpy(ad + 2, wh->i_addr1, 3 * IEEE80211_ADDR_LEN);
	ad[20] = wh->i_seq[0] & IEEE80211_SEQ_FRAG_MASK;
	ad[21] = 0; /* all bits masked */

	/*
	 * Construct variable-length portion of AAD based
	 * on whether this is a 4-address frame/QOS frame.
	 *
	 * We also fill in the priority bits of the CCM
	 * initial block as we know whether or not we have
	 * a QOS frame.
	 */
	if (IEEE80211_IS_DSTODS(wh)) {
		IEEE80211_ADDR_COPY(ad + 24,
			((struct ieee80211_frame_addr4 *)wh)->i_addr4);
		if (IS_QOS_DATA(wh)) {
			const struct ieee80211_qosframe_addr4 *qwh4 =
			    (const struct ieee80211_qosframe_addr4 *)wh;
			qos = qwh4->i_qos[0] & 0x0f; /* just priority bits */
			ad[28] = qos;
			ad[29] = 0;
			adlen = 22 + IEEE80211_ADDR_LEN + 2;
		} else {
			qos = 0;
			adlen = 22 + IEEE80211_ADDR_LEN;
		}
	} else {
		if (IS_QOS_DATA(wh)) {
			const struct ieee80211_qosframe *qwh =
			    (const struct ieee80211_qosframe *)wh;
			qos = qwh->i_qos[0] & 0x0f; /* just priority bits */
			ad[22] = qos;
			ad[23] = 0;
			adlen = 22 + 2;
		} else {
			qos = 0;
			adlen = 22;
		}
	}
	nonce[0] = qos;

	aes_ccm_init(aes_ccm, AES_128_NROUNDS, ctx, 2 /* L, counter octets */,
	    IEEE80211_WEP_MICLEN, nonce, sizeof nonce, ad, adlen, data_len);

#undef	IS_QOS_DATA
#undef	IS_4ADDRESS
}

static int
ccmp_encrypt(struct ieee80211_key *key, struct mbuf *m, int hdrlen)
{
	struct ccmp_ctx *ctx = key->wk_private;
	struct ieee80211_frame *wh;
	struct aes_ccm aes_ccm;
	size_t data_len;
	uint8_t mic[IEEE80211_WEP_MICLEN];

	KASSERT(hdrlen >= 0);
	KASSERT(hdrlen < m->m_pkthdr.len);
	KASSERT(ccmp.ic_header <= m->m_pkthdr.len - hdrlen);

	ctx->cc_vap->iv_stats.is_crypto_ccmp++;

	wh = mtod(m, struct ieee80211_frame *);
	data_len = m->m_pkthdr.len - (hdrlen + ccmp.ic_header);
	ccmp_init_blocks(&ctx->cc_aes, wh, key->wk_keytsc, data_len, &aes_ccm);
	aes_ccm_enc_mbuf(&aes_ccm, m, hdrlen + ccmp.ic_header, data_len, mic);

	return m_append(m, ccmp.ic_trailer, mic);
}

static int
ccmp_decrypt(struct ieee80211_key *key, u_int64_t pn, struct mbuf *m, int hdrlen)
{
	struct ccmp_ctx *ctx = key->wk_private;
	struct ieee80211vap *vap = ctx->cc_vap;
	struct ieee80211_frame *wh;
	struct aes_ccm aes_ccm;
	size_t data_len;
	uint8_t mic[IEEE80211_WEP_MICLEN];

	KASSERT(hdrlen >= 0);
	KASSERT(hdrlen < m->m_pkthdr.len);
	KASSERT(ccmp.ic_header < m->m_pkthdr.len - hdrlen);
	KASSERT(ccmp.ic_trailer < m->m_pkthdr.len - (hdrlen + ccmp.ic_header));

	vap->iv_stats.is_crypto_ccmp++;

	wh = mtod(m, struct ieee80211_frame *);
	data_len = m->m_pkthdr.len - (hdrlen + ccmp.ic_header + ccmp.ic_trailer);
	ccmp_init_blocks(&ctx->cc_aes, wh, pn, data_len, &aes_ccm);
	m_copydata(m, m->m_pkthdr.len - ccmp.ic_trailer, ccmp.ic_trailer, mic);

	if (!aes_ccm_dec_mbuf(&aes_ccm, m, hdrlen + ccmp.ic_header, data_len,
		mic)) {
		IEEE80211_DPRINTF(vap, IEEE80211_MSG_CRYPTO,
		    "[%s] AES-CCM decrypt failed; MIC mismatch\n",
		    ether_sprintf(wh->i_addr2));
		vap->iv_stats.is_rx_ccmpmic++;
		return 0;
	}
	return 1;
}

/*
 * Module glue.
 */
IEEE80211_CRYPTO_MODULE(ccmp, 1);
