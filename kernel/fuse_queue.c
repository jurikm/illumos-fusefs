/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mutex.h>
#include <sys/semaphore.h>
#include <sys/list.h>
#include <sys/uio.h>
#include <sys/avl.h>
#include <sys/vnode.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/ksynch.h>
#include <sys/cred.h>
#include <sys/sdt.h>

#include "fuse_queue.h"

static int
fuse_avl_compare(const void *x1, const void *x2);
static void fuse_avl_destroy(avl_tree_t *tree_p);

static fuse_session_t *fuse_sessions[FUSE_MAX_SESSIONS];

static kmutex_t fuse_global_mutx;

void
fuse_global_init()
{
	(void) mutex_init(&fuse_global_mutx, NULL, MUTEX_DEFAULT,
	    (void *) NULL);
}
void
fuse_global_fini()
{
	mutex_destroy(&fuse_global_mutx);
}
static void
fuse_global_mutex_enter()
{
	(void) mutex_enter(&fuse_global_mutx);
}
static void
fuse_global_mutex_exit()
{
	(void) mutex_exit(&fuse_global_mutx);
}

/* ARGSUSED */
static void
frd_on_request_complete_wakeup(fuse_session_t *ses_p, fuse_msg_node_t *msg_p)
{
	FUSE_SESSION_MUTEX_LOCK(ses_p);
	msg_p->fmn_state = FUSE_MSG_STATE_DONE;
	cv_signal(&msg_p->fmn_cv);
	FUSE_SESSION_MUTEX_UNLOCK(ses_p);
}

fuse_session_t *
fuse_minor_get_session(minor_t ndx)
{
	return (ndx < FUSE_MAX_SESSIONS ?  fuse_sessions[ndx] : NULL);
}

minor_t
fuse_session_get_minor(fuse_session_t *se)
{
	return (se->minor);
}

void
fuse_session_set_cred(fuse_session_t *se, cred_t *cr)
{
	crhold(cr);
	se->usercred = cr;
}

static void
fuse_session_clear_cred(fuse_session_t *se)
{
	if (se->usercred != NULL)
		crfree(se->usercred);
	se->usercred = NULL;

}

void
fuse_session_set_vfs(fuse_session_t *se, vfs_t *vfs)
{
	se->vfs = vfs;
}

/* double a global lock before calling it */
void
fuse_init_session(fuse_session_t *se)
{
	(void) mutex_init(&se->session_mutx, NULL, MUTEX_DEFAULT, NULL);
	(void) sema_init(&se->session_sema, 0, NULL, SEMA_DRIVER, NULL);
	list_create(&se->msg_list, sizeof (fuse_msg_node_t),
	    offsetof(fuse_msg_node_t, fmn_link));
	avl_create(&se->avl_cache, fuse_avl_compare,
	    sizeof (fuse_avl_cache_node_t),
	    offsetof(struct fuse_avl_cache_node, facn_cache_node));
	se->mounted = 0;
}

void
fuse_deinit_session(fuse_session_t *se)
{
	sema_destroy(&se->session_sema);
	mutex_destroy(&se->session_mutx);
	list_destroy(&se->msg_list);
	fuse_avl_destroy(&se->avl_cache);
	fuse_session_clear_cred(se);
}

void
fuse_free_session(fuse_session_t *se)
{
	fuse_sessions[fuse_session_get_minor(se)] = NULL;
	kmem_free(se, sizeof (fuse_session_t));
}

fuse_session_t *
fuse_alloc_session()
{
	int i;
	fuse_global_mutex_enter();

	for (i = 0; i < FUSE_MAX_SESSIONS; i++) {
		if (fuse_sessions[i] == NULL) {
			break;
		}
	}

	if (i == FUSE_MAX_SESSIONS) {
		fuse_global_mutex_exit();
		return (NULL);
	} else {
		fuse_sessions[i] = kmem_zalloc(sizeof (fuse_session_t),
		    KM_SLEEP);
		fuse_sessions[i]->minor = i;

		fuse_global_mutex_exit();
		return (fuse_sessions[i]);
	}
}

static void
fuse_init_msg(fuse_msg_node_t *msg_p)
{
	bzero(msg_p, sizeof (fuse_msg_node_t));
	sema_init(&msg_p->fmn_sema, 0, NULL, SEMA_DRIVER, (void *) NULL);
	cv_init(&msg_p->fmn_cv, NULL, CV_DEFAULT, NULL);
}
static void
fuse_deinit_msg(fuse_msg_node_t *msg_p)
{
	sema_destroy(&msg_p->fmn_sema);
	cv_destroy(&msg_p->fmn_cv);
}

fuse_msg_node_t *
fuse_alloc_msg()
{
	fuse_msg_node_t *msg_p = kmem_alloc(sizeof (fuse_msg_node_t), KM_SLEEP);
	fuse_init_msg(msg_p);
	return (msg_p);
}

void
fuse_free_msg(fuse_msg_node_t *msg_p)
{
	int i;
	fuse_deinit_msg(msg_p);
	/*
	 * Check and free if the buffer was allocated for exchange between fuse
	 * library and kernel module
	 */
	for (i = 0; i < msg_p->ipdata.iovs_used; i++) {
		if (msg_p->ipdata.iovbuf[i].memsize &&
		    msg_p->ipdata.iovbuf[i].memflag == MEM_TYPE_KMEM) {
			kmem_free(msg_p->ipdata.iovbuf[i].base,
			    msg_p->ipdata.iovbuf[i].memsize);
		}
	}

	/* Check if memory was allocated to receive fuse library response */
	if (msg_p->opdata.fouth)
		kmem_free(msg_p->opdata.fouth, sizeof (*(msg_p->opdata.fouth)));

	if (msg_p->opdata.iovbuf.memsize &&
	    msg_p->opdata.iovbuf.memflag == MEM_TYPE_KMEM)
		kmem_free(msg_p->opdata.iovbuf.base,
		    msg_p->opdata.iovbuf.memsize);

	kmem_free(msg_p, sizeof (fuse_msg_node_t));
}

void
fuse_queue_request_nowait(fuse_session_t *se, fuse_msg_node_t *req_p)
{
	FUSE_SESSION_MUTEX_LOCK(se);
	req_p->fmn_state = FUSE_MSG_STATE_QUEUE;
	/* the device write call removes the message from the queue */
	list_insert_tail(&(se->msg_list), req_p);
	FUSE_SESSION_MUTEX_UNLOCK(se);
	/* wake up the reader @ device */
	sema_v(&(se->session_sema));
}

int
fuse_queue_request_wait(fuse_session_t *se, fuse_msg_node_t *req_p)
{
	int err = 0;
	int interrupted = 0;

	req_p->frd_on_request_complete = frd_on_request_complete_wakeup;
	fuse_queue_request_nowait(se, req_p);

	FUSE_SESSION_MUTEX_LOCK(se);

	while (req_p->fmn_state != FUSE_MSG_STATE_DONE) {
		if (cv_wait_sig(&req_p->fmn_cv, &se->session_mutx) != 0) {
			continue;
		} else {
			interrupted = 1;
			break;
		}
	}
	if (interrupted == 0) {
		req_p->opdata.outdata = req_p->opdata.iovbuf.base;
		FUSE_SESSION_MUTEX_UNLOCK(se);
		return (err);
	}

	DTRACE_PROBE3(fuse_queue_request_wait_err_no_response,
	    char *, "no response from daemon",
	    fuse_session_t *, se, fuse_msg_node_t *, req_p);

	if (req_p->fmn_state == FUSE_MSG_STATE_DONE) {
		goto err;
	}
	if (req_p->fmn_state != FUSE_MSG_STATE_QUEUE)
		req_p->fmn_state = FUSE_MSG_STATE_SIG;

	while (req_p->fmn_state != FUSE_MSG_STATE_DONE)
		cv_wait(&req_p->fmn_cv, &se->session_mutx);
err:
	req_p->opdata.outdata = NULL;
	err = EINTR;
	FUSE_SESSION_MUTEX_UNLOCK(se);

	return (err);
}
/*
 *  Avl related
 */
static void
fuse_avl_destroy(avl_tree_t *tree_p)
{
	void *cookie = NULL;
	fuse_avl_cache_node_t *node;
	while ((node = avl_destroy_nodes(tree_p, &cookie)) != NULL) {
		fuse_avl_cache_node_destroy(node);
	}
	avl_destroy(tree_p);
}

fuse_avl_cache_node_t *
fuse_avl_cache_node_create(vnode_t *np, uint64_t nodeid, uint64_t par_nodeid,
    unsigned short namelen, char *name)
{
	fuse_avl_cache_node_t *nod = kmem_zalloc(
	    sizeof (fuse_avl_cache_node_t), KM_SLEEP);
	nod->facn_vnode_p = np;
	nod->facn_nodeid = nodeid;
	nod->par_nodeid = par_nodeid;

	if (namelen) {
		nod->namelen = namelen;
		nod->name = kmem_alloc(namelen, KM_SLEEP);
		(void) strlcpy(nod->name, name, namelen);
	}
	return (nod);
}

void
fuse_avl_cache_node_destroy(fuse_avl_cache_node_t *node)
{
	if (node->namelen)
		kmem_free(node->name, node->namelen);
	kmem_free(node, sizeof (fuse_avl_cache_node_t));
}

static int
fuse_avl_compare(const void *x1, const void *x2)
{
	fuse_avl_cache_node_t *new = (fuse_avl_cache_node_t *)x1;
	fuse_avl_cache_node_t *old = (fuse_avl_cache_node_t *)x2;

	/*
	 * We first check if valid nodeid is passed, if not we try to
	 * validate with the remaining fields of a node
	 */
	if (new->facn_nodeid == FUSE_NULL_ID) {
		if (new->namelen == old->namelen &&
		    new->par_nodeid == old->par_nodeid) {
			/* Compare the names for a match */
			if (!(strncmp(new->name, old->name, new->namelen)))
				return (0);
		}
	} else {
		return ((new->facn_nodeid == old->facn_nodeid) ? 0 :
		    ((new->facn_nodeid < old->facn_nodeid) ? -1 : 1));
	}
	return (-1);
}


void
fuse_session_umount(fuse_session_t *sep)
{
	if (sep->vfs) {
		if (vn_vfswlock(sep->vfs->vfs_vnodecovered) == 0) {
			VFS_RELE(sep->vfs);
			(void) dounmount(sep->vfs, 0, sep->usercred);
		} else {
			VFS_RELE(sep->vfs);
		}
	}
}
