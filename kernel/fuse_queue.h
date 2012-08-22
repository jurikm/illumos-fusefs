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
#ifndef	_FUSE_QUEUE_H
#define	_FUSE_QUEUE_H
#include <sys/int_types.h>
#include <sys/cred.h>
#include "fuse.h"

#ifdef	__cplusplus
extern "C" {
#endif


#define	FUSE_SESSION_MUTEX_LOCK(se)	mutex_enter(&((se)->session_mutx))
#define	FUSE_SESSION_MUTEX_UNLOCK(se)	mutex_exit(&((se)->session_mutx))

#define	FUSE_MSG_MUTEX_LOCK(x)	mutex_enter(& x->fmn_mutx)
#define	FUSE_MSG_MUTEX_UNLOCK(x)	mutex_exit(& x->fmn_mutx)

/*
 * TODO: create an array of session each array element representing a minor
 * device
 */

/* session is a connection between a mount point and a minor device */
typedef struct fuse_session
{
	kmutex_t	session_mutx;
	ksema_t		session_sema; /* devops read sleeps over it */
	list_t		msg_list;  /* message awaiting service rests here */
	avl_tree_t	avl_cache; /* nodeid used to track associated vnode */
	minor_t		minor; /* Minor number associated with this session */
	uint32_t	state;
	uint64_t	unique; /* msg id used between lib and kernel module */
	uint64_t	max_unique;
	cred_t		*usercred;  /* Credentials passed by fuse library */
	uint32_t	max_write;  /* Max Write value set by fuse lib */
	vfs_t		*vfs;
	uint32_t	mounted:1;
} fuse_session_t;


#define	FUSE_MAX_SESSIONS 1024

fuse_session_t *fuse_minor_get_session(minor_t ndx);
minor_t fuse_session_get_minor(fuse_session_t *se);

fuse_session_t *fuse_alloc_session();
void fuse_free_session(fuse_session_t *se);

void fuse_init_session(fuse_session_t *se);
void fuse_deinit_session(fuse_session_t *se);

void fuse_session_set_cred(fuse_session_t *se, cred_t *cr);
void fuse_session_set_vfs(fuse_session_t *se, vfs_t *vfs);

void fuse_session_umount(fuse_session_t *se);

typedef struct fuse_avl_cache_node {
	uint64_t facn_nodeid;
	uint64_t par_nodeid;
	vnode_t	*facn_vnode_p;
	char *name;
	unsigned short namelen;
	avl_node_t facn_cache_node;
} fuse_avl_cache_node_t;

#define	FUSE_MAX_MSG 8192

typedef struct fuse_req_data {
	char		frd_buf[FUSE_MAX_MSG];
	uint32_t	frd_cur_offset;
} fuse_req_data_t;

#define	FUSE_MSG_STATE_INIT  0
#define	FUSE_MSG_STATE_QUEUE 2
#define	FUSE_MSG_STATE_READ  3
#define	FUSE_MSG_STATE_WRITE  4
#define	FUSE_MSG_STATE_SIG  5
#define	FUSE_MSG_STATE_DONE  6

typedef struct fuse_msg_node fuse_msg_node_t;

struct fuse_msg_node
{
	list_node_t	fmn_link;
	ksema_t		fmn_sema;
	kcondvar_t	fmn_cv;
	kmutex_t	fmn_mutx;
	int		fmn_state;
	int		fmn_noreply; /* no reply expected */
	uint64_t	fmn_unique;  /* identifies a unique message */
	/* Message interchange struct between FUSE Kernel and FUSE lib. */
	fuse_req_data_t	fmn_req;
	void (*frd_on_request_complete)(fuse_session_t *ses_p,
	    fuse_msg_node_t *msg_p);
	struct fuse_data_in ipdata;  /* Data passed to the fuse lib */
	struct fuse_data_out opdata; /* Data received back from the fuse lib */
};

void fuse_queue_request_nowait(fuse_session_t *se, fuse_msg_node_t *req);
int  fuse_queue_request_wait(fuse_session_t *se, fuse_msg_node_t *req_p);

fuse_msg_node_t *fuse_alloc_msg();
void fuse_free_msg(fuse_msg_node_t *msgp);

uint64_t fuse_bake_cookie();

void fuse_avl_cache_node_destroy(fuse_avl_cache_node_t *node);
fuse_avl_cache_node_t *fuse_avl_cache_node_create(vnode_t *np, uint64_t inode,
    uint64_t par_nodeid, unsigned short namelen, char *name);
fuse_msg_node_t *fuse_setup_message(size_t argsize, enum fuse_opcode op,
    uint64_t nodeid, cred_t *credp, uint64_t unique);
void fuse_destroy_cache(fuse_session_t *sep);

#ifdef	__cplusplus
}
#endif
#endif /* _FUSE_QUEUE_H */
