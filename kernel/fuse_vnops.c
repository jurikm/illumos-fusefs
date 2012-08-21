/*
 * Copyright (C) 2005 Csaba Henk. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file has been derived from OpenSolaris devfs and others in uts/common/fs
 */
#include <sys/vnode.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/list.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/fcntl.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/dirent.h>
#include <sys/mode.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/fs_subr.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/buf.h>
#include <sys/note.h>
#include <sys/ksynch.h>
#include <sys/inttypes.h>
#include <sys/sdt.h>
#include <sys/vmsystm.h>

#include <vm/pvn.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kpm.h>

#include "fuse_queue.h"
#include "fuse.h"

/* Vnode operations */
static int fuse_open(struct vnode **vpp, int flag, struct cred *cred,
    caller_context_t *ct);
static int fuse_close(struct vnode *vp, int flag, int count,
    offset_t offset, struct cred *cred, caller_context_t *ct);
static int fuse_read(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *cred, struct caller_context *ct);
static int fuse_write(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *cred, struct caller_context *ct);
static int fuse_getattr(struct vnode *vp, struct vattr *vap, int flags,
    struct cred *cr, caller_context_t *ct);
static int fuse_setattr(struct vnode *vp, struct vattr *vap,
    int flags, struct cred *cr, caller_context_t *ct);
static int fuse_access(struct vnode *vp, int mode, int flags,
    struct cred *cr, caller_context_t *ct);
static int fuse_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *cred,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp);
static int fuse_create(struct vnode *dvp, char *nm, struct vattr *vap,
    vcexcl_t excl, int mode, struct vnode **vpp, struct cred *cred,
    int flag, caller_context_t *ct, vsecattr_t *vsecp);
static int fuse_readdir(struct vnode *dvp, struct uio *uiop,
    struct cred *cred, int *eofp, caller_context_t *ct, int flags);
static int fuse_fsync(struct vnode *vp, int syncflag, struct cred *cred,
    caller_context_t *ct);
static void fuse_inactive(struct vnode *vp, struct cred *cred,
    caller_context_t *ct);
static int fuse_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct);
static int fuse_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap,
    vnode_t **vpp, cred_t *cr, caller_context_t *ct, int flags,
    vsecattr_t *vsecp);
static int fuse_rmdir(vnode_t *dvp, char *name, vnode_t *cwd, cred_t *cr,
    caller_context_t *ct, int flags);
static int fuse_link(struct vnode *dvp, struct vnode *srcvp, char *tnm,
    struct cred *cred, caller_context_t *ct, int flags);
static int fuse_rename(vnode_t *sdvp, char *snm, vnode_t *tdvp, char *tnm,
    cred_t *cr, caller_context_t *ct, int flags);
static int fuse_remove(vnode_t *dvp, char *name, cred_t *cr,
    caller_context_t *ct, int flags);
static int fuse_symlink(vnode_t *dvp, char *name, vattr_t *vap, char *link,
    cred_t *cr, caller_context_t *ct, int flags);
static int fuse_readlink(vnode_t *vp, uio_t *uio, cred_t *cr,
    caller_context_t *ct);
static int fuse_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t off, cred_t *cr, caller_context_t *ct);
static int fuse_getpage(struct vnode *vp, offset_t off, size_t len,
    uint_t *protp, page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *credp, caller_context_t *ct);
static int fuse_putpage(struct vnode *vp, offset_t off, size_t len, int flags,
	struct cred *credp, caller_context_t *ct);
static int fuse_map(vnode_t *, offset_t, struct as *, caddr_t *, size_t,
    uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int fuse_addmap(vnode_t *, offset_t, struct as *, caddr_t,  size_t,
    uchar_t, uchar_t, uint_t, cred_t *, caller_context_t *);
static int fuse_delmap(vnode_t *, offset_t, struct as *, caddr_t,  size_t,
    uint_t, uint_t, uint_t, cred_t *, caller_context_t *);

/* Other supporting routines */
static int rdfuse(struct vnode *vp, struct uio *uiop, struct cred *credp);
static int fuse_send_release(fuse_session_t *sep, struct fuse_file_handle *fh,
    enum fuse_opcode op, struct vnode *vp, int flags);
static void fuse_vnode_cache_remove(struct vnode *vp, fuse_session_t *sep);
static void fuse_vnode_cleanup(struct vnode *vp, struct cred *credp,
    fuse_session_t *sep);
static void
fuse_vnode_destroy(struct vnode *vp, struct cred *credp, fuse_session_t *sep);
static void fuse_set_getattr(struct vnode *vp, struct vattr *vap,
    struct fuse_attr *attr);
static int
fuse_add_entry(struct vnode **vpp, struct vnode *dvp, fuse_msg_node_t *msgp,
    fuse_session_t *sep, char *name, int namelen, cred_t *credp, vtype_t vtype);
static void
    fuse_send_forget(uint64_t nodeid, fuse_session_t *sep, uint64_t nlookup);
static int
fuse_getvnode(uint64_t nodeid, struct vnode **vpp, v_getmode vmode,
    uint32_t mode, fuse_session_t *sep, vfs_t *vfsp, int namelen,
    char *name, uint64_t parent_nid, struct cred *credp);
static int
fuse_lookup_i(struct vnode *dvp, char *nm, struct vnode **vpp, cred_t *credp);
static int
fuse_getfilesize(struct vnode *vp, u_offset_t *fsize, struct cred *credp);
static inline void
fsize_change_notify(struct vnode *vp, size_t fsize, int flag);
static int
fuse_access_i(void *vp, int mode, struct cred *credp);
static int
fuse_access_inkernelcheck(void *vvp, int mode, struct cred *credp);
static int
fuse_fsync_fh(struct fuse_file_handle *fhp, struct fuse_fh_param *param);
static void
fuse_page_mapin(struct vnode *vp, struct buf **bp, struct page *pp, size_t len,
    int flag, struct fuse_iov *iovp);
static inline void fuse_vnode_free(struct vnode *vp, fuse_session_t *sep);

const fs_operation_def_t fuse_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = fuse_open },
	VOPNAME_CLOSE,		{ .vop_close = fuse_close },
	VOPNAME_READ,		{ .vop_read = fuse_read },
	VOPNAME_WRITE,		{ .vop_write = fuse_write },
	VOPNAME_GETATTR,	{ .vop_getattr = fuse_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = fuse_setattr },
	VOPNAME_ACCESS,		{ .vop_access = fuse_access },
	VOPNAME_LOOKUP,		{ .vop_lookup = fuse_lookup },
	VOPNAME_LINK,		{ .vop_link = fuse_link },
	VOPNAME_CREATE,		{ .vop_create = fuse_create },
	VOPNAME_READDIR,	{ .vop_readdir = fuse_readdir },
	VOPNAME_FSYNC,		{ .vop_fsync = fuse_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = fuse_inactive },
	VOPNAME_DISPOSE,	{ .vop_dispose = fs_dispose },
	VOPNAME_MKDIR,		{ .vop_mkdir = fuse_mkdir },
	VOPNAME_RMDIR,		{ .vop_rmdir = fuse_rmdir },
	VOPNAME_RENAME,		{ .vop_rename = fuse_rename },
	VOPNAME_REMOVE,		{ .vop_remove = fuse_remove },
	VOPNAME_SYMLINK,	{ .vop_symlink = fuse_symlink },
	VOPNAME_READLINK,	{ .vop_readlink = fuse_readlink },
	VOPNAME_SPACE,		{ .vop_space = fuse_space },
	VOPNAME_GETPAGE,	{ .vop_getpage = fuse_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = fuse_putpage },
	VOPNAME_SEEK,		{ .vop_seek = fuse_seek },
	VOPNAME_MAP,		{ .vop_map = fuse_map },
	VOPNAME_ADDMAP,		{ .vop_addmap = fuse_addmap },
	VOPNAME_DELMAP,		{ .vop_delmap = fuse_delmap },
	NULL, NULL
};


const fs_operation_def_t temp_vnodeops_template[] = {
	VOPNAME_OPEN, fuse_open,
	NULL, 		NULL
};

#define	cache_attrs(vp, fuse_out) do {					\
	timestruc_t ts;							\
									\
	VTOFD(vp)->cached_attrs_bound.tv_sec = (fuse_out)->attr_valid;	\
	VTOFD(vp)->cached_attrs_bound.tv_nsec = (fuse_out)->attr_valid_nsec; \
	gethrestime(&ts);						\
	timespecadd(&VTOFD(vp)->cached_attrs_bound, &ts);		\
	fuse_set_getattr(vp, &(VTOFD(vp)->cached_attrs), &(fuse_out)->attr); \
_NOTE(CONSTCOND) } while (0)

#define	ATTR_CACHE_VALID(curtime, attrtime)				\
	(curtime.tv_sec == attrtime.tv_sec) ?				\
	    (curtime.tv_nsec <= attrtime.tv_nsec) :			\
	    (curtime.tv_sec <= attrtime.tv_sec)

#define	invalidate_cached_attrs(vp)					\
	if (VTOFD(vp))							\
	    bzero(&(VTOFD(vp)->cached_attrs_bound), sizeof (timestruc_t));

/* Function which allocates the requested amount of size for message passing */
void
fuse_buf_alloc(struct fuse_iov *iov, size_t len)
{
	iov->base = kmem_zalloc(FUSE_BUF_ADJUST_SIZE(len), KM_SLEEP);
	iov->len = len;
	iov->memsize = FUSE_BUF_ADJUST_SIZE(len);
	iov->memflag = MEM_TYPE_KMEM;
}

/* Function which initializes the message header structure used by fuse lib */
static void
fuse_setup_inheader(struct fuse_in_header *finh, size_t arglen, int op,
    uint64_t unique, uint64_t nodeid, cred_t *cred)
{
	finh->len	= sizeof (struct fuse_in_header) + arglen;
	finh->opcode	= op;
	finh->unique	= unique;
	finh->nodeid	= nodeid;
	finh->uid	= crgetuid(cred);
	finh->gid	= crgetgid(cred);
	finh->pid	= ddi_get_pid();
}

/* Function which creates a message with ony header and no arguments */
static void
setup_msg_onlyheader(fuse_msg_node_t *msgp, enum fuse_opcode op,
    uint64_t unique, uint64_t nodeid, struct cred *credp)
{
	msgp->fmn_unique = unique;
	msgp->ipdata.iovs_used = 1;
	fuse_buf_alloc(&(msgp->ipdata.iovbuf[0]),
	    (sizeof (struct fuse_in_header)));
	msgp->ipdata.finh = msgp->ipdata.iovbuf[0].base;

	fuse_setup_inheader(msgp->ipdata.finh, 0, op, unique, nodeid, credp);
}

/* Function assigns various parameters to a message node */
static void
fuse_setup_msgparams(fuse_msg_node_t *msgp, size_t argsize,
    enum fuse_opcode op, uint64_t nodeid, cred_t *credp, uint64_t unique)
{
	msgp->ipdata.finh	= msgp->ipdata.iovbuf[0].base;
	msgp->ipdata.indata	= ((char *)msgp->ipdata.iovbuf[0].base +
	    sizeof (struct fuse_in_header));
	msgp->fmn_unique	= unique;

	fuse_setup_inheader(msgp->ipdata.finh, argsize, op,
	    msgp->fmn_unique, nodeid, credp);
	msgp->ipdata.iosize = argsize;
}

static void
fuse_msg_refresh(fuse_msg_node_t *msgp, size_t size, int forcefree)
{
	if (msgp->ipdata.iovbuf[0].memsize == size ||
	    (msgp->ipdata.iovbuf[0].memsize > size && !forcefree))
		return;
	else {
		kmem_free(msgp->ipdata.iovbuf[0].base,
		    msgp->ipdata.iovbuf[0].memsize);
		fuse_buf_alloc(&msgp->ipdata.iovbuf[0], size);
	}
}

/* Frees the memory allocated for data passed from the daemon */
static void
fuse_free_opdata(fuse_msg_node_t *msgp)
{
	if (msgp->opdata.iovbuf.base &&
	    msgp->opdata.iovbuf.memflag == MEM_TYPE_KMEM) {
		kmem_free(msgp->opdata.iovbuf.base,
		    msgp->opdata.iovbuf.memsize);
		if (msgp->opdata.fouth) {
			kmem_free(msgp->opdata.fouth,
			    sizeof (*(msgp->opdata.fouth)));
		}
		bzero(&(msgp->opdata), sizeof (msgp->opdata));
	}
}

/* Function which refreshes a previously used message with new values */
static void
fuse_msg_recreate(fuse_msg_node_t *msgp, size_t argsize, enum fuse_opcode op,
    uint64_t nodeid, cred_t *credp, uint64_t unique, int forcefree)
{
	/* Free the buffer used to receive data from fuse lib */
	fuse_free_opdata(msgp);

	fuse_msg_refresh(msgp, argsize, forcefree);

	fuse_setup_msgparams(msgp, argsize, op, nodeid, credp, unique);
}

/* Function which creates a message with header and arguments */
fuse_msg_node_t *
fuse_setup_message(size_t argsize, enum fuse_opcode op,
    uint64_t nodeid, cred_t *credp, uint64_t unique)
{
	fuse_msg_node_t *msgp = fuse_alloc_msg();

	msgp->ipdata.iovs_used = 1;
	fuse_buf_alloc(&(msgp->ipdata.iovbuf[0]),
	    (sizeof (struct fuse_in_header) + argsize));
	fuse_setup_msgparams(msgp, argsize, op, nodeid, credp, unique);

	return (msgp);
}

/* This function is used from FreeBSD Fuse */
static int
checkentry(struct fuse_entry_out *feo, enum vtype vtyp)
{
	if (vtyp != IFTOVT(feo->attr.mode) ||
	    feo->nodeid == FUSE_NULL_ID ||
	    feo->nodeid == FUSE_ROOT_ID) {
		DTRACE_PROBE2(checkentry_err_nodeid,
		    char *, "Invalid node entry, dropped",
		    struct fuse_entry_out *, feo);
		return (EINVAL);
	}

	return (0);
}

static void
release_create_data(struct fuse_create_data *fcd)
{
	if (fcd->name)
		kmem_free(fcd->name, fcd->namelen);
	kmem_free(fcd, sizeof (*fcd));
}

static int
create_filehandle(struct vnode *vp, int flag, cred_t *credp,
    fuse_msg_node_t **msgpp)
{
	struct fuse_vnode_data	*fvdata = VTOFD(vp);
	struct fuse_open_in	*foi;
	struct fuse_entry_out	*feo;
	struct fuse_mknod_in	*fmni;
	int			err = 0;
	fuse_msg_node_t		*msgp;
	fuse_session_t		*sep;
	fuse_avl_cache_node_t	*cache_nodep;
	int			sent_mknod = 0;
	fuse_avl_cache_node_t 	tofind, *foundp;
	avl_index_t		where;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(create_filehandle_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	msgp = fuse_setup_message((sizeof (*foi) + fvdata->fcd->namelen + 1),
	    FUSE_CREATE, fvdata->par_nid, credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	foi = (struct fuse_open_in *)msgp->ipdata.indata;

	foi->flags = F_TO_O_FLAGS(flag & ~O_NOCTTY);
	foi->mode = fvdata->fcd->mode;
	(void *) strlcpy(((char *)msgp->ipdata.indata + sizeof (*foi)),
	    fvdata->fcd->name, fvdata->fcd->namelen);

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	if (msgp->opdata.fouth->error == ENOSYS) {
		DTRACE_PROBE2(create_filehandle_info_enosys,
		    char *, "FUSE_CREATE not supported by filesys",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto sendmknod;
	}

	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(create_filehandle_err_create_req,
		    char *, "FUSE_CREATE request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}

	/* Obtained response from fuse library so interpret it */
	goto resp_intrprt;

sendmknod:
	sent_mknod = 1;
	/*
	 * Try avoiding freeing and allocating memory. Do it only if
	 * inevitable
	 */
	fuse_msg_recreate(msgp, (sizeof (*fmni) + fvdata->fcd->namelen + 1),
	    FUSE_MKNOD, fvdata->par_nid, fvdata->fcd->credp,
	    FUSE_GET_UNIQUE(sep), 0);

	/* Set up arguments to the fuse library */
	fmni = (struct fuse_mknod_in *)msgp->ipdata.indata;

	fmni->mode = fvdata->fcd->mode;
	fmni->rdev = 0;
	(void *) strlcpy((char *)msgp->ipdata.indata + sizeof (*foi),
	    fvdata->fcd->name, fvdata->fcd->namelen);

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(create_filehandle_err_mknod_req,
		    char *, "FUSE_MKNOD request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}

resp_intrprt:
	feo = (struct fuse_entry_out *)msgp->opdata.outdata;

	if ((err = checkentry(feo, VREG))) {
		goto cleanup;
	}

	/* Check if there will be a collision? */
	tofind.facn_nodeid = feo->nodeid;
	if ((foundp = avl_find(&(sep->avl_cache), &tofind,
	    &where)) != NULL) {
		DTRACE_PROBE2(create_filehandle_err_collision,
		    char *, "Node already in cache",
		    struct fuse_entry_out *, feo);
		/*
		 * We have the unhappy situation of forcing a purge on the
		 * existing vnode
		 */
		fuse_vnode_destroy(foundp->facn_vnode_p, credp, sep);
	}
	/* Add the vnode to the avl tree */
	cache_nodep = fuse_avl_cache_node_create(vp, feo->nodeid,
	    fvdata->fcd->par_nodeid, fvdata->fcd->namelen, fvdata->fcd->name);
	avl_add(&(sep->avl_cache), cache_nodep);

	release_create_data(fvdata->fcd);
	fvdata->fcd = NULL;
	bzero(&fvdata->fh, sizeof (fvdata->fh));

	/* Reinitialize vnode related fields */
	fvdata->nodeid = feo->nodeid;
	fvdata->nlookup++;
	vn_setops(vp, dv_vnodeops);
#ifndef DONT_CACHE_ATTRIBUTES
	cache_attrs(vp, feo);
#endif

	/*
	 * if we sent FUSE_CREATE request to library, then we don't need to
	 * do FUSE_OPEN, but if we got a response for FUSE_MKNOD, then we
	 * need to send FUSE_OPEN which is taken care by the caller of this
	 * function
	 */
	if (!sent_mknod)
		msgp->opdata.outdata = feo + 1;
	else
		msgp->opdata.outdata = NULL;

	*msgpp = msgp;
	return (err);
cleanup:
	if (fvdata->fcd)
		release_create_data(fvdata->fcd);
	fvdata->fcd = NULL;
	fuse_free_msg(msgp);
	*msgpp = NULL;
	return (err);
}

typedef int fuse_file_check_t(struct fuse_file_handle *fhp,
    struct fuse_fh_param *fh_param);

/* Function which releases a cached file handle */
static int
fuse_release_fh(struct fuse_file_handle *fhp, struct fuse_fh_param *param)
{
	struct vnode *vp = param->vp;
	fuse_vnode_data_t *fvdatap = VTOFD(vp);
	enum fuse_opcode op = (vp->v_type == VDIR) ?
	    FUSE_RELEASEDIR : FUSE_RELEASE;
	fuse_session_t *sep;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_release_fh_info_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
	}

	if ((param->flag & FUSE_FORCE_FH_RELEASE) || fhp->ref == 0) {
		DTRACE_PROBE2(fuse_release_fh_info,
		    char *, "file handle released.",
		    struct fuse_file_handle *, fhp);
		list_remove(&fvdatap->fh_list, fhp);
		if (sep != NULL) {
			(void) fuse_send_release(sep, fhp, op, vp, fhp->mode);
		}
		kmem_free(fhp, sizeof (*fhp));
	}
	/*
	 * This function is always called from iterate_filehandle, and if
	 * we return anything other than zero, iterate_filhandle will not scan
	 * the complete list, so we always return zero from this function.
	 */
	return (0);
}

/*
 * Function does a check if the filehandle passed as parameter is the one needed
 * by the current request
 */
static int
fuse_std_filecheck(struct fuse_file_handle *fhp, struct fuse_fh_param *param)
{
	if (((param->rw_mode & (FREAD | FWRITE | FAPPEND)) &
	    (fhp->mode & (FREAD | FWRITE | FAPPEND))) &&
	    crgetuid(param->credp) == crgetuid(fhp->credp) &&
	    crgetgid(param->credp) == crgetgid(fhp->credp) &&
	    curproc->p_pidp->pid_id == fhp->process_id) {
		fhp->ref++;
		DTRACE_PROBE2(fuse_std_filecheck_info_found,
		    char *, "Found file handle in cache list.",
		    struct fuse_file_handle *, fhp);
		return (1);
	}
	return (0);
}

/*
 * Iterates through the list of file handles and invokes the passed function
 * pointer
 */
static int
iterate_filehandle(struct vnode *vp, fuse_file_check_t file_check_fp,
    void *param, struct fuse_file_handle **fufhpp)
{
	int ret = 0;
	struct fuse_file_handle *fh, *next_fh;
	struct fuse_vnode_data *fvdatap = VTOFD(vp);

	mutex_enter(&fvdatap->fh_list_lock);
	for (fh = list_head(&fvdatap->fh_list); fh; fh = next_fh) {
		next_fh = list_next(&fvdatap->fh_list, fh);
		if ((ret = file_check_fp(fh, param))) {
			*fufhpp = fh;
			break;
		}
	}
	mutex_exit(&fvdatap->fh_list_lock);
	return (ret);
}

static int
get_filehandle(struct vnode *vp, int flag, struct cred *credp,
    struct fuse_file_handle **fufhpp, int check_cache)
{
	struct fuse_open_in	*foin;
	struct fuse_open_out	*foout;
	struct fuse_file_handle *fhp;
	int 			err = 0;
	fuse_msg_node_t		*msgp = NULL;
	fuse_session_t		*sep;
	struct fuse_fh_param	fh_param;
	fuse_vnode_data_t 	*fvdatap;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(get_filehandle_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	/* Check if it is due to create + open */
	if (vn_matchops(vp, temp_vnodeops)) {
		if ((err = create_filehandle(vp, flag, credp, &msgp))) {
			DTRACE_PROBE3(get_filehandle_err_create,
			    char *, "create_filehandle request failed",
			    int, err, struct vnode *, vp);
			goto out;
		} else if (msgp && msgp->opdata.outdata) {
			DTRACE_PROBE2(get_filehandle_info_create_ok,
			    char *, "create_filehandle request successful",
			    struct vnode *, vp);
			goto resp_intrprt;
		}
	}
	if ((check_cache & CACHE_LIST_CHECK)) {
		fh_param.credp = credp;
		fh_param.rw_mode = flag;
		fh_param.fufh = NULL;
		/*
		 * Check if we already have retrieved the file handle
		 * from user space before
		 */
		if (iterate_filehandle(vp, fuse_std_filecheck, &fh_param,
		    fufhpp))
			goto out;
	}
	/*
	 * Allocate a new message node only if create_filehandle wasn't able
	 * to do it for us, if not reuse memory
	 */

	if (!msgp)
		msgp = fuse_setup_message(sizeof (*foin),
		    (vp->v_type == VDIR? FUSE_OPENDIR: FUSE_OPEN),
		    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep));
	else
		fuse_msg_recreate(msgp, sizeof (*foin),
		    (vp->v_type == VDIR? FUSE_OPENDIR: FUSE_OPEN),
		    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep), 0);


	/* Set up arguments to the fuse library */
	foin = (struct fuse_open_in *)msgp->ipdata.indata;
	foin->flags = F_TO_O_FLAGS(flag & ~(O_CREAT | O_EXCL | O_NOCTTY |
	    O_TRUNC));

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* We got woken up, so fuse library has replied to our OPEN request */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(get_filehandle_err_open_req,
		    char *, "FUSE_OPEN request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}

	if (msgp->opdata.outsize != sizeof (struct fuse_open_out)) {
		DTRACE_PROBE2(get_filehandle_err_open_inval_resp,
		    char *, "FUSE_OPEN response invalid size",
		    size_t, msgp->opdata.outsize);
		err = EINVAL;
		goto cleanup;
	}
resp_intrprt:
	foout = (struct fuse_open_out *)msgp->opdata.outdata;
	fvdatap = VTOFD(vp);
	fhp = kmem_alloc(sizeof (struct fuse_file_handle), KM_SLEEP);

	fhp->fh_id = foout->fh;
	fhp->flags = foout->open_flags;

	fhp->mode = flag & ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);
	crhold(credp);
	fhp->credp = credp;
	fhp->ref = 1;
	fhp->process_id = curproc->p_pidp->pid_id;

	if (fufhpp)
		*fufhpp = fhp;

	/* Add it to the list */
	DTRACE_PROBE2(get_filehandle_info_insert,
	    char *, "file handle added to list",
	    struct fuse_file_handle *, fhp);
	mutex_enter(&fvdatap->fh_list_lock);
	list_insert_head(&fvdatap->fh_list, fhp);
	mutex_exit(&fvdatap->fh_list_lock);

cleanup:
	fuse_free_msg(msgp);
out:
	return (err);
}

/* ARGSUSED */
static int fuse_open(struct vnode **vpp, int flag, struct cred *cred_p,
    caller_context_t *ct)
{
	/*
	 * Send the fuse_OPEN req to lib and get the fh from there.
	 * alloc filehandle and associate with vnode private operation.
	 */
	struct vnode *vp = *vpp;
	int err = 0;

	if ((err = get_filehandle(vp, flag, cred_p, NULL,
	    CACHE_LIST_NO_CHECK))) {
		DTRACE_PROBE2(fuse_open_err_filehandle,
		    char *, "get_filehandle failed",
		    struct vnode *, vp);
		goto out;
	}

	/*
	 * TBD: Check can we do any optimization here? FreeBSD Fuse invokes
	 * vnode_create_vobject to avoid as it says needless getattr...
	 * Anything that can be done for Solaris?
	 */
out:
	return (err);
}

static int
fuse_send_release(fuse_session_t *sep, struct fuse_file_handle *fh,
    enum fuse_opcode op, struct vnode *vp, int flags)
{
	struct fuse_release_in *fri;
	fuse_msg_node_t *msgp;
	int err = DDI_SUCCESS;

	msgp = fuse_setup_message(sizeof (*fri), op, VNODE_TO_NODEID(vp),
	    sep->usercred, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	fri = (struct fuse_release_in *)msgp->ipdata.indata;
	fri->fh	= fh->fh_id;
	fri->flags = F_TO_O_FLAGS(flags & ~O_EXCL);

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* We got woken up, so fuse lib has replied to our release request */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_send_release_err_release_req,
		    char *, "FUSE_RELEASE request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}

cleanup:
	fuse_free_msg(msgp);
	return (err);
}

/* ARGSUSED */
static int fuse_close(struct vnode *vp, int flags, int count,
    offset_t offset, struct cred *credp, caller_context_t *ct)
{
	int err = DDI_SUCCESS;
	fuse_vnode_data_t *fvdatap = VTOFD(vp);
	struct fuse_file_handle *fhp = NULL;
	fuse_session_t *sep;
	enum fuse_opcode op = (vp->v_type == VDIR) ?
	    FUSE_RELEASEDIR : FUSE_RELEASE;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_close_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	if ((err = get_filehandle(vp, flags, credp, &fhp, CACHE_LIST_CHECK))) {
		DTRACE_PROBE2(fuse_close_err_filehandle,
		    char *, "get_filehandle failed",
		    struct vnode *, vp);
		goto cleanup;
	}

	fhp->ref--;
	if (fhp->ref == 1) {
		/* Remove it from the list */
		DTRACE_PROBE2(fuse_close_info_release,
		    char *, "releasing file handle",
		    struct fuse_file_handle *, fhp);

		mutex_enter(&fvdatap->fh_list_lock);
		list_remove(&fvdatap->fh_list, fhp);
		mutex_exit(&fvdatap->fh_list_lock);

		err = fuse_send_release(sep, fhp, op, vp, flags);
		kmem_free(fhp, sizeof (*fhp));
	}
cleanup:
	return (err);
}

/* ARGSUSED */
static int
fuse_getapage(struct vnode *vp, u_offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *credp)
{
	struct page *pp;
	fuse_msg_node_t *msgp = NULL;
	int err = 0;
	struct fuse_read_in *fri;
	fuse_session_t *sep;
	struct fuse_file_handle *fhp = NULL;
	int mode = FREAD;
	struct buf *bp = NULL;

	if (protp != NULL)
		*protp = PROT_ALL;

	if (pl == NULL)
		return (0);

	pl[0] = NULL;

again:
	if (pp = page_lookup(vp, off, rw == S_CREATE ? SE_EXCL : SE_SHARED)) {
		DTRACE_PROBE2(fuse_getapage_info_found,
		    char *, "page found",
		    struct page *, pp);
		pl[0] = pp;
		pl[1] = NULL;
		return (err);
	} else {
		pp = page_create_va(vp, off, PAGESIZE, PG_WAIT,
		    seg, addr);
		/*
		 * Someone raced in and created the page after we did the
		 * lookup but before we did the create, so go back and
		 * try to look it up again.
		 */
		if (pp == NULL) {
			DTRACE_PROBE1(fuse_getapage_err_create_failed,
			    char *, "page_create_va failed, try again");
			goto again;
		}

		DTRACE_PROBE2(fuse_getapage_info_create,
		    char *, "page_create_va successful",
		    struct page *, pp);

		sep = fuse_minor_get_session(getminor(vp->v_rdev));
		if (sep == NULL) {
			DTRACE_PROBE2(fuse_getapage_err_session,
			    char *, "failed to find session",
			    struct vnode *, vp);
			err = ENODEV;
			goto cleanup;
		}

		msgp = fuse_setup_message(sizeof (*fri),
		    (vp->v_type == VDIR) ? FUSE_READDIR : FUSE_READ,
		    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep));

		fri = (struct fuse_read_in *)msgp->ipdata.indata;

		/*
		 * Obtain the file handle associated with this request
		 * if it has already been retrieved from userspace then we
		 * should find it in our file handle list
		 */
		if ((err = get_filehandle(vp, mode, credp, &fhp,
		    CACHE_LIST_CHECK))) {
			DTRACE_PROBE2(fuse_getapage_err_filehandle,
			    char *, "get_filehandle failed",
			    struct vnode *, vp);
			goto cleanup;
		}

		fri->fh = fhp->fh_id;
		fri->offset = off;
		fri->size = (uint32_t)PAGESIZE;
		/* Map the page so that uio_move can be done on the page */
		fuse_page_mapin(vp, &bp, pp, len, B_READ,
		    &(msgp->opdata.iovbuf));

		/*
		 * queue the message for sending to userland filesystem
		 * framework
		 */
		if ((err = fuse_queue_request_wait(sep, msgp))) {
			goto cleanup;
		}
		/*
		 * If all has gone well we should have got the data in the page
		 * by this time already
		 */
		if ((err = msgp->opdata.fouth->error) != 0) {
			DTRACE_PROBE2(fuse_getapage_err_read_req,
			    char *, "FUSE_READ request failed",
			    struct fuse_out_header *, msgp->opdata.fouth);
			goto cleanup;
		}

		/*
		 * XXX: Is this required as this might have already been
		 * done earlier?
		 */
		/* If the returned data is less than what was asked for */
		if (msgp->opdata.outsize < PAGESIZE) {
			/* Zero out the rest of the page */
			bzero((void *)((char *)msgp->opdata.iovbuf.base +
			    msgp->opdata.outsize),
			    (PAGESIZE - msgp->opdata.outsize));
		}

	cleanup:
		if (bp != NULL) {
			bp_mapout(bp);
			pageio_done(bp);
		}

		if (err && pp) {
			pvn_read_done(pp, B_ERROR);
		}

		if (err == 0) {
			pvn_plist_init(pp, pl, plsz, off, PAGESIZE, rw);
		}

		if (fhp)
			fhp->ref--;

		if (msgp)
			fuse_free_msg(msgp);

	}

	return (err);
}


/* ARGSUSED */
static int
fuse_getpage(struct vnode *vp, offset_t off, size_t len, uint_t *protp,
    page_t *pl[], size_t plsz, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *credp, caller_context_t *ct)
{

	int err;

	if (len > PAGESIZE) {
		err = pvn_getpages(fuse_getapage, vp, off, len, protp, pl, plsz,
		    seg, addr, rw, credp);
	} else {
		err = fuse_getapage(vp, off, len, protp, pl, plsz, seg, addr,
		    rw, credp);
	}

	return (err);
}


/*
 * Read of devices (leaf nodes) is handled by specfs.
 * Read of directories is not supported.
 */
/* ARGSUSED */
static int
fuse_read(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *credp, struct caller_context *ct)
{
	return (rdfuse(vp, uiop, credp));

}

/*
 * This routine performs the actual read operation from the vnode. As a
 * side effect of the call made here, getpage routine gets
 * invoked which obtains the required data from the daemon.
 */
static int
rdfuse(struct vnode *vp, struct uio *uiop, struct cred *credp)
{
	int err;
	ulong_t req_len = uiop->uio_resid;
	ulong_t pageoffset;
	ulong_t segmap_offset;
	offset_t off;
	ssize_t len;
	caddr_t base;
	offset_t diff;
	u_offset_t fsize;

	/* Do consistency checks */
	if (uiop->uio_loffset < 0) {
		DTRACE_PROBE2(rdfuse_err_offset,
		    char *, "uio_loffset < 0",
		    struct uio *, uiop);
		return (EINVAL);
	}

	if (uiop->uio_resid == 0 ||
	    uiop->uio_loffset > MAXOFF_T) {
		DTRACE_PROBE2(rdfuse_info_offset,
		    char *, "uio_resid == 0 || uio_loffset > MAXOFF_T",
		    struct uio *, uiop);
		return (0);
	}

	if ((err = fuse_getfilesize(vp, &fsize, credp))) {
		DTRACE_PROBE3(rdfuse_err_filesize,
		    char *, "fuse_getfilesize failed",
		    int, err, struct vnode *, vp);
		return (err);
	}
	do {
		/* Calculate offset within a page that must be read */
		off = uiop->uio_loffset;
		pageoffset = off & PAGEOFFSET;
		len = MIN(PAGESIZE - pageoffset, uiop->uio_resid);

		/* Check if we are crossing end of file */
		diff = fsize - off;

		if (diff <= 0) {
			err = 0;
			break;
		}

		/* Adjust the length to be read if necessary */
		if (diff < len)
			len = (ssize_t)diff;

		if (vpm_enable) {
			err = vpm_data_copy(vp, off, len, uiop, 1,
			    NULL, 0, S_READ);
		} else {
			segmap_offset = (off & PAGEMASK) & MAXBOFFSET;
			base = segmap_getmapflt(segkmap, vp, off & MAXBMASK,
			    len, 1, S_READ);

			err = uiomove(base + segmap_offset + pageoffset,
			    (long)len, UIO_READ, uiop);
		}

		if (vpm_enable)
			(void) vpm_sync_pages(vp, off, len, 0);
		else
			(void) segmap_release(segkmap, base, 0);
	} while (err == 0 && uiop->uio_resid > 0);

	if (uiop->uio_resid != req_len)
		err = 0;

	return (err);
}

static inline void
fsize_change_notify(struct vnode *vp, size_t fsize, int flag)
{
	VTOFD(vp)->fsize = fsize;
	VTOFD(vp)->file_size_status = flag;
}

/* Main routine which does the actual write operation */
static int
wrfuse(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *credp, caller_context_t *ct)
{
	u_offset_t uoff;
	long	pageoff;	/* offset within a page */
	caddr_t base;		/* base of segmap */
	ssize_t bytes;
	int err;
	int pagecreate, newpage;
	ssize_t premove_resid;
	uint_t flags;
	ulong_t segmap_offset;
	rlim64_t limit = uiop->uio_llimit;
	int file_size_change = 0;
	long start_resid = uiop->uio_resid;	/* save starting resid */
	u_offset_t start_off = uiop->uio_offset; /* save starting offset */
	u_offset_t fsize;

	if (limit == RLIM64_INFINITY || limit > MAXOFFSET_T)
		limit = MAXOFFSET_T;

	if (uiop->uio_loffset >= limit) {
		proc_t *p = ttoproc(curthread);

		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_FSIZE], p->p_rctls,
		    p, RCA_UNSAFE_SIGINFO);
		mutex_exit(&p->p_lock);
		return (EFBIG);
	}
	if ((err = fuse_getfilesize(vp, &fsize, credp))) {
		DTRACE_PROBE3(wrfuse_err_filesize,
		    char *, "fuse_getfilesize failed",
		    int, err, struct vnode *, vp);
		return (err);
	}

	if (((ioflag & FAPPEND) != 0) && (vp->v_type == VREG)) {
		uiop->uio_loffset = fsize;
	}

	/*
	 * XXX If we later decide to support DIRECT_IO, its logic should
	 * go here
	 */

	do {
		uoff = uiop->uio_offset;
		pageoff = uoff & (u_offset_t)PAGEOFFSET;
		bytes = MIN(PAGESIZE - pageoff, uiop->uio_resid);

		if (uoff + bytes >= limit) {
			if (uoff >= limit) {
				err = EFBIG;
				goto out;
			}
			bytes = limit - uoff;
		}
		/*
		 * When is it not necessary to read in old page?
		 * Under following cases:
		 * 1. When we are writing one full page with page offset zero.
		 * 2. When the file is yet to be written to or of zero size.
		 * 3. When we are extending the file from a new page
		 */
		pagecreate = (bytes == PAGESIZE) | (fsize == 0) |
		    ((pageoff == 0) && (fsize <= uiop->uio_offset));

		if (uoff + bytes > fsize) {
			file_size_change = 1;
		}

		newpage = 0;
		premove_resid = uiop->uio_resid;

		if (vpm_enable) {
			err = vpm_data_copy(vp, uoff, bytes, uiop, !pagecreate,
			    &newpage, 0, S_WRITE);
		} else {
			segmap_offset = (uoff & PAGEMASK) & MAXBOFFSET;
			base = segmap_getmapflt(segkmap, vp,
			    uoff & MAXBMASK, PAGESIZE, !pagecreate, S_WRITE);
			/*
			 * segmap_pagecreate() returns 1 if it calls
			 * page_create_va() to allocate any pages.
			 */
			if (pagecreate) {
				newpage = segmap_pagecreate(segkmap,
				    base + segmap_offset, (size_t)PAGESIZE, 0);
				/*
				 * clear from the beginning of the page to the
				 * start offset of the data.
				 */
				if (pageoff != 0)
					(void) kzero(base + segmap_offset,
					    (size_t)pageoff);
			}

			err = uiomove(base + segmap_offset + pageoff,
			    (long)bytes, UIO_WRITE, uiop);
			/*
			 * If a new page was created, then we need to make sure
			 * that the page is properly initialized. Take care to
			 * zero out that part of the page where uio_move din't
			 * write valid data.
			 */
			if (pagecreate &&
			    uiop->uio_offset < P2ROUNDUP(uoff + bytes,
			    PAGESIZE)) {
				long zoffset;
				long nmoved;

				nmoved = uiop->uio_offset - uoff;
				ASSERT((nmoved + pageoff) <= PAGESIZE);

				if ((zoffset = pageoff + nmoved) < PAGESIZE)
					(void) kzero(
					    base + segmap_offset + zoffset,
					    (size_t)PAGESIZE - zoffset);
			}
			/*
			 * Unlock the page which have been allocated by
			 * page_create_va() in segmap_pagecreate()
			 */
			if (newpage) {
				segmap_pageunlock(segkmap, base + segmap_offset,
				    (size_t)PAGESIZE, S_WRITE);
			}
		}
		/*
		 * If the file size indeed changed after the
		 * uiomove, record that fact which will be
		 * used in fuse_putpage
		 */
		if (file_size_change) {
			/*
			 * if there was an error than first determine whether
			 * we did extend the file
			 */
			if (err) {
				if ((uoff + (premove_resid - uiop->uio_resid))
				    > fsize) {
					fsize = fsize + (premove_resid -
					    uiop->uio_resid);
					(void) fsize_change_notify(vp, fsize,
					    FSIZE_UPDATED);
				}
			} else {
				fsize = uoff + bytes;
				(void) fsize_change_notify(vp, fsize,
				    FSIZE_UPDATED);
			}
		}

		if (err) {
			DTRACE_PROBE2(wrfuse_err_write_fail,
			    char *, "write error, invalidate pages",
			    struct uio *, uiop);

			/*
			 * If we did not allocate a new page and if the file
			 * size remained unchanged, then we need to destroy
			 * the page where write failed so that we don't end up
			 * flushing invalid data
			 */
			if (file_size_change == 0 && newpage == 0) {
				/*
				 * Similar to UFS, we unwind what uiomove
				 * last did
				 */
				uiop->uio_resid = premove_resid;
				flags = SM_DESTROY;
			} else {
				/*
				 * Remove the page from the cache, if the page
				 * is dirty it would be written back
				 */
				flags = SM_INVAL;
			}
			/*
			 * If we failed on a write, we must
			 * be sure to invalidate any pages that may have
			 * been allocated.
			 */
			if (vpm_enable) {
				(void) vpm_sync_pages(vp, uoff, PAGESIZE,
				    flags);
			} else {
				(void) segmap_release(segkmap, base, flags);
			}
		} else {
			if (vpm_enable) {
				err = vpm_sync_pages(vp, uoff, PAGESIZE, 0);
			} else {
				err = segmap_release(segkmap, base, 0);
			}
		}
	} while (uiop->uio_resid > 0 && err == 0 && bytes != 0);
out:
	/* if we did write any data, then try flushing it out to daemon */
	if (start_resid != uiop->uio_resid) {
		err = VOP_PUTPAGE(vp, (offset_t)(start_off & PAGEMASK),
		    (size_t)0, 0, credp, ct);
	}

	return (err);
}

/*
 * Write of devices (leaf nodes) is handled by specfs.
 * Write of directories is not supported.
 */
/* ARGSUSED */
static int
fuse_write(struct vnode *vp, struct uio *uiop, int ioflag,
    struct cred *credp, struct caller_context *ct)
{
	/* Check for valid file types */
	if (vp->v_type != VREG && vp->v_type != VLNK)
		return (EIO);

	if (uiop->uio_loffset < (offset_t)0)
		return (EINVAL);

	if (uiop->uio_resid == 0)
		return (0);

	return (wrfuse(vp, uiop, ioflag, credp, ct));
}

static void fuse_set_getattr(struct vnode *vp, struct vattr *vap,
    struct fuse_attr *attr)
{
	vap->va_mode = attr->mode & MODEMASK;
	vap->va_size = attr->size;
	vap->va_atime.tv_sec = attr->atime;
	vap->va_atime.tv_nsec = attr->atimensec;
	vap->va_mtime.tv_sec = attr->mtime;
	vap->va_mtime.tv_nsec = attr->mtimensec;

	vap->va_uid = attr->uid;
	vap->va_gid = attr->gid;
	vap->va_nlink = attr->nlink;
	vap->va_ctime.tv_sec = attr->ctime;
	vap->va_ctime.tv_nsec = attr->ctimensec;

	vap->va_mask = AT_ALL;
	vap->va_type = vp->v_type;
	vap->va_nodeid = VNODE_TO_NODEID(vp);

	vap->va_rdev = vp->v_rdev;
	vap->va_blksize = vp->v_vfsp->vfs_bsize;
#define	howmany(x, y)	(((x)+((y)-1))/(y))

	vap->va_nblocks = howmany(vap->va_size, vap->va_blksize);
	/* TBD: What value should we set here ? */
	vap->va_seq = 0;
	vap->va_fsid = vp->v_vfsp->vfs_dev;
}

static int
fuse_getattr_from_daemon(struct vnode *vp, struct vattr *vap,
    cred_t *credp, fuse_msg_node_t **msgpp)
{
	int err;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_getattr_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	msgp = fuse_alloc_msg();

	/*
	 * setup the message with only header and no arguments to be sent to
	 * fuse library
	 */
	setup_msg_onlyheader(msgp, FUSE_GETATTR, FUSE_GET_UNIQUE(sep),
	    VNODE_TO_NODEID(vp), credp);


	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto out;
	}

	/* We got woken up, so fuse library has replied to our request */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_getattr_err_getattr_req,
		    char *, "FUSE_GETATTR request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto out;
	}

	if (msgp->opdata.outsize != sizeof (struct fuse_attr_out)) {
		DTRACE_PROBE2(fuse_getattr_err_inval_resp,
		    char *, "FUSE_GETATTR response invalid size",
		    size_t, msgp->opdata.outsize);
		err = EINVAL;
		goto out;
	}
	fuse_set_getattr(vp, vap,
	    &((struct fuse_attr_out *)msgp->opdata.outdata)->attr);

	if (msgpp) {
		/* It's caller's responsibility to free the msg node */
		*msgpp = msgp;
		return (err);
	}

out:
	fuse_free_msg(msgp);
	return (err);
}

/*
 * The flags parameter is generally passed as zero from most syscalls to
 * VOP_GETATTR
 */
/* ARGSUSED */
static int
fuse_getattr(struct vnode *vp, struct vattr *vap, int flags, cred_t *credp,
    caller_context_t *ct)
{
	int err = DDI_SUCCESS;
	fuse_msg_node_t *msgp = NULL;
#ifndef DONT_CACHE_ATTRIBUTES
	timestruc_t ts;
#endif

#ifndef DONT_CACHE_ATTRIBUTES
	gethrestime(&ts);
	if (ATTR_CACHE_VALID(ts, VTOFD(vp)->cached_attrs_bound)) {
		(void) memcpy(vap, &(VTOFD(vp)->cached_attrs), sizeof (*vap));
		DTRACE_PROBE2(fuse_getattr_info_cached,
		    char *, "Using cached attributes", struct vnode *, vp);
		return (0);
	}
#endif
	err = fuse_getattr_from_daemon(vp, vap, credp, &msgp);

	if (err)
		return (err);

#ifndef DONT_CACHE_ATTRIBUTES
	cache_attrs(vp, (struct fuse_attr_out *)(msgp->opdata.outdata));
#endif

out:
	fuse_free_msg(msgp);
	return (err);
}


/*
 * The flags parameter is generally passed as zero from most syscalls to
 * VOP_SETATTR.
 */
/* ARGSUSED */
static int
fuse_setattr(
    struct vnode *vp,
    struct vattr *vap,
    int flags,
    struct cred *credp,
    caller_context_t *ct)
{
	int err = 0;
	fuse_msg_node_t *msgp;
	struct fuse_setattr_in *fsai;
	struct vattr va;
	enum vtype vtyp;
	long int mask = vap->va_mask;
	fuse_session_t *sep;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_setattr_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	/* Check for unsettable attributes */
	if (mask & AT_NOSET)
		return (EINVAL);

	mutex_enter(&VTOFD(vp)->f_lock);

	if (err = VOP_GETATTR(vp, &va, flags, credp, ct))
		goto cleanup2;

	/* Let kernel do the appropriate access checks */
	err = secpolicy_vnode_setattr(credp, vp, vap, &va, flags,
	    fuse_access_i, vp);

	if (err)
		goto cleanup2;

	mask = vap->va_mask;

	msgp = fuse_setup_message(sizeof (*fsai), FUSE_SETATTR,
	    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep));

	fsai = msgp->ipdata.indata;

/*
 * In case we plan to support lower versions of fuse library this macro
 * can be changed
 */
#define	FUSEATTR(x) x

	if (mask & AT_UID) {
		fsai->FUSEATTR(uid) = vap->va_uid;
		fsai->valid |= FATTR_UID;
	}

	if (mask & AT_GID) {
		fsai->FUSEATTR(gid) = vap->va_gid;
		fsai->valid |= FATTR_GID;
	}

	if (mask & AT_MODE) {
		va.va_mode &= S_IFMT;
		va.va_mode |= vap->va_mode & ~S_IFMT;
		fsai->FUSEATTR(mode) = va.va_mode;
		fsai->valid |= FATTR_MODE;
	}

	if (mask & AT_ATIME) {
		fsai->FUSEATTR(atime) = vap->va_atime.tv_sec;
		fsai->FUSEATTR(atimensec) = vap->va_atime.tv_nsec;
		fsai->valid |= FATTR_ATIME;
	}

	if (mask & AT_MTIME) {
		fsai->FUSEATTR(mtime) = vap->va_mtime.tv_sec;
		fsai->FUSEATTR(mtimensec) = vap->va_mtime.tv_nsec;
		fsai->valid |= FATTR_MTIME;
	}

	if (mask & AT_SIZE) {
		fsai->FUSEATTR(size) = vap->va_size;
		fsai->valid |= FATTR_SIZE;
	}
	/* if we received a signal or daemon replied with an error */
	if ((err = fuse_queue_request_wait(sep, msgp)) != 0) {
		goto cleanup;
	}
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_setattr_err_setattr_req,
		    char *, "FUSE_SETATTR request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
#ifndef DONT_CACHE_ATTRIBUTES
		invalidate_cached_attrs(vp);
#endif
		goto cleanup;
	}
	vtyp =
	    IFTOVT(((struct fuse_attr_out *)msgp->opdata.outdata)->attr.mode);

	if (vp->v_type != vtyp) {
		if (vp->v_type == VNON) {
			vp->v_type = vtyp;
		} else {
			VOP_INACTIVE(vp, credp, ct);
			err = ENOTCONN;
			goto cleanup;
		}
	}
#ifndef DONT_CACHE_ATTRIBUTES
	cache_attrs(vp, (struct fuse_attr_out *)msgp->opdata.outdata);
#endif

cleanup:
	fuse_free_msg(msgp);
cleanup2:
	mutex_exit(&VTOFD(vp)->f_lock);
	return (err);
}
/*
 * vnode operation to support POSIX link()
 * The first param is the vnode of the dir containing the file, second param is
 * the vnode of the file to hard link, the third param is the new name to be
 * given.
 */
/* ARGSUSED */
static int
fuse_link(struct vnode *dvp, struct vnode *srcvp, char *tnm,
    struct cred *credp, caller_context_t *ct, int flags)
{
	struct fuse_link_in *fli;
	struct fuse_entry_out *feo;
	fuse_msg_node_t *msgp;
	char *name;
	fuse_session_t *sep;
	int err = DDI_SUCCESS;
	int nmlen = strlen(tnm) + 1;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_link_err_session,
		    char *, "failed to find session",
		    struct vnode *, dvp);
		return (ENODEV);
	}

	msgp = fuse_setup_message(sizeof (*fli) + nmlen, FUSE_LINK,
	    VNODE_TO_NODEID(dvp), credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	fli = (struct fuse_link_in *)msgp->ipdata.indata;
	fli->oldnodeid = VNODE_TO_NODEID(srcvp);
	name = (char *)msgp->ipdata.indata + sizeof (*fli);
	(void *) strlcpy(name, tnm, nmlen);
	name[nmlen - 1] = '\0';

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* We got woken up, so fuse lib has replied to our release request */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_link_err_link_req,
		    char *, "FUSE_LINK request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}

	feo = (struct fuse_entry_out *)msgp->opdata.outdata;

	if ((err = checkentry(feo, srcvp->v_type))) {
		goto cleanup;
	}
#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(dvp);
	/*
	 * To be on the safer side we disregard the cached attribute for the
	 * original so that fs gets a chance to pass on updated attributes next
	 * time we need
	 */
	/* See the comments at the same place in FreeBSD Fuse kernel module */
	invalidate_cached_attrs(srcvp);
#endif
	VTOFD(srcvp)->nlookup++;

cleanup:
	fuse_free_msg(msgp);
	return (err);
}

/* unistd.h */
/* Symbolic constants for the "access" routine: */
#define	R_OK	4	/* Test for Read permission */
#define	W_OK	2	/* Test for Write permission */
#define	X_OK	1	/* Test for eXecute permission */
#define	F_OK	0	/* Test for existence of File */

/* ARGSUSED */
static int
fuse_access(struct vnode *vp, int mode, int flags, struct cred *credp,
    caller_context_t *ct)
{
	return (fuse_access_i((void *)vp, mode, credp));
}

static int
fuse_access_i(void *vvp, int mode, struct cred *credp)
{
	struct vnode *vp = vvp;
	struct fuse_access_in *fai;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;
	int err = 0;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_access_i_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	/*
	 * TBD: Check if it is mounted readonly and return error on
	 * Write access
	 */

	/*
	 * According to FreeBSD Fuse, if default permission option is
	 * set while mounting or if a regular file is checked for executing
	 * we have to do a in-kernel check. Since we don't have mount options
	 * support yet, we just check for execute mode
	 */
	if (vp->v_type == VREG && mode == VEXEC) {
		return (fuse_access_inkernelcheck(vp, mode, credp));
	} else {
		msgp = fuse_setup_message(sizeof (*fai), FUSE_ACCESS,
		    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep));

		fai = (struct fuse_access_in *)msgp->ipdata.indata;

		fai->mask = F_OK;
		if (mode & VREAD)
			fai->mask |= R_OK;
		if (mode & VWRITE)
			fai->mask |= W_OK;
		if (mode & VEXEC)
			fai->mask |= X_OK;

		/*
		 * queue the message for sending to userland filesystem
		 * lib framework
		 */
		err = fuse_queue_request_wait(sep, msgp);
		if (!(err)) {
			/*
			 * We got woken up, so fuse library has replied to
			 * our request
			 */
			err = msgp->opdata.fouth->error;
			if (err == ENOSYS) {
				DTRACE_PROBE2(fuse_access_i_info_enosys,
				    char *,
				    "FUSE_ACCESS not supported by filesys",
				    struct fuse_out_header *,
				    msgp->opdata.fouth);
				/*
				 * If the userspace filesystem has not provided
				 * an implementation we just return SUCCESS to
				 * the kernel
				 */
				err = 0;
			} else {
				DTRACE_PROBE2(fuse_access_i_err_access_req,
				    char *, "FUSE_ACCESS request failed",
				    struct fuse_out_header *,
				    msgp->opdata.fouth);
			}
		}
		fuse_free_msg(msgp);
		return (err);
	}
}

/* Performs the basic access check w.r.t. owner, group and public permissions */
#define	MODESHIFT	3
static int
fuse_access_inkernelcheck(void *vvp, int mode, struct cred *credp)
{
	int shift = 0;
	struct vnode *vp = (struct vnode *)vvp;
	int err = 0;
	struct vattr va;

	if (err = VOP_GETATTR(vp, &va, 0, credp, NULL))
		return (err);

	/* Check access based on owner, group and public permissions */
	if (crgetuid(credp) != va.va_uid) {
		shift += MODESHIFT;
		if (groupmember(va.va_gid, credp))
			shift += MODESHIFT;
	}
	/* Compute missing mode bits */
	mode &= ~(va.va_mode << shift);

	if (mode == 0)
		return (0);

	return (secpolicy_vnode_access(credp, vp, va.va_uid, mode));
}

/*
 * Logic is from UFS.
 * Decide whether it is okay to remove within a sticky directory.
 * Two conditions need to be met:  write access to the directory
 * is needed.  In sticky directories, write access is not sufficient;
 * you can remove entries from a directory only if you own the directory,
 * if you are privileged, if you own the entry or if the entry is
 * a plain file and you have write access to that file.
 * Function returns 0 if remove access is granted.
 */
static int
fuse_sticky_remove_access(struct vnode *dvp, struct vnode *vp, struct cred *cr,
    caller_context_t *ct)
{
	struct vattr dva;
	struct vattr va;
	uid_t uid;
	int err;

	/*
	 * Ah! We will have to request daemon for both source and its parent
	 * directory vnode attributes. We try getting attributes for source
	 * before its par directory since there is a better chance that we
	 * might be able to sneak in and get the attributes from the cache.
	 */
	if (err = VOP_GETATTR(vp, &va, 0, cr, ct))
		return (err);

	if (err = VOP_GETATTR(dvp, &dva, 0, cr, ct))
		return (err);

	/* Perform the check */
	if ((dva.va_mode & VSVTX) &&
	    (uid = crgetuid(cr)) != dva.va_uid &&
	    uid != va.va_uid &&
	    (va.va_mode != VREG ||
	    fuse_access_i((void *)vp, VWRITE, cr) != 0))
		return (secpolicy_vnode_remove(cr));

	return (0);
}

/*
 * Lookup
 *
 * Given the directory vnode and the name of the component, return
 * the corresponding held vnode for that component.
 */
/* ARGSUSED */

static int fuse_lookup(struct vnode *dvp, char *nm, struct vnode **vpp,
    struct pathname *pnp, int flags, struct vnode *rdir, struct cred *credp,
    caller_context_t *ct, int *direntflags, pathname_t *realpnp)
{
	int err = 0;
	fuse_session_t *sep;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_lookup_err_session,
		    char *, "failed to find session",
		    struct vnode *, dvp);
		return (ENODEV);
	}

	if (dvp->v_type != VDIR) {
		err = ENOTDIR;
		goto out;
	}

	/*
	 * if this is the root of our filesystem, we will check
	 * for valid access permissions
	 */
	if ((VTOFD(dvp))->nodeid == FUSE_ROOT_ID) {
		if (err = fuse_access(dvp, VEXEC, flags, credp, ct)) {
			DTRACE_PROBE2(fuse_lookup_err_access,
			    char *, "fuse_access failed",
			    struct vnode *, dvp);
			goto out;
		}
	}

	/* Check for NULL name and "." */
	if (nm[0] == '\0' || ((nm[0] == '.') && (nm[1] == '\0'))) {
		VN_HOLD(dvp);
		*vpp = dvp;
		goto out;
	}

	/* Check if lookup needs to traverse beyond our filesystem */
	if (nm[0] == '.' && nm[1] == '.' && nm[2] == '\0') {
		if (VTOFD(dvp)->nodeid == FUSE_ROOT_ID) {
			if (dvp->v_vfsp->vfs_vnodecovered) {
				err = VOP_LOOKUP(dvp->v_vfsp->vfs_vnodecovered,
				    nm, vpp, pnp, flags, rdir, credp, ct,
				    direntflags, realpnp);
			} else {
				DTRACE_PROBE2(fuse_lookup_err_vnodecovered,
				    char *, "vnode covered is NULL",
				    struct vnode *, dvp);
				err = EIO;
			}
		} else if (VTOFD(dvp)->par_nid == FUSE_ROOT_ID) {
			err = VFS_ROOT(dvp->v_vfsp, vpp);
		} else if (VTOFD(dvp)->par_nid != FUSE_NULL_ID) {
			err = fuse_getvnode(VTOFD(dvp)->par_nid, vpp,
			    VNODE_CACHED, VDIR, sep, dvp->v_vfsp, 0, NULL,
			    FUSE_NULL_ID, credp);
			/*
			 * We don't seem to have the parent vnode cached, so
			 * we need to request daemon then
			 */
			if (err == ENOENT) {
				goto request_daemon;
			}
		} else {
			/*
			 * If we don't have a valid parent nodeid then there
			 * isn't much we can do, so we return error to the user
			 */
			DTRACE_PROBE2(fuse_lookup_err_parent,
			    char *, "No valid parent nodeid",
			    struct vnode *, dvp);
			err = EIO;
		}
		goto out;
	}

request_daemon:
	err = fuse_lookup_i(dvp, nm, vpp, credp);
out:
	return (err);
}


/*
 * This will free the private data allocated for a vnode. The caller should
 * ensure all the file handles associated with the passed vnode has been
 * released appropriately before invoking this function
 */
static void
fuse_free_vdata(struct vnode *vp)
{
	fuse_vnode_data_t *fvdatap = VTOFD(vp);
	list_destroy(&fvdatap->fh_list);
	mutex_destroy(&fvdatap->fh_list_lock);
	mutex_destroy(&fvdatap->f_lock);
	kmem_free(fvdatap, sizeof (*fvdatap));
}

/*
 * This routine frees a vnode and ensures that appropriate cleanups is taken
 * care of before returning it to the kernel
 */
static void
fuse_vnode_destroy(struct vnode *vp, struct cred *credp, fuse_session_t *sep)
{
	fuse_vnode_cleanup(vp, credp, sep);

	if (VTOFD(vp))
		fuse_free_vdata(vp);
	vp->v_data = NULL;

	vn_free(vp);
}

static int
fuse_getvnode(uint64_t nodeid, struct vnode **vpp, v_getmode vmode,
    uint32_t mode, fuse_session_t *sep, vfs_t *vfsp, int namelen,
    char *name, uint64_t parent_nid, struct cred *credp)
{
	fuse_avl_cache_node_t tofind, *foundp;
	fuse_avl_cache_node_t *avl_nodep;
	int create_new = 0;

	tofind.facn_nodeid = nodeid;
	if ((foundp = avl_find(&(sep->avl_cache), &tofind,
	    NULL)) != NULL) {
		*vpp = foundp->facn_vnode_p;
		ASSERT(*vpp);
		/*
		 * If we need a new vnode, then try to destroy the previously
		 * cached vnode
		 */
		if (vmode == VNODE_NEW) {
			(void) fuse_vnode_destroy(*vpp, credp, sep);
			create_new = 1;
		} else {
			VN_HOLD(*vpp);
		}
	} else {
		/*
		 * If the caller was looking for the previously cached vnode
		 * then return an error since we din't find it in the AVL tree
		 */
		if (vmode == VNODE_CACHED) {
			return (ENOENT);
		}
		/*
		 * Create and add the vnode in AVL cache
		 */
		create_new = 1;
	}
	if (create_new) {
		*vpp = fuse_create_vnode(vfsp, nodeid, parent_nid,
		    mode, OTHER_OP);

		avl_nodep = fuse_avl_cache_node_create(
		    *vpp, nodeid, parent_nid, namelen, name);
		avl_add(&(sep->avl_cache), avl_nodep);
	}
	VTOFD(*vpp)->nlookup++;
	return (0);
}

static int
fuse_lookup_i(struct vnode *dvp, char *nm, struct vnode **vpp, cred_t *credp)
{
	int err = 0;
	int nmlen = 0;
	uint64_t nodeid;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;
	struct fuse_entry_out *feo;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_lookup_i_err_session,
		    char *, "failed to find session",
		    struct vnode *, dvp);
		return (ENODEV);
	}

	nmlen = strlen(nm) + 1;

	/* Be cautions against a possible attack */
	if (nmlen > MAXNAMELEN) {
		DTRACE_PROBE2(fuse_lookup_i_err_nametoolong,
		    char *, "name too long", char *, nm);
		return (ENAMETOOLONG);
	}

	/* Need to send a FUSE_LOOKUP message to the fuse library */
	msgp = fuse_setup_message(nmlen, FUSE_LOOKUP, VNODE_TO_NODEID(dvp),
	    credp, FUSE_GET_UNIQUE(sep));

	(void *) strlcpy(msgp->ipdata.indata, nm, nmlen);

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		fuse_free_msg(msgp);
		return (err);
	}

	/* We got woken up, so fuse library has replied to our Lookup request */

	/* Check for any error from fuse library */
	if ((err = msgp->opdata.fouth->error) == 0) {
		/*
		 * If there was no error from the fuse library, then verify
		 * obtained nodeid
		 */
		feo = (struct fuse_entry_out *)msgp->opdata.outdata;
		nodeid = feo->nodeid;
		if (!nodeid) {
			err = ENOENT;
		} else if (nodeid == FUSE_ROOT_ID) {
			err = EIO;
		} else { /* Valid nodeid perhaps */
			err = fuse_getvnode(nodeid, vpp, VNODE_ANY,
			    IFTOVT(feo->attr.mode), sep, dvp->v_vfsp, nmlen, nm,
			    VNODE_TO_NODEID(dvp), credp);

			if (err) {
				fuse_send_forget(nodeid, sep, 1);
			} else {
#ifndef DONT_CACHE_ATTRIBUTES
				cache_attrs((*vpp), feo);
#endif

				/*
				 * Convert device special files
		 		 */
				if (IS_DEVVP(*vpp)) {
					vnode_t	*svp;

					svp = specvp(*vpp, (*vpp)->v_rdev,
					    (*vpp)->v_type, credp);
					VN_RELE(*vpp);
					if (svp == NULL)
						err = ENOSYS;
					else
						*vpp = svp;
				}
			}
		}
	} else {
		DTRACE_PROBE2(fuse_lookup_i_err_lookup_req,
		    char *, "FUSE_LOOKUP request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
	}

	fuse_free_msg(msgp);
	return (err);
}

/*
 * The following comments are from (OpenSolaris) ZFS :
 * Remove a directory subdir entry. If the current working
 * directory is the same as the subdir to be removed, the
 * remove will fail. [BUT fuse has no way to know if cwd is
 *	 subdir of dvp as we do not maintain the dir tree in kernel]
 *
 *	IN:	dvp	- vnode of directory to remove from.
 *		name	- name of directory to be removed.
 *		cwd	- vnode of current working directory.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 */
/* ARGSUSED */
static int
fuse_rmdir(vnode_t *dvp, char *name, vnode_t *cwd, cred_t *credp,
    caller_context_t *ct, int flags)
{
	int err = 0;
	fuse_session_t *sep;
	fuse_msg_node_t *msgp;
	struct vnode *vp = NULL;
	int namelen = strlen(name) + 1;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_rmdir_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	if (dvp->v_type != VDIR)
		return (ENOTDIR);

	/* . and .. cannot be removed */
	if (name[0] == '.') {
		if (name[1] == '\0') {
			return (EINVAL);
		} else if (name[1] == '.' && name[2] == '\0') {
			return (EEXIST);
		}
	}

	err = fuse_getvnode(FUSE_NULL_ID, &vp, VNODE_CACHED,
	    0, sep, dvp->v_vfsp, namelen, name, VNODE_TO_NODEID(dvp), credp);

	if (err) {
		/*
		 * This means, we have never seen this directory before, so
		 * we don't have its vnode, just send the message to daemon
		 */
		if (err == ENOENT) {
			goto sendmsg;
		} else {
			/* This shouldn't occur */
			DTRACE_PROBE3(fuse_rmdir_err_getvnode,
			    char *, "getvnode returned error",
			    int, err, uint64_t, FUSE_NULL_ID);
			return (err);
		}
	}
	ASSERT(vp != NULL);

	/*
	 * XXX: We have no way to know if cwd is subdir of dvp as we do not
	 * maintain the dir tree in kernel
	 */

	if (vp == cwd || vp == dvp) {
		err = EINVAL;
		goto out;
	}

	if (vp->v_type != VDIR) {
		err = ENOTDIR;
		goto out;
	}

	if (vn_vfswlock(vp)) {
		err = EBUSY;
		goto out;
	}

	if (vn_mountedvfs(vp)) {
		vn_vfsunlock(vp);
		err = EBUSY;
		goto out;
	}

sendmsg:
	msgp = fuse_setup_message(namelen, FUSE_RMDIR, VNODE_TO_NODEID(dvp),
	    credp, FUSE_GET_UNIQUE(sep));

	(void *) strlcpy(msgp->ipdata.indata, name, namelen);

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* We got woken up, so fuse library has replied to our Lookup request */
	/* Check for any error from fuse library */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_rmdir_err_rmdir_req,
		    char *, "FUSE_RMDIR request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}
	if (vp) {
		/*
		 * If all went well, we don't need this vnode any more so
		 * we will get rid of it
		 */
		/*
		 * XXX: This call releases vnode with vn_free, can this
		 * be an issue? Or does VN_RELE do the required job for us?
		 */
		fuse_vnode_free(vp, sep);
		vp = NULL;
	}

#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(dvp);
#endif

cleanup:
	fuse_free_msg(msgp);
out:	if (vp)
		VN_RELE(vp);
	return (err);
}

/*
 * the (OpenSolaris)devfs prototype was used in this func.
 *
 * - any create fails if the node doesn't exist - EROFS.
 * - creating an existing directory read-only succeeds, otherwise EISDIR.
 * - exclusive creates fail if the node already exists - EEXIST.
 * - failure to create the snode for an existing device - ENOSYS.
 */
/*
 * Attempt to create a new entry in a directory. If the entry
 * already exists, truncate the file if permissible, else return
 * an error. Return the vp of the created or trunc'd file.
 *
 *	IN:	dvp	- vnode of directory to put new file entry in.
 *		name	- name of new file entry.
 *		vap	- attributes of new file.
 *		excl	- flag indicating exclusive or non-exclusive mode.
 *		mode	- mode to open file with.
 *		cr	- credentials of caller.
 *		flag	- creat() param is passed here [filemode &
 *                        ~(FTRUNC|FEXCL)]
 *
 *	OUT:	vpp	- vnode of created or trunc'd entry.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated if new entry created
 *	 vp - ctime|mtime always, atime if new
 */
/* ARGSUSED */
static int
fuse_create(struct vnode *dvp, char *nm, struct vattr *vap, vcexcl_t excl,
    int mode, struct vnode **vpp, struct cred *cred_p, int flag,
    caller_context_t *ct, vsecattr_t *va)
{
	struct fuse_vnode_data *fvdata;
	uint32_t stringlen;

	if (!nm || *nm == '\0') {
		DTRACE_PROBE2(fuse_create_err_invalid_name,
		    char *, "Invalid filename", char *, nm);
		return (EEXIST);
	}

	if (vap->va_type == VDIR) {
		return (VOP_MKDIR(dvp, nm, vap, vpp, cred_p, ct, 0, va));
	}

	if (vap->va_type != VREG) {
		DTRACE_PROBE2(fuse_create_err_invalid_type,
		    char *, "Invalid file type",
		    struct vattr *, vap);
		return (EINVAL);
	}

	/*
	 * We follow the approach as in FreeBSD Fuse and provide atomic
	 * create + open. So this create method for a regular file doesn't send
	 * a request to user space fuse lib, rather its done in the open method
	 */
	*vpp = fuse_create_vnode(dvp->v_vfsp, FUSE_NULL_ID,
	    VNODE_TO_NODEID(dvp), vap->va_type, FILE_CREATE_OP);
	fvdata = (struct fuse_vnode_data *)(*vpp)->v_data;

	/* Copy the needed parameters, to be used in open() */
	crhold(cred_p);
	fvdata->fcd->credp	= cred_p;
	fvdata->fcd->flag	= flag;
	fvdata->fcd->mode	= MAKEIMODE(vap->va_type, vap->va_mode);
	fvdata->fcd->par_nodeid	= VNODE_TO_NODEID(dvp);
	stringlen		= strlen(nm) + 1;

	/* Be cautious against any possible attacks */
	if (stringlen > MAXNAMELEN) {
		stringlen = MAXNAMELEN;
	}

	fvdata->fcd->namelen	= stringlen;
	fvdata->fcd->name	= kmem_alloc(stringlen, KM_SLEEP);
	(void *) strlcpy(fvdata->fcd->name, nm, stringlen);
#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(dvp);
#endif

	return (0);
}

/*
 * This function consumes directory entries sent by Fuse library in the form
 * of fuse_direct structures. It creates equivalent dirent64 entries which is
 * the form expected by Solaris Kernel. The logic of this function is similar
 * to FreeBSD Fuse function fuse_dir_buffeater()
 */
/* ARGSUSED */
static int
fuse_cons_dir(struct uio *uiop, size_t reqsize, void *buf, size_t bufsize,
    void *arg)
{
	struct dirent64 *de;
	struct fuse_dirent *fudge;
	int err = 0;
	size_t freclen;
	int cou = 0;
	unsigned short bytesavail;
	struct fuse_iov iov, *iovp = &iov;

	ASSERT(bufsize <= reqsize);

	/*
	 * Sanity check: if this fails, we would overrun the allocated space
	 * upon entering the loop below, so we'd better leave right now.
	 * If so, we return -1 to terminate reading.
	 */
	if (bufsize < FUSE_NAME_OFFSET)
		return (-1);

	/*
	 * We preallocate a buffer of maximum dirent size so that we don't have
	 * to frequently free and alloc again.
	 */
	fuse_buf_alloc(iovp, MAX_DENTRY64_SIZE);

	de = (struct dirent64 *)iovp->base;
	/*
	 * The following piece of code is from FreeBSD Fuse with slight
	 * modification
	 */
	/*
	 * Can we avoid infite loops? An infinite loop could occur only if we
	 * leave this function with 0 return value, because otherwise we wont't
	 * be called again. But both 0 exit points imply that some data has
	 * been consumed... because
	 *   1) if a turn is not aborted, it consumes positive amount of data
	 *   2) the 0 jump-out from within the loop can't occur in the first
	 *	  turn
	 *   3) if we exit 0 after the loop is over, then at least one turn
	 *	  was completed, otherwise we hed exited above with -1.
	 */

	for (;;) {
		if (bufsize < FUSE_NAME_OFFSET) {
			err = -1;
			break;
		}

		cou++;
		fudge = (struct fuse_dirent *)buf;
		freclen = FUSE_DIRENT_SIZE(fudge);

		/*
		 * Here is an exit condition: we terminate the whole reading
		 * process if a fresh chunk of buffer is already too short to
		 * cut out an entry.
		 * (It it was not the first turn in the loop, nevermind,
		 * return with asking for more)
		 */
		if (bufsize < freclen) {
			err = ((cou == 1) ? -1 : 0);
			break;
		}

		/* Sanity checks */
		if (!fudge->namelen || fudge->namelen > MAXNAMELEN) {
			DTRACE_PROBE2(fuse_cons_dir_err_invalid_name,
			    char *, "Invalid name length",
			    struct fuse_dirent *, fudge);
			err = EIO;
			break;
		}

		bytesavail = DIRENT64_RECLEN(fudge->namelen);

		/*
		 * Exit condition 2: if the pretended amount of input is more
		 * than that the userspace wants, then it's time to stop
		 * reading.
		 */
		if (bytesavail > uiop->uio_resid) {
			err = -1;
			break;
		}

		/*
		 * Verify if size allocated is sufficient for this record, if
		 * not allocate as much as we need
		 */
		if (bytesavail > iovp->memsize) {
			kmem_free(iovp->base, iovp->memsize);
			fuse_buf_alloc(iovp, bytesavail);
		}

		de = (struct dirent64 *)iovp->base;

		de->d_ino = fudge->ino;
		de->d_reclen = bytesavail;
		(void *) memcpy((char *)iovp->base + DENTRY64_NAME_OFFSET,
		    (char *)buf + FUSE_NAME_OFFSET, fudge->namelen);

		((char *)iovp->base)[DENTRY64_NAME_OFFSET + fudge->namelen] =
		    '\0';

		err = uiomove(iovp->base, bytesavail, UIO_READ, uiop);

		if (err)
			break;

		buf = (char *)buf + freclen;
		bufsize -= freclen;

		uiop->uio_loffset = fudge->off;
	}

	return (err);
}

/*
 * This function performs a generic read by sending repeated requests to the
 * fuse library and waiting for a response until the desired amount of data
 * is not obtained. It invokes the call back function initialized by the caller
 * after every response from the fuse library, which in turn consumes the data
 * The logic of this function is similar to FreeBSD Fuse function:
 * fuse_direct_backend()
 */
static int
fuse_perform_read(struct fuse_io_data *fiodata)
{
	struct vnode		*vp = fiodata->vp;
	struct fuse_file_handle *fh = fiodata->fh;
	struct uio 		*uiop = fiodata->uiop;
	cred_t 			*credp = fiodata->credp;
	enum fuse_opcode 	op = fiodata->op;
	fuse_consfunc_t		*consfunc = fiodata->consfunc;
	void			*arg = fiodata->arg;
	fuse_msg_node_t		*msgp;
	fuse_session_t		*sep;
	struct fuse_read_in	*fri;
	int			err = 0;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_perform_read_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	if (uiop->uio_resid == 0)
		return (0);

	msgp = fuse_setup_message(sizeof (*fri), op,
	    VNODE_TO_NODEID(vp), credp, FUSE_GET_UNIQUE(sep));

	while (uiop->uio_resid > 0) {

		/* Set up arguments to the fuse library */
		fri = (struct fuse_read_in *)msgp->ipdata.indata;
		fri->fh = fh->fh_id;
		fri->offset = uiop->uio_offset;
		fri->size = MIN(uiop->uio_resid,
		    PAGESIZE * FUSE_MAX_PAGES_PER_REQ);

		if ((err = fuse_queue_request_wait(sep, msgp))) {
			goto cleanup;
		}

		/* We got woken up, so fuse lib has replied to our request */
		if ((err = msgp->opdata.fouth->error) != 0) {
			DTRACE_PROBE2(fuse_perform_read_err_read_req,
			    char *, "FUSE_READ request failed",
			    struct fuse_out_header *, msgp->opdata.fouth);
			goto cleanup;
		}

		if ((err = consfunc(uiop, fri->size, msgp->opdata.iovbuf.base,
		    msgp->opdata.outsize, arg)))
			break;

		/* Refresh the message node if necessary */
		if (uiop->uio_resid)
			fuse_msg_recreate(msgp, sizeof (*fri), op,
			    VNODE_TO_NODEID(vp), credp,
			    FUSE_GET_UNIQUE(sep), 0);
	}

cleanup:
	fuse_free_msg(msgp);
	return ((err == -1) ? 0 : err);
}

/* ARGSUSED */
static int
fuse_readdir(struct vnode *dvp, struct uio *uiop, struct cred *cred_p,
    int *eof_p, caller_context_t *ct, int flags)
{
	int err = 0;
	struct fuse_file_handle *fh = NULL;
	struct fuse_io_data fiodata;

	if (uiop->uio_loffset < 0 || uiop->uio_resid <= 0)
		return (ENOENT);

	if (uiop->uio_iovcnt != 1)
		return (EINVAL);

	if (dvp->v_type != VDIR)
		return (ENOTDIR);
	/*
	 * the readdir() libc is called in a loop, the syscall readdir calls
	 * getdent64 [usr/src/uts/common/syscall/getdents.c#190] getdents64()
	 * takes first param as fd, from which it gets the File pointer and
	 * getsvnode from it. This vnode's call back is mapped to this
	 * filesystem, thus this function gets called. The function getdents64()
	 * passes the last offset in uio_loffset, which we must check to figure
	 * out if EOF has been reached. It ignores the last eof pointer and
	 * instead figures out that EOF has reached if uio_resid has not been
	 * changed.
	 */
#if 0 /* TBD: Verify if this is needed */
	if ((uiop->uio_loffset != 0) && (uiop->uio_loffset >=
	    ((fuse_vnode_data_t *)dvp->v_data)->fileh.fh_offset)) {
		if (eof_p)
			*eof_p = 1;
		return (0);
	}
#endif

	/* Get File handle by checking through the cached file handle list */
	if ((err = get_filehandle(dvp, FREAD, cred_p, &fh, CACHE_LIST_CHECK))) {
		DTRACE_PROBE2(fuse_readdir_err_filehandle,
		    char *, "get_filehandle failed",
		    struct vnode *, dvp);
		goto out;
	}

	if (!fh) {
		DTRACE_PROBE2(fuse_readdir_err_filehandle,
		    char *, "get_filehandle returned NULL handle",
		    struct vnode *, dvp);
		return (EIO);
	}

	fh->ref++;

	/* setup fuse i/o data structure */
	fiodata.uiop = uiop;
	fiodata.credp = cred_p;
	fiodata.vp = dvp;
	fiodata.fh = fh;
	fiodata.op = FUSE_READDIR;
	fiodata.consfunc = fuse_cons_dir;

	err = fuse_perform_read(&fiodata);
	fh->ref--;
#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(dvp);
#endif
out:
	return (err);
}

/*
 * Check if the source vnode is in the path to the target directory
 */
static int
fuse_path_check(struct vnode *svp, struct vnode *tdvp, struct cred *credp)
{
	struct vnode *vp = tdvp;
	struct vnode *par_vp = NULL;
	fuse_session_t *sep;
	int err = 0;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_path_check_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	for (;;) {
		/*
		 * if the current vnode under investigation is same as the
		 * source vnode then return error since source is above the
		 * target in the path
		 */
		if (VNODE_TO_NODEID(vp) == VNODE_TO_NODEID(svp)) {
			err = EINVAL;
			break;
		}
		if (VNODE_TO_NODEID(vp) == FUSE_ROOT_ID) {
			break;
		}
		if ((VTOFD(vp)->par_nid != FUSE_NULL_ID)) {
			/*
			 * Try finding the parent vnode, this call
			 * also sets the hold on the vnode
			 */
			err = fuse_getvnode(VTOFD(vp)->par_nid, &par_vp,
			    VNODE_CACHED, VDIR, sep, vp->v_vfsp, 0, NULL,
			    FUSE_NULL_ID, credp);
			/*
			 * We don't seem to have the parent vnode cached, since
			 * we can't know who the parent is, even the daemon
			 * can't help us, so return error.
			 */
			if (err == ENOENT) {
				DTRACE_PROBE2(fuse_path_check_err_parent,
				    char *, "Parent vnode not found",
				    struct vnode *, vp);
				vp = NULL;
				/*
				 * XXX: Is this the right error no to return?
				 */
				err = EINVAL;
				break;
			} else if (err) {
				DTRACE_PROBE3(fuse_path_check_err_getvnode,
				    char *, "fuse_getvnode returned error",
				    int, err, uint64_t, VTOFD(vp)->par_nid);
				vp = NULL;
				break;
			}
			/* Release our hold on the currently looked up dir */
			if (vp != tdvp) {
				VN_RELE(vp);
			}
			/* Start checking from this directory onwards */
			vp = par_vp;
		}
	}
	/* Release hold if any */
	if (vp && vp != tdvp)
		VN_RELE(vp);

	return (err);
}

/* This function interacts with the daemon for rename operation */
static int
fuse_rename_i(struct vnode *sdvp, char *oldname, struct vnode *tdvp,
    char *newname, struct cred *credp)
{
	struct fuse_rename_in *fri;
	fuse_session_t *sep;
	fuse_msg_node_t *msgp;
	char *strptr;
	int err = 0;
	int old_namelen = strlen(oldname) + 1;
	int new_namelen = strlen(newname) + 1;

	if (old_namelen > MAXNAMELEN || new_namelen > MAXNAMELEN)
		return (ENAMETOOLONG);

	sep = fuse_minor_get_session(getminor(sdvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_rename_i_err_session,
		    char *, "failed to find session",
		    struct vnode *, sdvp);
		return (ENODEV);
	}

	msgp = fuse_setup_message((sizeof (*fri) + old_namelen + new_namelen),
	    FUSE_RENAME, VNODE_TO_NODEID(sdvp), credp, FUSE_GET_UNIQUE(sep));

	/* Set up the arguments required by the daemon */
	fri = (struct fuse_rename_in *)msgp->ipdata.indata;
	fri->newdir = VNODE_TO_NODEID(tdvp);
	/* Copy the old and new name */
	strptr = (char *)fri + sizeof (*fri);
	(void) memcpy(strptr, oldname, old_namelen);
	strptr += old_namelen;
	(void) memcpy(strptr, newname, new_namelen);

	err = fuse_queue_request_wait(sep, msgp);
	fuse_free_msg(msgp);
	return (err);
}

/*
 * Move an entry from the provided source directory to the target
 * directory. (comment & func. prtotype copies from zfs)
 *
 *	IN:	sdvp	- Source directory containing the "old entry".
 *		oldname	- Old entry name.
 *		tdvp	- Target directory to contain the "new entry".
 *		newname	- New entry name.
 *		credp	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	sdvp, tdvp - ctime|mtime updated
 */
/* ARGSUSED */
static int
fuse_rename(vnode_t *sdvp, char *oldname, vnode_t *tdvp, char *newname,
    cred_t *credp,  caller_context_t *ct, int flags)
{
	int err = EIO;
	int samedir;
	struct vnode *svp = NULL;
	struct vnode *tvp = NULL;


	/* Try obtaining the source vnode by doing a lookup */
	err = fuse_lookup_i(sdvp, oldname, &svp, credp);

	if (err)
		return (err);

	/*
	 * Make sure we can delete the old (source) entry.  This
	 * requires write permission on the containing directory.  If
	 * that directory is "sticky" it requires further checks.
	 */
	if (((err = fuse_access_i((void *)sdvp, VWRITE, credp)) != 0) ||
	    (err = fuse_sticky_remove_access(sdvp, svp, credp, ct)) != 0) {
		goto errout;
	}

	/*
	 * Check for renaming to or from '.' or '..'
	 */
	if ((oldname[0] == '.' &&
	    (oldname[1] == '\0' || (oldname[1] == '.' &&
	    oldname[2] == '\0'))) ||
	    (newname[0] == '.' &&
	    (newname[1] == '\0' || (newname[1] == '.' &&
	    newname[2] == '\0'))) ||
	    (sdvp == svp)) {
		err = EINVAL;
		goto errout;
	}

	samedir = (sdvp == tdvp);

	/*
	 * Make sure we can search and rename into the new
	 * (destination) directory.
	 */
	if (!samedir) {
		err = fuse_access_i((void *)tdvp, VEXEC|VWRITE, credp);
		if (err)
			goto errout;
	}
	/*
	 * If we are trying to move a directory, then make sure there is
	 * no pathname conflicts, i.e. make sure the source is not above the
	 * target in the path
	 */
	if (svp->v_type == VDIR && !samedir) {
		if ((err = fuse_path_check(svp, tdvp, credp))) {
			goto errout;
		}
	}

	/* Try doing a lookup for the target name */
	if ((err = fuse_lookup_i(tdvp, newname, &tvp, credp))) {
		if (err != ENOENT) {
			goto errout;
		} else {
			err = 0;
		}
	}
	/*
	 * if the target exists, then validate if src and target are
	 * of compatible type so that target directory can be rewritten to
	 * point to src
	 */
	if (tvp) {
		if ((tvp->v_type == VDIR && svp->v_type != VDIR) ||
		    (tvp->v_type != VDIR && svp->v_type == VDIR)) {
			err = ENOTDIR;
			goto errout;
		}
	}
	/* Inform daemon to handle the rename operation */
	if ((err = fuse_rename_i(sdvp, oldname, tdvp, newname, credp)))
		goto errout;

errout:
	if (svp)
		VN_RELE(svp);
	if (tvp)
		VN_RELE(tvp);
	return (err);
}

/* ARGSUSED */
static int
fuse_fsync(struct vnode *vp, int syncflag, struct cred *credp,
    caller_context_t *ct)
{
	int err;
	struct fuse_fh_param fh_param;

	/* XXX: Do locking related logic here */

	/* Flush out any dirty pages associated with this vnode */
	if (vn_has_cached_data(vp) && !(syncflag & FNODSYNC) &&
	    (vp->v_type != VCHR)) {
		err = VOP_PUTPAGE(vp, (offset_t)0, (size_t)0, 0, credp, ct);
		if (err)
			return (err);
	}
	/*
	 * We will iterate through all the file handles associated with this
	 * vnode and send FUSE_FSYNC/FUSE_FSYNCDIR. See comment in FreeBSD
	 * Fuse fsync implementation for more information
	 */
	fh_param.vp = vp;
	fh_param.credp = credp;
	fh_param.rw_mode = FWRITE;
	fh_param.fufh = NULL;
	(void) iterate_filehandle(vp, fuse_fsync_fh, &fh_param, NULL);

	return (0);
}

/*
 * This function sends FUSE_FSYNC/FUSE_FSYNCDIR on the passed
 * file handle associated with the concerned vnode
 */
static int
fuse_fsync_fh(struct fuse_file_handle *fhp, struct fuse_fh_param *param)
{
	struct fuse_fsync_in *ffsi;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;
	enum fuse_opcode op = (param->vp->v_type == VDIR) ? FUSE_FSYNCDIR :
	    FUSE_FSYNC;

	sep = fuse_minor_get_session(getminor(param->vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_fsync_fh_err_session,
		    char *, "failed to find session",
		    struct vnode *, param->vp);
		return (ENODEV);
	}

	msgp = fuse_setup_message(sizeof (*ffsi), op,
	    VNODE_TO_NODEID(param->vp), param->credp, FUSE_GET_UNIQUE(sep));
	ffsi = (struct fuse_fsync_in *)msgp->ipdata.indata;
	ffsi->fh = fhp->fh_id;
	/* We want to sync file data and not just metadata */
	ffsi->fsync_flags = 1;

	(void) fuse_queue_request_wait(sep, msgp);

	fuse_free_msg(msgp);
	/*
	 * Since this is called from iterate_filehandle() we will not return
	 * obtained err if any. This is to ensure that all the file handles
	 * in the list are serviced.
	 */
	return (0);
}

/* ARGSUSED */
static int
fuse_seek(struct vnode *vp, offset_t ooff, offset_t *noffp,
    caller_context_t *ct)
{
	return ((*noffp < 0 || *noffp > MAXOFFSET_T) ? EINVAL : 0);
}

/*
 * Remove an entry from a directory.
 *
 *	IN:	dvp	- vnode of directory to remove entry from.
 *		name	- name of entry to remove.
 *		credp	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime
 *	 vp - ctime (if nlink > 0)
 */
/* ARGSUSED */
static int
fuse_remove(vnode_t *dvp, char *name, cred_t *credp, caller_context_t *ct,
    int flags)
{
	int err;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;
	int namelen = strlen(name) + 1;
	struct vnode *vp = NULL;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_remove_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	msgp = fuse_setup_message(namelen, FUSE_UNLINK,
	    VNODE_TO_NODEID(dvp), credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	(void) memcpy(msgp->ipdata.indata, name, namelen - 1);
	((char *)msgp->ipdata.indata)[namelen - 1] = '\0';

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* Check if we have seen and cached the associated vnode */
	err = fuse_getvnode(FUSE_NULL_ID, &vp, VNODE_CACHED,
	    0, sep, dvp->v_vfsp, namelen, name, VNODE_TO_NODEID(dvp), credp);

	if (err) {
		if (err == ENOENT) {
			/*
			 * This means, we don't have this vnode, so
			 * there is nothing else to do, just reset the error
			 * and return.
			 */
			err = 0;
		}
		goto cleanup;
	}
	ASSERT(vp != NULL);
	/*
	 * Destroy the vnode, but we can't go through the sane way of
	 * destroying the vnode which involves sending FUSE_FORGET message
	 * to the daemon, flushing dirty data and so on. All this is a bit
	 * too heavy weight when we don't have to care about this vnode any
	 * more. So we just free all associated memory with this vnode and
	 * return it to kernel.
	 */
	/*
	 * XXX: This call releases vnode with vn_free, can this
	 * be an issue? Or does VN_RELE do the required job for us?
	 */
	fuse_vnode_free(vp, sep);
cleanup:
	fuse_free_msg(msgp);
	return (err);
}

/*
 * This function does the release of all the associated
 * memory with the passed vnode
 */
static inline void
fuse_vnode_free(struct vnode *vp, fuse_session_t *sep)
{
	struct fuse_file_handle *fhp;
	struct fuse_vnode_data *fvdatap = VTOFD(vp);

	if (VTOFD(vp)) {
		mutex_enter(&fvdatap->fh_list_lock);
		for (fhp = list_head(&fvdatap->fh_list); fhp;
		    fhp = list_next(&fvdatap->fh_list, fhp)) {
			list_remove(&fvdatap->fh_list, fhp);
			kmem_free(fhp, sizeof (*fhp));
		}
		mutex_exit(&fvdatap->fh_list_lock);
		fuse_vnode_cache_remove(vp, sep);
		fuse_free_vdata(vp);
	}
	vp->v_data = NULL;

	vn_free(vp);
}
/*
 * Insert the indicated symbolic reference entry into the directory.
 *
 *	IN:	dvp	- Directory to contain new symbolic link.
 *		name	- Name for new symlink entry.
 *		vap	- Attributes of new entry.
 *		target	- Target path of new symlink.
 *		cr	- credentials of caller.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	dvp - ctime|mtime updated
 */
/* ARGSUSED */
static int
fuse_symlink(vnode_t *dvp, char *name, vattr_t *vap, char *target,
    cred_t *credp,  caller_context_t *ct, int flags)
{
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;
	int err = DDI_SUCCESS;
	int namelen = strlen(name) + 1;
	int targlen = strlen(target) + 1;
	struct vnode *vp;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_symlink_err_session,
		    char *, "failed to find session",
		    struct vnode *, dvp);
		return (ENODEV);
	}

	msgp = fuse_setup_message(namelen + targlen, FUSE_SYMLINK,
	    VNODE_TO_NODEID(dvp), credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	(void) memcpy(msgp->ipdata.indata, name, namelen - 1);
	((char *)msgp->ipdata.indata)[namelen - 1] = '\0';
	(void) memcpy((char *)msgp->ipdata.indata + namelen, target,
	    targlen - 1);
	((char *)msgp->ipdata.indata)[namelen + targlen - 1] = '\0';

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto cleanup;
	}

	/* We got woken up, so fuse lib has replied to our release request */
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_symlink_err_symlink_req,
		    char *, "FUSE_SYMLINK request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}


	err = fuse_add_entry(&vp, dvp, msgp, sep, name, namelen, credp, VLNK);

cleanup:
	fuse_free_msg(msgp);
	return (err);
}
/*
 * Return, in the buffer contained in the provided uio structure,
 * the symbolic path referred to by vp.
 *
 *	IN:	vp	- vnode of symbolic link.
 *		uoip	- structure to contain the link path.
 *		cr	- credentials of caller.
 *
 *	OUT:	uio	- structure to contain the link path.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 * Timestamps:
 *	vp - atime updated
 */
/* ARGSUSED */
static int
fuse_readlink(vnode_t *vp, uio_t *uiop, cred_t *cred_p, caller_context_t *ct)
{
	int err = DDI_SUCCESS;
	fuse_msg_node_t *msgp;
	fuse_session_t *sep;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_readlink_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	msgp = fuse_alloc_msg();

	/*
	 * setup the message with only header and no arguments to be sent to
	 * fuse library
	 */
	setup_msg_onlyheader(msgp, FUSE_READLINK, FUSE_GET_UNIQUE(sep),
	    VNODE_TO_NODEID(vp), cred_p);


	if ((err = fuse_queue_request_wait(sep, msgp))) {
		goto out;
	}

	err = msgp->opdata.fouth->error;

	if (!err) {
		err = uiomove(msgp->opdata.outdata, msgp->opdata.outsize,
		    UIO_READ, uiop);
	} else {
		DTRACE_PROBE2(fuse_readlink_err_readlink_req,
		    char *, "FUSE_READLINK request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
	}

#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(vp);
#endif

out:
	fuse_free_msg(msgp);
	return (err);
}

/*
 * Sends the FUSE_FORGET message to daemon which performs the necessary
 * cleanup
 */
static void
fuse_send_forget(uint64_t nodeid, fuse_session_t *sep, uint64_t nlookup)
{
	fuse_msg_node_t *msgp;
	struct fuse_forget_in *ffi;

	msgp = fuse_setup_message(sizeof (*ffi), FUSE_FORGET,
	    nodeid, sep->usercred, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	ffi = (struct fuse_forget_in *)msgp->ipdata.indata;
	ffi->nlookup = nlookup;

	/* Send the request to the fuse daemon and return */
	fuse_queue_request_nowait(sep, msgp);
}

/*
 * Returns the file size associated with the passed vnode, if needed contacts
 * the daemon
 */
static int
fuse_getfilesize(struct vnode *vp, u_offset_t *fsize, struct cred *credp)
{
	int err;
	struct vattr va;
	fuse_msg_node_t *msgp;

	/* Provide, if the updated file size is available with us */
	if (VTOFD(vp)->file_size_status & FSIZE_UPDATED) {
		*fsize = VTOFD(vp)->fsize;
		DTRACE_PROBE2(fuse_getfilesize_info_cache,
		    char *, "returning file size from cache",
		    u_offset_t, *fsize);
		return (0);
	}
#ifndef DONT_CACHE_ATTRIBUTES
	/*
	 * Next step is to check if the attribute cache is valid, if so
	 * no need to ask the daemon for the file size
	 */
	timestruc_t ts;
	gethrestime(&ts);
	if (ATTR_CACHE_VALID(ts, VTOFD(vp)->cached_attrs_bound)) {
		*fsize = VTOFD(vp)->cached_attrs.va_size;
		DTRACE_PROBE2(fuse_getfilesize_info_attr_cache,
		    char *, "returning file size from attr cache",
		    u_offset_t, *fsize);
		return (0);
	}
#endif
	/* We are not lucky, have to get file size from daemon */
	err = fuse_getattr_from_daemon(vp, &va, credp, &msgp);

	if (err)
		return (err);

#ifndef DONT_CACHE_ATTRIBUTES
	cache_attrs(vp, (struct fuse_attr_out *)(msgp->opdata.outdata));
#endif
	*fsize = va.va_size;
	DTRACE_PROBE2(fuse_getfilesize_info_daemon,
	    char *, "returning file size from daemon",
	    u_offset_t, *fsize);

	fuse_free_msg(msgp);
	return (err);
}

/* Performs the mapping of a page to kernel virtual address space */
static void
fuse_page_mapin(struct vnode *vp, struct buf **bp, struct page *pp, size_t len,
    int flag, struct fuse_iov *iovp)
{

	/* Map the page into kernel virtual memory */
	*bp = pageio_setup(pp, len, vp, flag);
	ASSERT((*bp) != NULL);

	(*bp)->b_edev = 0;
	(*bp)->b_dev = 0;
	(*bp)->b_lblkno = 0;
	(*bp)->b_file = vp;
	(*bp)->b_offset = 0;

	bp_mapin((*bp));

	iovp->memsize = len;
	iovp->len = 0;
	iovp->memflag = MEM_TYPE_PAGE;
	iovp->base = (*bp)->b_un.b_addr;

}

/*
 * Free storage space associated with the specified vnode. The portion
 * to be freed is specified by bfp->l_start and bfp->l_len (already
 * normalized to a "whence" of 0).
 *
 * This is an experimental facility whose continued existence is not
 * guaranteed.  Currently, we only support the special case
 * of l_len == 0, meaning free to end of file.
 */
/* ARGSUSED */
static int
fuse_space(vnode_t *vp, int cmd, struct flock64 *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int error;

	if (cmd != F_FREESP)
		return (EINVAL);

	ASSERT(vp->v_type == VREG);

	error = convoff(vp, bfp, 0, offset);
	if (error == 0) {
		ASSERT(bfp->l_start >= 0);

		if (bfp->l_len == 0) {
			vattr_t va;

			va.va_mask = AT_SIZE;
			error = VOP_GETATTR(vp, &va, 0, cr, ct);
			if (error || va.va_size == bfp->l_start) {
				/*
				 * do not update ctime/mtime if truncate
				 * to previous size, just exit
				 */
				return (error);
			}
			va.va_mask = AT_SIZE;
			va.va_size = bfp->l_start;
			error = VOP_SETATTR(vp, &va, 0, cr, ct);
		}
		else
			error = EINVAL;
	}

	return (error);
}

/* ARGSUSED */
static int
fuse_putapage(vnode_t *vp, page_t *pp, u_offset_t *offp,
    size_t *lenp, int flags, cred_t *credp)
{
	fuse_session_t *sep;
	u_offset_t fsize;
	int err, diff;
	struct fuse_write_in *fwi;
	struct fuse_write_out *fwo;
	struct fuse_file_handle *fhp = NULL;
	fuse_msg_node_t *msgp = NULL;
	struct buf *bp = NULL;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_putapage_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return (ENODEV);
	}

	if ((err = get_filehandle(vp, FWRITE, credp, &fhp, CACHE_LIST_CHECK))) {
		DTRACE_PROBE2(fuse_putapage_err_filehandle,
		    char *, "get_filehandle failed",
		    struct vnode *, vp);
		goto cleanup;
	}
	if ((err = fuse_getfilesize(vp, &fsize, credp))) {
		DTRACE_PROBE3(fuse_putapage_err_file_size,
		    char *, "fuse_getfilesize failed",
		    int, err, struct vnode *, vp);
		goto cleanup;
	}
	msgp = fuse_setup_message(sizeof (*fwi),
	    FUSE_WRITE, VTOFD(vp)->nodeid, credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	fwi = (struct fuse_write_in *)msgp->ipdata.indata;

	fwi->fh = fhp->fh_id;
	fwi->offset = pp->p_offset;
	fwi->size = (uint32_t)MIN(PAGESIZE, fsize - pp->p_offset);
	/*
	 * XXX:There is a lot of room for optimization here, we can do
	 * page klustering and then create a scatter gather list
	 * of pages and their addresses to be used by device read
	 */

	/* Map this page in to kernel virtual address space */
	fuse_page_mapin(vp, &bp, pp, PAGESIZE, B_WRITE,
	    &(msgp->ipdata.iovbuf[1]));
	msgp->ipdata.iovbuf[1].len = fwi->size;
	msgp->ipdata.iovs_used = 2;

	if ((err = fuse_queue_request_wait(sep, msgp)) != 0) {
		goto cleanup;
	}

	if ((err = msgp->opdata.fouth->error) !=  0) {
		DTRACE_PROBE2(fuse_putapage_err_write_req,
		    char *, "FUSE_WRITE request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}
	fwo = (struct fuse_write_out *)msgp->opdata.outdata;
	diff = fwi->size - fwo->size;
	if (diff < 0) {
		err = EINVAL;
		goto cleanup;
	}
	if (diff > 0) {
		/*
		 * This means daemon could do only a partial write, we
		 * currently don't manage the hassles of handling partial
		 * write with possibly partial dirty pages, so we treat
		 * as an error
		 */
		DTRACE_PROBE2(fuse_putapage_err_short_write,
		    char *, "daemon executed partial write ",
		    struct fuse_write_out *, fwo);
		err = EIO;
		goto cleanup;
	}
cleanup:
	if (fhp)
		fhp->ref--;
	if (err) {
		flags |= B_ERROR;
	} else {
		if (lenp)
			*lenp = fwi->size;
	}

	if (bp != NULL) {
		bp_mapout(bp);
		pageio_done(bp);
	}
	if (msgp != NULL)
		fuse_free_msg(msgp);

	(void) pvn_write_done(pp, B_WRITE | flags);

	return (err);
}

/*
 * If len == 0, do from off to EOF.
 *
 * The normal cases should be len == 0 & off == 0 (entire vp list),
 * len == MAXBSIZE (from segmap_release actions), and len == PAGESIZE
 * (from pageout).
 */
/* ARGSUSED */
static int
fuse_putpage(struct vnode *vp, offset_t off, size_t len, int flags,
	struct cred *credp, caller_context_t *ct)
{
	register page_t *pp;
	int err = 0;
	size_t io_len = 0;
	u_offset_t fsize = 0;
	u_offset_t io_off;
	u_offset_t eoff;

	if (vp->v_count == 0) {
		DTRACE_PROBE2(fuse_putpage_err_vcount,
		    char *, "vnode v_count == 0",
		    struct vnode *, vp);
		return (EAGAIN);
	}

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (!vn_has_cached_data(vp))
		return (0);

	if (len == 0) {
		err = pvn_vplist_dirty(vp, (u_offset_t)off, fuse_putapage,
		    flags, credp);
	} else {
		if ((err = fuse_getfilesize(vp, &fsize, credp))) {
			DTRACE_PROBE3(fuse_putpage_err_filesize,
			    char *, "fuse_getfilesize failed",
			    int, err, struct vnode *, vp);
			return (err);
		}

		eoff = MIN(off + len, fsize);

		for (io_off = off; io_off < eoff; io_off += io_len) {
			/*
			 * If we are not invalidating, synchronously
			 * freeing or writing pages use the routine
			 * page_lookup_nowait() to prevent reclaiming
			 * them from the free list.
			 */
			if ((flags & B_INVAL) || ((flags & B_ASYNC) == 0)) {
				pp = page_lookup(vp, io_off,
				    (flags & (B_INVAL | B_FREE)) ?
				    SE_EXCL : SE_SHARED);
			} else {
				pp = page_lookup_nowait(vp, io_off,
				    (flags & B_FREE) ? SE_EXCL : SE_SHARED);
			}

			if (pp == NULL || pvn_getdirty(pp, flags) == 0) {
				io_len = PAGESIZE;
			} else {
				err = fuse_putapage(vp, pp, &io_off, &io_len,
				    flags, credp);
				if (err != 0)
					break;
			}
		}
	}
	/* If invalidating, verify all pages on vnode list are gone. */
	if (err == 0 && off == 0 && len == 0 &&
	    (flags & B_INVAL) && vn_has_cached_data(vp)) {
		panic("fuse_putpage: B_INVAL, pages not gone");
	}
	/*
	 * If all the dirty pages was written back, remove the file size changed
	 * status flag
	 */
	if (len == 0 || eoff == fsize) {
		(void) fsize_change_notify(vp, 0, FSIZE_NOT_RELIABLE);
	}
	return (err);
}

/* ARGSUSED */
static int
fuse_map(vnode_t *vp, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    cred_t *cr, caller_context_t *ct)
{
	struct segvn_crargs vn_a;
	int error;

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (off < (offset_t)0 || (offset_t)(off + len) < (offset_t)0)
		return (ENXIO);

	if (vp->v_type != VREG)
		return (ENODEV);

	/*
	 * XXX: If file is being locked, disallow mapping.
	 */

	as_rangelock(as);
	error = choose_addr(as, addrp, len, off, ADDR_VACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		goto out;
	}

	vn_a.vp = vp;
	vn_a.offset = off;
	vn_a.type = (flags & MAP_TYPE);
	vn_a.prot = prot;
	vn_a.maxprot = maxprot;
	vn_a.cred = cr;
	vn_a.amp = NULL;
	vn_a.flags = (flags & ~MAP_TYPE);
	vn_a.szc = 0;
	vn_a.lgrp_mem_policy_flags = 0;

	error = as_map(as, *addrp, len, segvn_create, &vn_a);
	as_rangeunlock(as);

out:
	return (error);
}

/* ARGSUSED */
static int
fuse_addmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uchar_t prot, uchar_t maxprot, uint_t flags,
    cred_t *cr, caller_context_t *ct)
{
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	mutex_enter(&VTOFD(vp)->f_lock);
	VTOFD(vp)->f_mapcnt += btopr(len);
	mutex_exit(&VTOFD(vp)->f_lock);

	return (0);
}

/* ARGSUSED */
static int
fuse_delmap(vnode_t *vp, offset_t off, struct as *as, caddr_t addr,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags,
    cred_t *cr, caller_context_t *ct)
{
	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	mutex_enter(&VTOFD(vp)->f_lock);
	VTOFD(vp)->f_mapcnt -= btopr(len);
	mutex_exit(&VTOFD(vp)->f_lock);

	if ((flags & MAP_SHARED) && (prot & PROT_WRITE) &&
	    vn_has_cached_data(vp))
		(void) VOP_PUTPAGE(vp, off, len, B_ASYNC, cr, ct);

	return (0);
}

static void
fuse_vnode_cache_remove(struct vnode *vp, fuse_session_t *sep)
{
	avl_index_t where;
	fuse_avl_cache_node_t discard, *removep;

	discard.facn_nodeid = VNODE_TO_NODEID(vp);
	if ((removep = avl_find(& (sep->avl_cache), &discard, &where))
	    != NULL) {
		avl_remove(&(sep->avl_cache), removep);
		fuse_avl_cache_node_destroy(removep);
	}
}

/* Does all the necessary cleanup w.r.t a vnode */
static void
fuse_vnode_cleanup(struct vnode *vp, struct cred *credp, fuse_session_t *sep)
{
	struct fuse_fh_param fh_param;
	/* Invalidate pages while flushing out any dirty data */
	if (vn_has_cached_data(vp)) {
		(void) pvn_vplist_dirty(vp, 0, fuse_putapage, B_FREE, credp);
	}
	/* Release if the vnode has any file handles with it */
	if (VTOFD(vp)) {
		fh_param.vp = vp;
		fh_param.flag = FUSE_FORCE_FH_RELEASE;
		(void) iterate_filehandle(vp, fuse_release_fh, &fh_param, NULL);
	}
	/* Let daemon know that we are getting rid of this vnode */
	fuse_send_forget(VNODE_TO_NODEID(vp), sep, (VTOFD(vp))->nlookup);

	/* Finally its time to remove it from our cache */
	fuse_vnode_cache_remove(vp, sep);
}

/* ARGSUSED */
static void
fuse_inactive(struct vnode *vp, struct cred *credp, caller_context_t *ct)
{
	struct fuse_fh_param fh_param;
	fuse_session_t *sep;

	fh_param.vp = vp;
	fh_param.flag = 0;

	sep = fuse_minor_get_session(getminor(vp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_inactive_err_session,
		    char *, "failed to find session",
		    struct vnode *, vp);
		return;
	}

	(void) iterate_filehandle(vp, fuse_release_fh, &fh_param, NULL);

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		return;
	}
	mutex_exit(&vp->v_lock);
#ifndef FLUSH_DATA_ON_VNODE_RELEASE

	/*
	 * We don't free any pages associated with this vnode, nor do we
	 * remove it from the AVL tree
	 */
	return;
#else
	if (!(vp->v_flag & VROOT)) {
		fuse_vnode_destroy(vp, credp, sep);
	}
#endif
}

static int
fuse_add_entry(struct vnode **vpp, struct vnode *dvp, fuse_msg_node_t *msgp,
    fuse_session_t *sep, char *name, int namelen, cred_t *credp, vtype_t vtype)
{
	int err = DDI_SUCCESS;
	struct fuse_entry_out *feo =
	    (struct fuse_entry_out *)msgp->opdata.outdata;

	if ((err = checkentry(feo, vtype))) {
		return (err);
	}

	err = fuse_getvnode(feo->nodeid, vpp, VNODE_NEW,
	    IFTOVT(feo->attr.mode), sep, dvp->v_vfsp, namelen, name,
	    VNODE_TO_NODEID(dvp), credp);

	if (err) {
		DTRACE_PROBE3(fuse_add_entry_err_getvnode,
		    char *, "fuse_getvnode returned error",
		    int, err, uint64_t, feo->nodeid);
		fuse_send_forget(feo->nodeid, sep, 1);
		return (err);
	}
#ifndef DONT_CACHE_ATTRIBUTES
	invalidate_cached_attrs(dvp);
	cache_attrs((*vpp), feo);
#endif
	return (err);
}

/*
 * Create a new directory and insert it into dvp using the name
 * provided. Return a pointer to the inserted directory.
 *
 *	IN:	dvp	- vnode of directory to add subdir to.
 *		dirname	- name of new directory.
 *		vap	- attributes of new directory.
 *		cr	- credentials of caller.
 *
 *	OUT:	vpp	- vnode of created directory.
 *
 *	RETURN:	0 if success
 *		error code if failure
 *
 */
/* ARGSUSED */
static int
fuse_mkdir(vnode_t *dvp, char *dirname, vattr_t *vap, vnode_t **vpp,
    cred_t *credp, caller_context_t *ct, int flags, vsecattr_t *vsecp)
{
	struct fuse_mkdir_in *fmkdi;
	fuse_msg_node_t *msgp;
	int err = 0;
	fuse_session_t *sep;
	int namelen;

	sep = fuse_minor_get_session(getminor(dvp->v_rdev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_mkdir_err_session,
		    char *, "failed to find session",
		    struct vnode *, dvp);
		return (ENODEV);
	}

	namelen = strlen(dirname) + 1;
	if (namelen > MAXNAMELEN) {
		return (ENAMETOOLONG);
	}

	msgp = fuse_setup_message((sizeof (*fmkdi) + namelen),
	    FUSE_MKDIR, VTOFD(dvp)->nodeid, credp, FUSE_GET_UNIQUE(sep));

	/* Set up arguments to the fuse library */
	fmkdi = (struct fuse_mkdir_in *)msgp->ipdata.indata;

	fmkdi->mode = MAKEIMODE(vap->va_type, vap->va_mode);
	(void *) strlcpy(((char *)msgp->ipdata.indata + sizeof (*fmkdi)),
	    dirname, namelen);

	if ((err = fuse_queue_request_wait(sep, msgp)) != 0) {
		goto cleanup;
	}
	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_mkdir_err_mkdir_req,
		    char *, "FUSE_MKDIR request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		goto cleanup;
	}
	err = fuse_add_entry(vpp, dvp, msgp, sep, dirname, namelen, credp,
	    VDIR);
cleanup:
	fuse_free_msg(msgp);
	return (err);
}
