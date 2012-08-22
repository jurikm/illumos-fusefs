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

/*
 * This file has been derived from OpenSolaris devfs and others in uts/common/fs
 */
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/vfs.h>
#include <sys/fs_subr.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/cred.h>
#include <sys/cred_impl.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/policy.h>
#include <sys/modctl.h>
#include <sys/mntent.h>
#include <sys/vfs.h>

#include <sys/fs/namenode.h>
#include <sys/mount.h>
#include <sys/strsubr.h>
#include <sys/sdt.h>

#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include "fuse_queue.h"
#include "fuse.h"

/* It could be as large as PATH_MAX, but would that have any uses? */
#define	FUSE_NAME_MAX 1024

/*
 * devfs vfs operations.
 */
static int fuse_mount(struct vfs *, struct vnode *, struct mounta *,
    struct cred *);
static int fuse_unmount(struct vfs *, int, struct cred *);
static int fuse_root(struct vfs *, struct vnode **);
static int fuse_statvfs(struct vfs *, struct statvfs64 *);

static int fuse_init(int fstype, char *name);

typedef struct fuse_vfs_data {
	vnode_t *vfs_root_vnode;
} fuse_vfs_data_t;

extern struct mod_ops mod_fsops;
static int devfstype;		/* fstype */
vnodeops_t *dv_vnodeops;
vnodeops_t *temp_vnodeops;	/* Used during create operation */


static mntopt_t fuse_options[] = {
	{ "fd",		NULL,	NULL,	MO_NODISPLAY|MO_HASVALUE,	NULL},
};

static mntopts_t fuse_opttbl = {
	sizeof (fuse_options) / sizeof (mntopt_t),
	fuse_options
};
static vfsdef_t fuse_vfw = {
	VFSDEF_VERSION,
	FUSE_FS_TYPE,
	fuse_init,
	VSW_HASPROTO,
	&fuse_opttbl
};

struct modlfs fuse_vfs_modldrv = {
	&mod_fsops, FUSE_FS_DESCRIPTION, &fuse_vfw
};

static int fuse_init(int fstype, char *name)
{
	int error = DDI_SUCCESS;

	static const fs_operation_def_t fuse_vfsops_template[] = {
		VFSNAME_MOUNT,   { .vfs_mount = fuse_mount },
		VFSNAME_UNMOUNT, { .vfs_unmount = fuse_unmount },
		VFSNAME_ROOT,    { .vfs_root = fuse_root },
		VFSNAME_STATVFS, { .vfs_statvfs = fuse_statvfs },
		VFSNAME_SYNC,    { .vfs_sync = fs_sync },
		NULL, NULL
	};

	/* TODO: associate the FUSE device here? */
	devfstype = fstype;
	/*
	 * Associate VFS ops vector with this fstype
	 */
	error = vfs_setfsops(fstype, fuse_vfsops_template, NULL);
	if (error != 0) {
		DTRACE_PROBE2(fuse_init_err_setops,
		    char *, "vfs_setfsops failed",
		    int, error);
		return (error);
	}

	error = vn_make_ops(name, fuse_vnodeops_template, &dv_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		DTRACE_PROBE2(fuse_init_err_makeops,
		    char *, "vn_make_ops failed for dv_vnodeops",
		    int, error);
		return (error);
	}

	error = vn_make_ops(name, temp_vnodeops_template, &temp_vnodeops);
	if (error != 0) {
		(void) vfs_freevfsops_by_type(fstype);
		DTRACE_PROBE2(fuse_init_err_makeops,
		    char *, "vn_make_ops failed for temp_vnodeops",
		    int, error);
		vn_freevnodeops(dv_vnodeops);
		dv_vnodeops = NULL;
		return (error);
	}

	return (error);
}

struct vnode *
fuse_create_vnode(vfs_t *vfsp, uint64_t nodeid, uint64_t parent_nid, int type,
    int iscreate)
{
	struct vnode *vp;
	struct fuse_vnode_data *vdata;

	/*
	 * Allocate vnode and internal data structure
	 */
	vdata = kmem_zalloc(sizeof (fuse_vnode_data_t), KM_SLEEP);

	vp = vn_alloc(KM_SLEEP);
	/*
	 * Set up various pointers
	 */

	vp->v_data = vdata;
	vdata->nodeid = nodeid;
	vdata->par_nid = parent_nid;

	/* Create the list for storing file handles */
	list_create(&vdata->fh_list, sizeof (fuse_file_handle_t),
	    offsetof(fuse_file_handle_t, fh_link));

	mutex_init(&vdata->fh_list_lock, NULL, MUTEX_DEFAULT, (void *) NULL);
	mutex_init(&vdata->f_lock, NULL, MUTEX_DEFAULT, (void *) NULL);

	/*
	 * Initialize vnode and hold parent.
	 * If we are invoked during create operation, allocate memory for
	 * storing create related data arguments.
	 */
	if (iscreate) {
		vn_setops(vp, temp_vnodeops);
		vdata->fcd = kmem_zalloc(
		    sizeof (struct fuse_create_data), KM_SLEEP);
	} else {
		vn_setops(vp, dv_vnodeops);
	}

	VFS_HOLD(vfsp);
	VN_SET_VFS_TYPE_DEV(vp, vfsp, type, vfsp->vfs_dev);
	vp->v_flag |= VNOSWAP | VNOMOUNT;

	return (vp);
}

/* -------------------------- VFS related ---------------------------------- */


static struct vnode *
fuse_get_root_node(vfs_t *vfsp)
{
	struct vnode *vp = fuse_create_vnode(vfsp, FUSE_ROOT_ID,
	    FUSE_NULL_ID, VDIR, OTHER_OP);
	vp->v_flag |= VROOT;
	return (vp);
}

static void
fuse_process_init_msg(fuse_session_t *sep, fuse_msg_node_t *msg_p)
{
	struct fuse_init_out *foutarg;

	if (msg_p->opdata.fouth->error) {
		DTRACE_PROBE2(fuse_process_init_msg_err_init_req,
		    char *, "FUSE_INIT request failed",
		    struct fuse_out_header *, msg_p->opdata.fouth);
		fuse_session_umount(sep);
	} else {
		if (msg_p->opdata.outsize != sizeof (struct fuse_init_out)) {
			DTRACE_PROBE2(fuse_process_init_msg_err_size,
			    char *, "FUSE_INIT reply wrong size",
			    struct fuse_data_out *, &msg_p->opdata);
			fuse_session_umount(sep);
		} else {
			foutarg = (struct fuse_init_out *)
			    msg_p->opdata.iovbuf.base;
			if (foutarg->major < 7) {
				DTRACE_PROBE2(fuse_process_init_msg_err_version,
				    char *, "FUSE_INIT reply wrong version",
				    struct fuse_init_out *, foutarg);
				fuse_session_umount(sep);
			}
			sep->max_write = foutarg->max_write;

		}
	}
	fuse_free_msg(msg_p);
}

/*
 * Function which sends FUSE_INIT message to the fuse library.
 * FUSE_INIT cannot fail. The response is not waited for so that
 * mount(2) can return immediately.
 */
static int
fuse_send_mounted_notice(fuse_session_t *se_p)
{
	struct fuse_init_in *finitarg;
	fuse_msg_node_t *msg_p = NULL;

	msg_p = fuse_setup_message(sizeof (*finitarg), FUSE_INIT,
	    FUSE_ROOT_ID, se_p->usercred, FUSE_GET_UNIQUE(se_p));

	/* Set up arguments to the fuse library */
	finitarg = (struct fuse_init_in *)msg_p->ipdata.indata;
	finitarg->major = FUSE_KERNEL_VERSION;
	finitarg->minor = FUSE_KERNEL_MINOR_VERSION;

	msg_p->frd_on_request_complete = fuse_process_init_msg;
	fuse_queue_request_nowait(se_p, msg_p);

	return (0);
}


static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}


/* Taken from NFS code: usr/src/stand/lib/fs/nfs/mount.c */

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')
#define	bad(val)	(val == NULL || !isdigit(*val))

static int
atoi(const char *p)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
		case '-':
			neg++;
			/* FALLTHROUGH */
		case '+':
			c = *++p;
		}
		if (!isdigit(c))
			return (0);
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	return (neg ? n : -n);
}

/*
 * Given a filedescriptor as a string return the associated
 * device.
 */
static dev_t
fuse_str_to_dev(char *fdstr)
{
	dev_t dev = 0;
	struct file *fp;
	int fd = atoi(fdstr);
	if ((fp = getf(fd)) != 0) {
		dev = fp->f_vnode->v_rdev;
		releasef(fd);
	}
	return (dev);
}

static int
fuse_mount(struct vfs *vfsp, struct vnode *mvp, struct mounta *uap,
    struct cred *cr)
{
	fuse_vfs_data_t	 *vfsdata;
	fuse_session_t	 *se;
	dev_t dev;
	char *fdstr;
	int err;

	if (secpolicy_fs_mount(cr, mvp, vfsp) != 0)
		return (EPERM);

	if (mvp->v_type != VDIR)
		return (ENOTDIR);

	if ((uap->flags & MS_OVERLAY) == 0 &&
	    (mvp->v_count != 1 || (mvp->v_flag & VROOT)))
		return (EBUSY);

	if (vfs_optionisset(vfsp, "fd", &fdstr)) {
		dev = fuse_str_to_dev(fdstr);
	} else {
		return (ENXIO);
	}

	vfsdata = kmem_alloc(sizeof (fuse_vfs_data_t), KM_SLEEP);

	/*
	 * Initialize vfs fields
	 */
	/* TODO: what should be set here? PAGE_CACHE_SIZE; */
	vfsp->vfs_bsize = 512;
	vfsp->vfs_fstype = devfstype;

	vfsp->vfs_data = vfsdata;
	vfsp->vfs_dev = dev;

	vfs_make_fsid(& vfsp->vfs_fsid, vfsp->vfs_dev, devfstype);

	/* Create root */
	((struct fuse_vfs_data *)vfsdata)->vfs_root_vnode =
	    fuse_get_root_node(vfsp);

	/*
	 * The session associated with this device should have been allocated
	 * when fuse_dev_open was called.
	 */
	se = fuse_minor_get_session(getminor(dev));
	if (se == NULL) {
		DTRACE_PROBE2(fuse_mount_err_session,
		    char *, "failed to find session",
		    dev_t, dev);
		return (ENXIO);
	}

	fuse_session_set_cred(se, cr);
	fuse_session_set_vfs(se, vfsp);
	se->mounted = 1;
	err = fuse_send_mounted_notice(se);

	return (err);
}

static int
fuse_unmount(struct vfs *vfsp, int flag, struct cred *crp)
{
	fuse_vfs_data_t *data;
	fuse_session_t *fsep;

	if (secpolicy_fs_unmount(crp, vfsp) != 0)
		return (EPERM);

	/*
	 * We do not currently support forced unmounts
	 */
	if (flag & MS_FORCE)
		return (ENOTSUP);

	/*
	 * We should never have a reference count of less than 2: one for the
	 * caller, one for the root vnode.
	 */
	/* ASSERT(vfsp->vfs_count >= 2); */

	/*
	 * Any active vnodes will result in a hold on the root vnode
	 */
	data = vfsp->vfs_data;
	if (data->vfs_root_vnode->v_count != 1)
		return (EBUSY);

	/*
	 * Release the last hold on the root vnode
	 */
	VN_RELE(data->vfs_root_vnode);

	kmem_free(data, sizeof (fuse_vfs_data_t));

	/* Clean-up the session */
	fsep = fuse_minor_get_session(getminor(vfsp->vfs_dev));

	if (fsep != NULL) {
		fuse_destroy_cache(fsep);
		/* Mark the filesystem as unmounted */
		fsep->mounted = 0;

		/*
		 * Wake the fuselib reader so it can exit and clean
		 * up the session
		 */
		sema_v(&(fsep->session_sema));
	} else {
		DTRACE_PROBE2(fuse_unmount_info_session,
		    char *, "failed to find session",
		    dev_t, vfsp->vfs_dev);
	}

	return (DDI_SUCCESS);
}

/* This code is similar to UFS implementation */
static int fuse_root(struct vfs *vfsp, struct vnode **vpp)
{
	fuse_vfs_data_t	*data;
	int err = DDI_SUCCESS;

	if (!vfsp)
		err = EIO;

	if (!err) {
		data = (fuse_vfs_data_t *)vfsp->vfs_data;
		if (!data || !data->vfs_root_vnode)
			err = (EIO);
	}

	if (!err) {
		*vpp = data->vfs_root_vnode;
		VN_HOLD(*vpp);
	}

	return (err);
}

static int
fuse_statvfs(struct vfs *vfsp, struct statvfs64 *sp)
{
	int err = 0;
	struct fuse_statfs_out *fso = NULL;
	fuse_msg_node_t	*msgp = NULL;
	fuse_session_t *sep = NULL;

	(void) bzero(sp, sizeof (*sp));

	if (vfsp->vfs_flag & VFS_UNMOUNTED)
		return (EIO);

	sep = fuse_minor_get_session(getminor(vfsp->vfs_dev));
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_statvfs_err_session,
		    char *, "failed to find session",
		    dev_t, vfsp->vfs_dev);
		return (ENODEV);
	}

	msgp = fuse_setup_message(0, FUSE_STATFS, 0, sep->usercred,
	    FUSE_GET_UNIQUE(sep));

	if ((err = fuse_queue_request_wait(sep, msgp))) {
		return (err);
	}

	if ((err = msgp->opdata.fouth->error) != 0) {
		DTRACE_PROBE2(fuse_statvfs_err_statfs_req,
		    char *, "FUSE_STATFS request failed",
		    struct fuse_out_header *, msgp->opdata.fouth);
		fuse_free_msg(msgp);
		return (err);
	}

	if (msgp->opdata.outsize != sizeof (struct fuse_statfs_out)) {
		DTRACE_PROBE2(fuse_statvfs_err_size,
		    char *, "FUSE_STATFS reply wrong size",
		    struct fuse_data_out *, &msgp->opdata);
		err = EINVAL;
	} else {
		fso = msgp->opdata.outdata;

		sp->f_bsize = fso->st.bsize;
		sp->f_blocks = fso->st.blocks;
		sp->f_bfree = fso->st.bfree;
		sp->f_files = fso->st.files;
		sp->f_ffree = fso->st.ffree;
		sp->f_favail = fso->st.ffree;
		sp->f_bavail = fso->st.bavail;
		sp->f_namemax = fso->st.namelen;

		sp->f_frsize = fso->st.frsize ? fso->st.frsize : fso->st.bsize;


		(void) strlcpy(sp->f_basetype, vfssw[vfsp->vfs_fstype].vsw_name,
		    sizeof (sp->f_basetype));

		DTRACE_PROBE2(fuse_statvfs_info_statvfs,
		    char *, "FUSE_STATFS reply",
		    struct statvfs64 *, sp);
	}
	fuse_free_msg(msgp);
	return (err);
}
