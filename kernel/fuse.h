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

#ifndef _FUSE_H
#define	_FUSE_H

#include <sys/kmem.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include "fuse_kernel.h"
#include "fuse_queue.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define	FUSE_DEV_DESCRIPTION "fuse driver"
#define	FUSE_DEV_TYPE "fuse"
#define	FUSE_FS_DESCRIPTION "filesystem for fuse"
#define	FUSE_FS_TYPE "fuse"

/* Used for fuse_create_vnode() to identify if it's invoked during create op */
#define	OTHER_OP	0
#define	FILE_CREATE_OP	1

/*
 * Used to indicate whether to scan the cached list of filehandles while
 * retrieving a file handle
 */
#define	CACHE_LIST_NO_CHECK 0
#define	CACHE_LIST_CHECK 1

#define	FUSE_NULL_ID	0

#define	FSIZE_UPDATED		0x1	/* File size modifed by write */
#define	FSIZE_NOT_RELIABLE	0x2	/* Cached file size might be invalid */

#define	FUSE_FORCE_FH_RELEASE	0x1	/* force release of filehandle */

/* Defines way to retrieve fuse_vnode_data_t associated with the vnode */
#define	VTOFD(vp)	((fuse_vnode_data_t *)(vp)->v_data)

/* From FreeBSD Fuse, used to keep track of open files */
typedef struct fuse_file_handle {
	list_node_t	fh_link;
	uint64_t	fh_id;
	pid_t		process_id;
	int		mode;
	int		flags;
	int		ref;
	cred_t		*credp;
	struct file 	*filep;
} fuse_file_handle_t;

struct fuse_fh_param {
	struct vnode *vp;
	cred_t *credp;
	struct fuse_file_handle *fufh;
	int rw_mode;
	int flag;
};

/* used to save arguments passed to fuse_fs_create */
struct fuse_create_data {
	uint64_t par_nodeid;
	cred_t	*credp;
	int	flag;
	int	mode;
	char	*name;
	int	namelen;
};

struct fuse_filehandle {
	uint64_t fh_id;
	offset_t fh_offset; /* 64 bits */
	int mode;
};

typedef struct fuse_vnode_data {
	list_t fh_list;
	kmutex_t fh_list_lock;

	uint64_t nodeid;
	uint64_t nlookup;
	uint64_t par_nid;

	struct fuse_file_handle fh;
	struct fuse_create_data *fcd;

#ifndef DONT_CACHE_ATTRIBUTES
	struct vattr cached_attrs;
	struct timespec cached_attrs_bound;
#endif
	size_t fsize;	/* temp place holder when file size gets modified */
	int file_size_status; /* indicates if cached file size is valid */

	kmutex_t f_lock; /* serializes write/setattr requests */
	long f_mapcnt;	/* mappings to file pages */
	/*
	 * This field will be eventually removed as we complete
	 * rewriting the implementation. It is still here so that the code
	 * compiles.
	 */
	struct fuse_filehandle fileh;
} fuse_vnode_data_t;

/* Get nodeid from the struct vnode */
#define	VNODE_TO_NODEID(vp)	((struct fuse_vnode_data *)vp->v_data)->nodeid
/*
 * Max number of pages that can be used in a single read request
 * (used in FreeBSD Fuse)
 */
#define	FUSE_MAX_PAGES_PER_REQ	32

/*
 * TBD: Should we do it like FreeBSD Fuse, where minimum size of 128 bytes
 * is allocated?
 */
#define	FUSE_BUF_ADJUST_SIZE(len)	(len)

/* TBD: Should this be made atomic? */
#define	FUSE_GET_UNIQUE(se_p)	(++se_p->unique)

#define	DENTRY64_NAME_OFFSET	(offsetof(dirent64_t, d_name[0]))

#define	MAX_DENTRY64_SIZE	(((DENTRY64_NAME_OFFSET) + \
	(MAXNAMELEN) + 7) & ~ 7)

/* convert from FREAD/FWRITE to O_RDONLY/O_WRONLY */
#define	F_TO_O_FLAGS(flags)	((flags) - 1)

typedef enum memory_type {
	MEM_NOT_ALLOCATED	= 0,
	MEM_TYPE_PAGE,
	MEM_TYPE_KMEM
} mem_type;

typedef enum vnode_getmode {
	VNODE_ANY,
	VNODE_CACHED,
	VNODE_NEW
} v_getmode;

/* This structure is obtained from FreeBSD version of Fuse */
struct fuse_iov {
	void	*base;		/* Pointer to allocated memory */
	size_t	memsize;	/* Size of allocated memory */
	size_t	len;		/* Size of available data */
	mem_type memflag;	/* Flag indicating the memory type */
};

#define	FUSE_MAX_IOV	3

/* This defines the data passed to the fuse daemon from the kernel module */
struct fuse_data_in {
	struct fuse_in_header *finh;	/* header for the message passed */
	void *indata;			/* pointer to start of arguments */
	size_t iosize;			/* size occupied by args in the msg */
	int iovs_used;			/* Number of iovbufs used */
	uint64_t nodeid;		/* Node ID referred in this operation */
	struct fuse_iov iovbuf[FUSE_MAX_IOV]; /* Buffer storing header + args */
};

/* This defines the data passed from the fuse daemon to the kernel module */
struct fuse_data_out {
	struct fuse_out_header *fouth;	/* header for the message passed from */
					/* the fuse daemon */
	void *outdata;			/* pointer to start of arguments */
	size_t outsize;			/* size occupied by arguments */
	struct fuse_iov iovbuf;		/* Buffer storing arguments */
};

typedef	int fuse_consfunc_t(struct uio *uiop, size_t reqsize, void *buf,
    size_t bufsize, void *arg);

/* From FreeBSD Fuse, used for an I/O operation b/w daemon and kernel module */
struct fuse_io_data {
	struct vnode		*vp;
	struct uio		*uiop;
	struct fuse_file_handle	*fh;
	enum fuse_opcode	op;
	fuse_consfunc_t		*consfunc;
	cred_t			*credp;
	void			*arg;
};

/* Extern Declarations */
extern vnodeops_t *dv_vnodeops;
extern vnodeops_t *temp_vnodeops;
extern const fs_operation_def_t fuse_vnodeops_template[];
extern const fs_operation_def_t temp_vnodeops_template[];

/* Function prototype */
void fuse_buf_alloc(struct fuse_iov *iov, size_t len);
struct vnode *fuse_create_vnode(vfs_t *vfsp, uint64_t nodeid, uint64_t par_nid,
    int type, int iscreate);

#ifdef	__cplusplus
}
#endif

#endif	/* _FUSE_H */
