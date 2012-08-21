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


#include <sys/devops.h>	/* used by dev_ops */
#include <sys/conf.h>	/* used by dev_ops and cb_ops */
#include <sys/modctl.h>	/* used by modlinkage, modldrv, _init, _info, */
			/* and _fini */
#include <sys/types.h>	/* used by open, close, read, write, prop_op, */
			/* and ddi_prop_op */
#include <sys/file.h>	/* used by open, close */
#include <sys/errno.h>	/* used by open, close, read, write */
#include <sys/open.h>	/* used by open, close, read, write */
#include <sys/cred.h>	/* used by open, close, read */
#include <sys/uio.h>	/* used by read */
#include <sys/stat.h>	/* defines S_IFCHR used by ddi_create_minor_node */
#include <sys/ddi.h>	/* used by all entry points for this driver */
			/* also used by cb_ops, ddi_get_instance, and */
			/* ddi_prop_op */
#include <sys/sunddi.h> /* used by all entry points for this driver */
			/* also used by cb_ops, ddi_create_minor_node, */
			/* ddi_get_instance, and ddi_prop_op */


#include <sys/atomic.h>	/* used for debugging, added atomic counter */

extern struct modldrv fuse_dev_drv_modldrv;
extern struct modlfs fuse_vfs_modldrv;
extern void fuse_global_init();
extern void fuse_global_fini();

/*
 * Fuse kernel module has a char device as well as a filesystem.
 * modlinkage structure:
 */
static struct modlinkage ml = {
	MODREV_1,
	&fuse_dev_drv_modldrv,
	&fuse_vfs_modldrv,
	NULL
};

/* Loadable module configuration entry points */
int
_init(void)
{
	int rv;

	fuse_global_init();
	if ((rv = mod_install(&ml)) != 0) {
		fuse_global_fini();
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&ml)) == 0) {
		fuse_global_fini();
	}
	return (rv);
}
