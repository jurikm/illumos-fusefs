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
 * Skeleton code Derived from Solaris DDK tutorial
 */

#include <sys/devops.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pathname.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <sys/mkdev.h>
#include <sys/inttypes.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include "fuse_queue.h"
#include "fuse.h"

static int fuse_dev_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int fuse_dev_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int fuse_dev_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int fuse_dev_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);


static int fuse_dev_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int fuse_dev_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int fuse_dev_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int fuse_dev_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int fuse_dev_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp);

/* cb_ops structure */
static struct cb_ops fuse_dev_cb_ops = {
	fuse_dev_open,
	fuse_dev_close,
	nodev,	/* no strategy - nodev returns ENXIO */
	nodev,	/* no print */
	nodev,	/* no dump */
	fuse_dev_read,
	fuse_dev_write,
	nodev,	/* no ioctl */
	nodev,	/* no devmap */
	nodev,	/* no mmap */
	nodev,	/* no segmap */
	fuse_dev_poll,
	fuse_dev_prop_op,
	NULL,	/* streamtab struct; if not NULL, all above */
		/* fields are ignored */
	D_NEW | D_MP,	/* compatibility flags: see conf.h */
	CB_REV,	/* cb_ops revision number */
	nodev,	/* no aread */
	nodev	/* no awrite */
};
/* dev_ops structure */
static struct dev_ops fuse_dev_ops = {
	DEVO_REV,
	0,	/* reference count */
	fuse_dev_getinfo,
	nulldev,	/* no identify - nulldev returns 0 */
	nulldev,	/* no probe */
	fuse_dev_attach,
	fuse_dev_detach,
	nodev,		/* no reset - nodev returns ENXIO */
	&fuse_dev_cb_ops,
	(struct bus_ops *)NULL,
	nodev		/* no power */
};
/* modldrv structure */
struct modldrv fuse_dev_drv_modldrv = {
	&mod_driverops,	/* Type of module. This is a driver. */
	FUSE_DEV_DESCRIPTION,	/* Name of the module. */
	&fuse_dev_ops
};

/* dev_info structure */
static dev_info_t *fuse_dip;   /* keep track of one instance */

extern fuse_session_t *fuse_alloc_session();


/* Device autoconfiguration entry points */
static int
fuse_dev_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_ATTACH:
			fuse_dip = dip;
			/* S_IFBLK */
			if (ddi_create_minor_node(dip, "fuse", S_IFCHR,
			    ddi_get_instance(dip), DDI_PSEUDO, 0)
			    != DDI_SUCCESS) {
				DTRACE_PROBE2(fuse_dev_attach_err_create_node,
				    char *, "Error creating minor node",
				    dev_info_t *, dip);
				return (DDI_FAILURE);
			} else {
				return (DDI_SUCCESS);
			}
		default:
			return (DDI_FAILURE);
	}
}

static int
fuse_dev_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
		case DDI_DETACH:
/* TODO: check if all sessions are closed before detaching */
			fuse_dip = 0;
			ddi_remove_minor_node(dip, NULL);
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
fuse_dev_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
void **resultp)
{
	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			*resultp = fuse_dip;
			return (DDI_SUCCESS);
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = 0;
			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}
}

static int
fuse_dev_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

/* Use context entry points */
/* ARGSUSED */
static int
fuse_dev_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	fuse_session_t *fs;
	minor_t minor;

	/* see: pg 154 Writing Device Drivers - May 2002 */
	fs = fuse_alloc_session();
	if (fs == NULL)
		return (DDI_FAILURE);
	fuse_init_session(fs);
	minor = fuse_session_get_minor(fs);

	*devp = makedevice(getmajor(*devp), minor);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
fuse_dev_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	minor_t ndx = getminor(dev);
	fuse_session_t *sep = fuse_minor_get_session(ndx);

	if (sep == NULL) {
		DTRACE_PROBE2(fuse_dev_close_err_session,
		    char *, "failed to find session",
		    dev_t, dev);
		return (ENODEV);
	}

	if (sep->mounted) {
		fuse_session_umount(sep);
	}

	fuse_deinit_session(sep);
	fuse_free_session(sep);

	/* TODO: check if this session has no pending request before de-init */
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
fuse_dev_poll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	short revent = 0;
	minor_t ndx = getminor(dev);
	fuse_session_t *sep = fuse_minor_get_session(ndx);

	if (sep == NULL) {
		DTRACE_PROBE2(fuse_dev_poll_err_session,
		    char *, "failed to find session",
		    dev_t, dev);
		revent = POLLERR;
	} else {
		if (!(sep->mounted)) {
			revent = (POLLERR | POLLHUP);
		}
	}
	*reventsp = revent;

	return (0);
}

/* ARGSUSED */
static int
fuse_dev_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	minor_t ndx = getminor(dev);
	fuse_msg_node_t *msgp = NULL;
	fuse_session_t *sep;
	int err = DDI_SUCCESS;
	int i;

	sep = fuse_minor_get_session(ndx);
	if (sep == NULL) {
		DTRACE_PROBE2(fuse_dev_read_err_session,
		    char *, "failed to find session",
		    dev_t, dev);
		return (ENODEV);
	}

	if (sema_p_sig(& (sep->session_sema)) == 1) {
		/* We got unblocked because of a signal, so return */
		DTRACE_PROBE2(fuse_dev_read_err_signal,
		    char *, "Woke up due to pending signal",
		    fuse_session_t *, sep);
		return (ENODEV);
	}

	/*
	 * See if the filesystem has been unmounted. If an unmount occurred
	 * the session should be cleared up and ENODEV should be returned to
	 * fuselib to indicate unmount.
	 */
	if (!(sep->mounted)) {
		return (ENODEV);
	}

	FUSE_SESSION_MUTEX_LOCK(sep);

	for (msgp = list_head(&sep->msg_list); msgp;
	    msgp = list_next(&(sep->msg_list), msgp)) {
		if (msgp->fmn_state == FUSE_MSG_STATE_QUEUE) {
			msgp->fmn_state = FUSE_MSG_STATE_READ;
			break;
		}
	}
	FUSE_SESSION_MUTEX_UNLOCK(sep);
	if (msgp == NULL) {
		DTRACE_PROBE2(fuse_dev_read_err_msgp,
		    char *, "No message found on session msg_list",
		    fuse_session_t *, sep);
		return (DDI_FAILURE);
	}

	/*
	 * This is not supposed to function as a seekable device. To prevent
	 * offset from growing and eventually exceed the maximum, reset the
	 * offset here for every call.
	 */
	uiop->uio_loffset = 0;

	DTRACE_PROBE2(msg_read, struct fuse_in_header *, msgp->ipdata.finh,
	    void *, msgp->ipdata.indata);

	/*
	 * For each of the iovbufs which is used try copying data to buffer
	 * provided by daemon
	 */
	for (i = 0; i < msgp->ipdata.iovs_used; i++) {
		/*
		 * Check if there is enough room to copy all data from this
		 * iovbuf
		 */
		if (uiop->uio_resid < msgp->ipdata.iovbuf[i].len) {
			DTRACE_PROBE2(fuse_dev_read_err_no_space,
			    char *, "Buffer too small for request data",
			    fuse_session_t *, sep);
			err = ENODEV;
			break;
		}
		err = uiomove(msgp->ipdata.iovbuf[i].base,
		    msgp->ipdata.iovbuf[i].len, UIO_READ, uiop);
		if (err)
			break;
	}

	return (err);
}

/*
 * This function is from FreeBSD version of Fuse. It validates the header sent
 * by the fuse library. It converts any error value sent by the fuse library
 * to positive, since thats how it is understood inside the Solaris kernel
 */
static int
fuse_ohead_audit(struct fuse_out_header *ohead, struct uio *uio)
{
	if (uio->uio_resid + sizeof (struct fuse_out_header) != ohead->len) {
		DTRACE_PROBE3(fuse_ohead_audit_err_header,
		    char *, "Invalid length in header",
		    struct uio *, uio,
		    struct fuse_out_header *, ohead);
		return (EINVAL);
	}

	if (uio->uio_resid && ohead->error) {
		DTRACE_PROBE3(fuse_ohead_audit_err_format,
		    char *, "Non zero error with message body",
		    struct uio *, uio,
		    struct fuse_out_header *, ohead);
		return (EINVAL);
	}

	/* Sanitize the linuxism of negative errnos */
	ohead->error = -(ohead->error);

	return (0);
}

/* ARGSUSED */
static int
fuse_dev_write(dev_t dev, struct uio *uiop, cred_t *cred_p)
{
	int err = DDI_FAILURE;
	struct fuse_out_header *outh;
	fuse_session_t *se_p;
	fuse_msg_node_t *msg_p = NULL;
	minor_t ndx = getminor(dev);
	struct fuse_iov *iovbuf;

	if (uiop->uio_resid < sizeof (struct fuse_out_header)) {
		DTRACE_PROBE2(fuse_dev_write_err_response_length,
		    char *, "response length less than header size.",
		    struct uio *, uiop);
		return (EINVAL);
	}

	/* Allocate memory for the header part of the message */
	outh = kmem_alloc(sizeof (struct fuse_out_header), KM_SLEEP);

	/*
	 * This is not supposed to function as a seekable device. To prevent
	 * offset from growing and eventually exceed the maximum, reset the
	 * offset here for every call.
	 */
	uiop->uio_loffset = 0;

	/* If we are unable to copy the data, then free the allocated memory */
	if ((err = uiomove(outh, sizeof (struct fuse_out_header), UIO_WRITE,
	    uiop)) != 0)
		goto cleanup;

	/*
	 * Verify if the header is valid, this code is similar to FreeBSD
	 * version of Fuse
	 */
	if ((err = fuse_ohead_audit(outh, uiop)))
		goto cleanup;


	se_p = fuse_minor_get_session(ndx);
	if (se_p == NULL) {
		DTRACE_PROBE2(fuse_dev_write_err_session,
		    char *, "failed to find session",
		    dev_t, dev);
		err = ENODEV;
		goto cleanup;
	}
	FUSE_SESSION_MUTEX_LOCK(se_p);

	/* Reset error before starting the search */
	err = DDI_FAILURE;
	for (msg_p = list_head(&(se_p->msg_list)); msg_p;
	    msg_p = list_next(&(se_p->msg_list), msg_p)) {
		if (msg_p->fmn_unique == outh->unique) {
			if (msg_p->fmn_state == FUSE_MSG_STATE_READ) {
				msg_p->fmn_state = FUSE_MSG_STATE_WRITE;
			/* remove it from the queue */
				list_remove(&(se_p->msg_list), msg_p);
				err = DDI_SUCCESS;
				break;
			} else if (msg_p->fmn_state == FUSE_MSG_STATE_SIG) {
				msg_p->fmn_state = FUSE_MSG_STATE_DONE;
				list_remove(&(se_p->msg_list), msg_p);
				cv_signal(&msg_p->fmn_cv);
				FUSE_SESSION_MUTEX_UNLOCK(se_p);
				goto cleanup;
			}
		}
	}
	FUSE_SESSION_MUTEX_UNLOCK(se_p);

	if (err == DDI_SUCCESS) {
		msg_p->opdata.fouth = outh;

		if (uiop->uio_resid) {

			iovbuf = &msg_p->opdata.iovbuf;

			if (iovbuf->memsize &&
			    iovbuf->memsize < uiop->uio_resid &&
			    iovbuf->memflag == MEM_TYPE_KMEM) {
				kmem_free(iovbuf->base, iovbuf->memsize);
				iovbuf->memsize = 0;
			}

			if (iovbuf->memsize == 0) {
				fuse_buf_alloc(iovbuf, uiop->uio_resid);
			}

			iovbuf->len = min(iovbuf->memsize, uiop->uio_resid);

			/* Save the start and length of arguments */
			msg_p->opdata.outdata = iovbuf->base;
			msg_p->opdata.outsize = iovbuf->len;

			/* Copy the arguments part sent by fuse library */
			if ((err = uiomove(msg_p->opdata.outdata,
			    iovbuf->len, UIO_WRITE, uiop)) != 0) {
				fuse_free_msg(msg_p);
				goto out;
			}
		}

		DTRACE_PROBE2(msg_write, struct fuse_out_header *,
		    msg_p->opdata.fouth, void *, msg_p->opdata.outdata);

		/* If an handler is registered, then it will free the memory */
		if (msg_p->frd_on_request_complete)
			msg_p->frd_on_request_complete(se_p, msg_p);
		else {
			/*
			 * No callback handler is registered, so its our
			 * responsibility to free up the message node
			 * This function also frees the header we allocated
			 * here.
			 */
			fuse_free_msg(msg_p);
		}
		/*
		 * Here, either the handler has been called which would have
		 * freed the entire message structure with the header or if
		 * there was no handler registered, we did it ourselves, so
		 * just get out of here.
		 */
		goto out;
	} else {
		DTRACE_PROBE2(fuse_dev_write_err_msgp,
		    char *, "No matching message on session msg_list",
		    fuse_session_t *, se_p);
	}

cleanup:
	kmem_free(outh, sizeof (struct fuse_out_header));

out:
	return (err);
}
