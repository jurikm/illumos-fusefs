#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END

#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

INSTALL= /usr/sbin/install
CC = cc
CTFMERGE = ctfmerge
CTFCONVERT = ctfconvert
LINT = lint

CCFLAGS = $(CFLAGS) -g -D_KERNEL -D__SOLARIS__
LLINTFLAGS =  -sxnuF -errtags -errsecurity=extended $(LINTFLAGS) -D_KERNEL -D__SOLARIS__
LD = /usr/ccs/bin/ld

FUSE_MODULE=fuse 

OBJS=fuse_dev.o fuse_ini.o fuse_queue.o fuse_vnops.o fuse_vfsops.o
HDRS=fuse.h fuse_kernel.h fuse_queue.h

SRC=$(OBJS:%.o=../%.c)
INCHDRS=$(HDRS:%.h=../%.h)

ROOT = ../proto

all: $(FUSE_MODULE) $(SRC) 

$(FUSE_MODULE): $(OBJS) 
	$(LD) -r $(LDFLAGS) $(OBJS) -o $@
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)

%.o: ../%.c $(INCHDRS)
	$(CC) $(CCFLAGS) -c ../$*.c -o $@
	$(CTFCONVERT) -i -L VERSION $@

lint: $(SRC)
	$(LINT) $(LLINTFLAGS) $(SRC)

install_common:
	$(INSTALL) -f $(ROOT)/usr/kernel/drv fuse
	$(INSTALL) -f $(ROOT)/usr/kernel/drv ../fuse.conf

clean:
	rm -f $(OBJS) $(FUSE_MODULE)
