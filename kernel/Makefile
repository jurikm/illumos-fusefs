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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

MACH:sh =uname -p

MACH64_1 = $(MACH:sparc=sparcv9)
MACH64 = $(MACH64_1:i386=amd64)

ROOT = proto
DIRS = $(ROOT)/usr \
	   $(ROOT)/usr/kernel \
	   $(ROOT)/usr/kernel/drv

PKGDIR = packages

all := TARGET = all
clean := TARGET = clean
install:= TARGET = install
pkg:= TARGET = pkg
lint:= TARGET = lint

all: $(MACH) $(MACH64)

clean: $(MACH) $(MACH64)
	rm -fr $(DIRS) $(ROOT) $(PKGDIR)

install: preinstall $(MACH) $(MACH64)

lint: $(MACH) $(MACH64)

pkg: prepkg pkgdefs

preinstall:
	mkdir -p $(ROOT) $(DIRS)

prepkg:
	mkdir -p $(PKGDIR)

$(MACH) $(MACH64) pkgdefs: FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
