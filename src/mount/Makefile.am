##
## @file src/mount/Makefile.am
## @brief Process this file with automake to produce src/mount/Makefile.in
##

##
## Copyright 2010 Oracle.  All rights reserved.
##
## This file is part of fedfs-utils.
##
## fedfs-utils is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License version 2.0 as
## published by the Free Software Foundation.
##
## fedfs-utils is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License version 2.0 for more details.
##
## You should have received a copy of the GNU General Public License
## version 2.0 along with fedfs-utils.  If not, see:
##
##	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
##

noinst_HEADERS		= nls.h
root_sbin_PROGRAMS	= mount.fedfs
sbin_PROGRAMS		= fedfs-map-nfs4
fedfs_map_nfs4_SOURCES	= fedfs-map-nfs4.c
fedfs_map_nfs4_LDADD	= $(top_builddir)/src/libsi/libsi.la \
			  $(LIBRESOLV)
mount_fedfs_SOURCES	= main.c
# mount.fedfs must never link against libraries in /usr
mount_fedfs_LDADD	= $(top_builddir)/src/libsi/libsi.la \
			  $(LIBRESOLV)

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

AM_CFLAGS		= -ggdb -fstrict-aliasing \
			  -Wall -Wextra -pedantic -Wformat=2 \
			  -Wstrict-aliasing=2 -Wp,-D_FORTIFY_SOURCE=2
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include
