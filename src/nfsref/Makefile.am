##
## @file src/nfsref/Makefile.am
## @brief Process this file with automake to produce src/nfsref/Makefile.in
##

##
## Copyright 2011 Oracle.  All rights reserved.
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

noinst_HEADERS		= nfsref.h
sbin_PROGRAMS		= nfsref
nfsref_SOURCES		= add.c lookup.c nfsref.c remove.c
LDADD			= $(top_builddir)/src/libnsdb/libnsdb.la \
			  $(top_builddir)/src/libxlog/libxlog.la \
			  $(top_builddir)/src/libjunction/libjunction.la \
			  $(LIBLDAP) $(LIBLBER) $(LIBXML2) \
			  $(LIBSQLITE3) $(LIBIDN) $(LIBUUID) \
			  $(LIBURIPARSER) $(LIBCRYPTO) $(LIBSSL)

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

AM_CFLAGS		= -ggdb -fstrict-aliasing \
			  -Wall -Wextra -pedantic -Wformat=2 \
			  -Wstrict-aliasing=2 -Wp,-D_FORTIFY_SOURCE=2
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include
AM_LDFLAGS		= -Wl,--as-needed
