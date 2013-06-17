##
## @file src/libjunction/Makefile.am
## @brief Process this file with automake to produce src/libjunction/Makefile.in
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

noinst_HEADERS		= junction-internal.h

noinst_LTLIBRARIES	= libjunction.la
noinst_PROGRAMS		= display-junction
libjunction_la_SOURCES	= export-cache.c fedfs.c junction.c \
			  locations.c nfs.c xml.c
display_junction_LDADD	= $(top_builddir)/src/libxlog/libxlog.la \
			  libjunction.la \
			  $(top_builddir)/src/libnsdb/libnsdb.la

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

AM_CFLAGS		= -ggdb -fstrict-aliasing \
			  -Wall -Wextra -pedantic -Wformat=2 \
			  -Wstrict-aliasing=2 -Wp,-D_FORTIFY_SOURCE=2
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include \
			  -I/usr/include/libxml2
