##
## @file src/nsdbparams/Makefile.am
## @brief Process this file with automake to produce src/nsdbparams/Makefile.in
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

sbin_PROGRAMS		= nsdbparams
nsdbparams_SOURCES	= main.c
LDADD			= -ltirpc -luuid -lcap -lsqlite3 -lldap -lidn -llber \
			  $(top_builddir)/src/libnsdb/libnsdb.a \
			  $(top_builddir)/src/libjunction/libjunction.a \
			  $(top_builddir)/src/libpath/libpath.a \
			  $(top_builddir)/src/libxlog/libxlog.a
CLEANFILES		= cscope.in.out cscope.out cscope.po.out
DISTCLEANFILES		= Makefile.in

AM_CFLAGS		= -ggdb -fstrict-aliasing -fpie -Wall -Wextra \
			  -pedantic -Wformat=2 -Wstrict-aliasing=2
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include -I/usr/include/tirpc
AM_LDFLAGS		= -fPIC
