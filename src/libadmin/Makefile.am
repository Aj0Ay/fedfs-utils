##
## @file src/libadmin/Makefile.am
## @brief Process this file with automake to produce src/libadmin/Makefile.in
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

noinst_LTLIBRARIES	= libadmin.la
libadmin_la_SOURCES	= fedfs_admin_clnt.c fedfs_admin_svc.c fedfs_admin_xdr.c

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

# Squelch compiler warnings for rpcgen-produced source code
AM_CFLAGS		= -ggdb -fstrict-aliasing
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include -I/usr/include/tirpc
