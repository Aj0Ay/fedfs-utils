##
## @file src/fedfsd/Makefile.am
## @brief Process this file with automake to produce src/fedfsd/Makefile.in
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

noinst_HEADERS		= fedfsd.h
RPCPREFIX		= rpc.
sbin_PROGRAMS		= fedfsd
fedfsd_SOURCES		= listen.c main.c privilege.c svc.c
fedfsd_LDADD		= $(top_builddir)/src/libadmin/libadmin.la \
			  $(top_builddir)/src/libnsdb/libnsdb.la \
			  $(top_builddir)/src/libjunction/libjunction.la \
			  $(top_builddir)/src/libxlog/libxlog.la \
			  $(LIBTIRPC) $(LIBLDAP) $(LIBLBER) $(LIBXML2) \
			  $(LIBSQLITE3) $(LIBIDN) $(LIBUUID) $(LIBCAP) \
			  $(LIBURIPARSER) $(LIBCRYPTO) $(LIBSSL)

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

AM_CFLAGS		= -ggdb -fstrict-aliasing \
			  -Wall -Wextra -pedantic -Wformat=2 \
			  -Wstrict-aliasing=2 -Wp,-D_FORTIFY_SOURCE=2
AM_CPPFLAGS		= -I. -I$(top_srcdir)/src/include -I/usr/include/tirpc

#######################################################################
# The following allows the current practice of having
# daemons renamed during the install to include RPCPREFIX
# This could all be done much easier with program_transform_name
# ( program_transform_name = s/^/$(RPCPREFIX)/ )
# but that also renames the man pages, which the current
# practice does not do.
install-exec-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PROGRAMS); do \
	    mv -f $$p$(EXEEXT) $(RPCPREFIX)$$p$(EXEEXT) ;\
	  done)
uninstall-hook:
	(cd $(DESTDIR)$(sbindir) && \
	  for p in $(sbin_PROGRAMS); do \
	    rm -f $(RPCPREFIX)$$p$(EXEEXT) ;\
	  done)
