##
## @file doc/rpcl/Makefile.am
## @brief Process this file with automake to produce doc/rpcl/Makefile.in
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

GENFILES_CLNT		= fedfs_admin_clnt.c
GENFILES_SVC		= fedfs_admin_svc.c
GENFILES_XDR		= fedfs_admin_xdr.c
GENFILES_H		= fedfs_admin.h
GENFILES		= $(GENFILES_CLNT) $(GENFILES_SVC) $(GENFILES_XDR) \
			  $(GENFILES_H)

EXTRA_DIST		= fedfs_admin.x
BUILT_SOURCES		= $(GENFILES)

CLEANFILES		= $(GENFILES) cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

$(GENFILES_H): %.h: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -5 -h $< -o $@

$(GENFILES_XDR): %_xdr.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -5 -c $< -o $@

$(GENFILES_CLNT): %_clnt.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -5 -l $< -o $@

$(GENFILES_SVC): %_svc.c: %.x $(RPCGEN)
	test -f $@ && rm -rf $@ || true
	$(RPCGEN) -5 -m $< -o $@
