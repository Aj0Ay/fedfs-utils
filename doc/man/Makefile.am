##
## @file doc/Makefile.am
## @brief Process this file with automake to produce doc/Makefile.in
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

FEDFS_CLIENT_CMDS	= fedfs-create-junction.8 fedfs-create-replication.8 \
			  fedfs-delete-junction.8 fedfs-delete-replication.8 \
			  fedfs-lookup-junction.8 fedfs-lookup-replication.8 \
			  fedfs-get-nsdb-params.8 fedfs-set-nsdb-params.8 \
			  fedfs-get-limited-nsdb-params.8 fedfs-null.8
NSDB_CLIENT_CMDS	= nsdb-create-fsl.8 nsdb-create-fsn.8 \
			  nsdb-delete-fsl.8 nsdb-delete-fsn.8 \
			  nsdb-resolve-fsn.8 nsdb-update-fsl.8 \
			  nsdb-annotate.8 nsdb-describe.8 \
			  nsdb-list.8 nsdb-nces.8 \
			  nsdb-update-nci.8 nsdb-remove-nci.8 \
			  nsdb-delete-nsdb.8 nsdb-simple-nce.8

dist_man7_MANS		= fedfs.7 nsdb-parameters.7
dist_man8_MANS		= rpc.fedfsd.8 mount.fedfs.8 fedfs-map-nfs4.8 nfsref.8 \
			  nsdbparams.8 $(FEDFS_CLIENT_CMDS) $(NSDB_CLIENT_CMDS)

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in

dist-hook:
	(cd $(distdir) && \
	  for p in $(dist_man7_MANS) $(dist_man8_MANS); do \
	    $(SED) -i 's,[@]publication-date@,$(pubdate),' $$p ;\
	  done)

install-data-hook:
	(cd $(DESTDIR)$(mandir)/man7 && \
	  for p in $(dist_man7_MANS); do \
	    $(SED) -i 's,[@]statedir@,$(statedir),' $$p ;\
	    $(SED) -i 's,[@]fedfsuser@,$(fedfsuser),' $$p ;\
	  done)
	(cd $(DESTDIR)$(mandir)/man8 && \
	  for p in $(dist_man8_MANS); do \
	    $(SED) -i 's,[@]statedir@,$(statedir),' $$p ;\
	    $(SED) -i 's,[@]fedfsuser@,$(fedfsuser),' $$p ;\
	  done)
