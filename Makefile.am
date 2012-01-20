##
## @file Makefile.am
## @brief Process this file with automake to produce Makefile.in
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

AUTOMAKE_OPTIONS	= foreign
SUBDIRS			= doc src contrib
dist_noinst_SCRIPTS	= autogen.sh
EXTRA_DIST		= ChangeLog COPYING README INSTALL doxy.cfg .gitignore
ACLOCAL_AMFLAGS		= -I m4

CLEANFILES		= cscope.in.out cscope.out cscope.po.out *~
DISTCLEANFILES		= Makefile.in ChangeLog fedfs-utils*.tar.gz

ChangeLog:
	git log > ChangeLog

clean-local: doxyclean

dist-hook: ChangeLog

# Doxygen-related targets

.PHONY: doxy doxyclean

# building src/ ensures rpcgen source is available to be documented
doxy: doxyclean src
	mkdir -p Doxygen
	doxygen doxy.cfg

doxyclean:
	$(RM) -rf Doxygen
