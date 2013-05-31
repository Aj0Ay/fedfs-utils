#!/bin/sh -e
#
# @file autogen.sh
# @brief Regenerate autotools configuration files
#

#
# Copyright 2010 Oracle.  All rights reserved.
#
# This file is part of fedfs-utils.
#
# fedfs-utils is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2.0 as
# published by the Free Software Foundation.
#
# fedfs-utils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License version 2.0 for more details.
#
# You should have received a copy of the GNU General Public License
# version 2.0 along with fedfs-utils.  If not, see:
#
#	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
#

RM=/bin/rm
FIND=/bin/find
XARGS=/usr/bin/xargs

REMOVE="aclocal.m4 configure compile config.* depcomp install-sh ltmain.sh missing mkinstalldirs libtool stamp-h1 ar-lib"

echo -n cleaning up.

(
  for FILE in ${REMOVE}; do
    if test -f ${FILE}; then
      ${RM} -f ${FILE}
    fi
    echo -n .
    done
)

for DIR in autom4te.cache m4; do
  if test -d ${DIR}; then
    ${RM} -rf ${DIR}
  fi
  echo -n .
done

${FIND} . -type f -name 'Makefile.in' -print0 | ${XARGS} -r0  ${RM} -f --
${FIND} . -type f -name 'Makefile' -print0 | ${XARGS} -r0 ${RM} -f --

echo ' done'

if test x"${1}" = x"clean"; then
  exit
fi

aclocal
libtoolize --force --copy --install
autoheader
automake --add-missing --copy --gnu
autoconf
