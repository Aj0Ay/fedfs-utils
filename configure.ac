#               -*- Autoconf -*-
# Initial configure.ac created with autoscan
# Thu Oct 28 16:29:21 EDT 2010
#
# @file configure.ac
# @brief Process this file with autoconf to produce a configure script
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

AC_PREREQ([2.65])
AC_INIT([fedfs-utils], [0.6.1], [fedfs-utils-devel@oss.oracle.com])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Automake and libtools initialization
LT_INIT
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

AC_CHECK_PROG([DOT_PRESENT], [dot], [yes], [no])
if test "$DOT_PRESENT" = no; then
	echo "Warning: GraphViz not present on this system. 'make doxy' will fail."
fi

AC_ARG_VAR([RPCGEN], [rpcgen-like protocol compiler command])
AC_PATH_PROG([RPCGEN], [rpcgen])

# C compiler options
AC_PROG_CC_C99
AC_C_INLINE
AC_C_CONST

# Checks for libraries (essentially, -devel packages)
AC_CHECK_LIB([cap], [cap_set_proc], [],
		[AC_MSG_ERROR([libcap not found.])])
AC_CHECK_LIB([idn], [idna_to_ascii_8z], [],
		[AC_MSG_ERROR([libidn not found.])])
AC_CHECK_LIB([ldap], [ldap_initialize], [],
		[AC_MSG_ERROR([libldap not found.])])
AC_CHECK_LIB([lber], [ber_memvfree], [],
		[AC_MSG_ERROR([liblber not found.])])
AC_CHECK_LIB([sqlite3], [sqlite3_initialize], [],
		[AC_MSG_ERROR([libsqlite3 not found.])])
AC_CHECK_LIB([tirpc], [svc_tli_create], [],
		[AC_MSG_ERROR([libtirpc not found.])])
AC_CHECK_LIB([uuid], [uuid_parse], [],
		[AC_MSG_ERROR([libuuid not found.])])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h langinfo.h locale.h memory.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/socket.h syslog.h termios.h unistd.h wchar.h])
AC_HEADER_STDBOOL

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([atexit memset nl_langinfo pathconf setlocale socket strcasecmp strchr strdup strerror strndup strrchr strtoul])

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 doc/ldap/Makefile
                 doc/man/Makefile
                 doc/rpcl/Makefile
                 src/Makefile
                 src/fedfsc/Makefile
                 src/fedfsd/Makefile
                 src/include/Makefile
                 src/libadmin/Makefile
                 src/libjunction/Makefile
                 src/libnsdb/Makefile
                 src/libparser/Makefile
                 src/libpath/Makefile
                 src/libsi/Makefile
                 src/libxlog/Makefile
                 src/mount/Makefile
                 src/nsdbc/Makefile
                 src/nsdbparams/Makefile
                 src/resolve-junction/Makefile])
AC_OUTPUT
