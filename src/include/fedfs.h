/*
 * @file src/include/fedfs.h
 * @brief Common definitions
 */

/*
 * Copyright 2010 Oracle.  All rights reserved.
 *
 * This file is part of fedfs-utils.
 *
 * fedfs-utils is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2.0 as
 * published by the Free Software Foundation.
 *
 * fedfs-utils is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2.0 for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2.0 along with fedfs-utils.  If not, see:
 *
 *	http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
 */

#ifndef _FEDFS_H_
#define _FEDFS_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/**
 * Size of C string representation of a RFC 4122 UUID, in bytes
 */
#define FEDFS_UUID_STRLEN	\
	(sizeof("ffffffff-ffff-ffff-ffff-ffffffffffff") + 1)

/**
 * Directory containing X.509 v3 cert store
 */
#define FEDFS_NSDBCERT_DIR		"nsdbcerts"

/**
 * Name of file containing NSDB connection parameter database
 */
#define FEDFS_DATABASE_FILE		"nsdbparam.sqlite3"

/**
 * Default pathname of directory where fedfsd maintains persistent state
 */
#ifndef FEDFS_DEFAULT_STATEDIR
#define FEDFS_DEFAULT_STATEDIR		"/var/lib/fedfs"
#endif	/* FEDFS_DEFAULT_STATEDIR */

/**
 * User name to use when dropping privileges.  This user is
 * typically the owner of default state directory.
 */
#ifndef FEDFS_USER
#define FEDFS_USER	"fedfs"
#endif	/* FEDFS_USER */

#endif	/* !_FEDFS_H_ */
