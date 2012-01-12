/**
 * @file src/nfsref/remove.c
 * @brief Remove junction metadata from a local file system object
 */

/*
 * Copyright 2011 Oracle.  All rights reserved.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>

#include "fedfs.h"
#include "junction.h"
#include "xlog.h"
#include "nfsref.h"

/**
 * Remove any NFS junction information
 *
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_remove_unspecified(const char *junct_path)
{
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: Removing junction from %s",
		__func__, junct_path);

	retval = nfs_delete_junction(junct_path);
	if (retval != FEDFS_OK) {
		if (retval != FEDFS_ERR_NOTJUNCT)
			goto out_err;
		retval = fedfs_delete_junction(junct_path);
		if (retval != FEDFS_OK)
			goto out_err;
	}

	printf("Removed junction from %s\n", junct_path);
	return EXIT_SUCCESS;

out_err:
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "No junction information found in %s", junct_path);
		break;
	default:
		xlog(L_ERROR, "Failed to delete %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
	}
	return EXIT_FAILURE;
}

/**
 * Remove an NFS locations-style junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_remove_nfs_basic(const char *junct_path)
{
	int status = EXIT_FAILURE;
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: Removing FedFS junction from %s",
		__func__, junct_path);

	retval = nfs_delete_junction(junct_path);
	switch (retval) {
	case FEDFS_OK:
		printf("Removed nfs-basic junction from %s\n", junct_path);
		status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "%s is not an nfs-basic junction", junct_path);
		break;
	default:
		xlog(L_ERROR, "Failed to delete %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
	}

	return status;
}

/**
 * Remove a FedFS-style junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_remove_nfs_fedfs(const char *junct_path)
{
	int status = EXIT_FAILURE;
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: Removing FedFS junction from %s",
		__func__, junct_path);

	retval = fedfs_delete_junction(junct_path);
	switch (retval) {
	case FEDFS_OK:
		printf("Removed nfs-fedfs junction from %s\n", junct_path);
		status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "%s is not an nfs-fedfs junction", junct_path);
		break;
	default:
		xlog(L_ERROR, "Failed to delete %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
	}

	return status;
}

/**
 * Remove an NFS junction
 *
 * @param type type of junction to add
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
int
nfsref_remove(enum nfsref_type type, const char *junct_path)
{
	switch (type) {
	case NFSREF_TYPE_UNSPECIFIED:
		return nfsref_remove_unspecified(junct_path);
	case NFSREF_TYPE_NFS_BASIC:
		return nfsref_remove_nfs_basic(junct_path);
	case NFSREF_TYPE_NFS_FEDFS:
		return nfsref_remove_nfs_fedfs(junct_path);
	default:
		xlog(L_ERROR, "Unrecognized junction type");
	}
	return EXIT_FAILURE;
}
