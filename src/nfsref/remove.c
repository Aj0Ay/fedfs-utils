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
#include "gpl-boiler.h"
#include "nfsref.h"

/**
 * Display help message for "remove" subcommand
 *
 * @param progname NUL-terminated C string containing name of program
 * @return program exit status
 */
int
nfsref_remove_help(const char *progname)
{
	fprintf(stderr, " \n");

	fprintf(stderr, "Usage: %s [ -t type ] remove <junction path>\n\n",
		progname);

	fprintf(stderr, "Remove the junction at <junction path>.  For FedFS "
			"junctions, FSL and FSN\n");
	fprintf(stderr, "records are removed from the NSDB.\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
	return EXIT_SUCCESS;
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
 * Delete the FSN in a FedFS-style junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return a FedFsStatus code
 */
static FedFsStatus
nfsref_remove_delete_fsn(const char *junct_path)
{
	char *fsn_uuid = NULL;
	unsigned int ldap_err;
	char *binddn, *nce;
	FedFsStatus retval;
	nsdb_t host;

	retval = fedfs_get_fsn(junct_path, &fsn_uuid, &host);
	switch (retval) {
	case FEDFS_OK:
		xlog(D_CALL, "%s: FSN UUID is %s", __func__, fsn_uuid);
		break;
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "%s is not an nfs-fedfs junction", junct_path);
		goto out;
	default:
		xlog(L_ERROR, "Failed to read %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		goto out;
	}

	nsdb_env(NULL, NULL, &binddn, &nce);

	retval = FEDFS_ERR_INVAL;
	if (binddn == NULL)
		binddn = (char *)nsdb_default_binddn(host);
	if (binddn == NULL) {
		xlog(L_ERROR, "No NDSB bind DN was specified");
		goto out_free;
	}
	if (nce == NULL)
		nce = (char *)nsdb_default_nce(host);
	if (nce == NULL) {
		xlog(L_ERROR, "No NCE was specified");
		goto out_free;
	}

	retval = nsdb_open_nsdb(host, binddn, NULL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_INVAL:
		xlog(L_ERROR, "Missing or invalid password");
		goto out_free;
	case FEDFS_ERR_NSDB_CONN:
		xlog(L_ERROR, "Failed to connect to NSDB %s:%u",
			nsdb_hostname(host), nsdb_port(host));
		goto out_free;
	case FEDFS_ERR_NSDB_AUTH:
		xlog(L_ERROR, "Failed to establish secure connection "
			"to NSDB %s:%u", nsdb_hostname(host), nsdb_port(host));
		goto out_free;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_INVALID_CREDENTIALS:
			xlog(L_ERROR, "Incorrect password for DN %s",
				binddn);
			break;
		default:
			xlog(L_ERROR, "Failed to bind to NSDB %s:%u: %s",
				nsdb_hostname(host), nsdb_port(host),
				ldap_err2string(ldap_err));
		}
		goto out_free;
	default:
		xlog(L_ERROR, "Failed to open NSDB %s:%u: %s",
			nsdb_hostname(host), nsdb_port(host),
			nsdb_display_fedfsstatus(retval));
		goto out_free;
	}

	retval = nsdb_delete_fsn_s(host, nce, fsn_uuid, false, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully deleted FSL records for FSN %s under %s\n",
			fsn_uuid, nce);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			xlog(L_ERROR, "NSDB %s:%u has no NCE",
				nsdb_hostname(host), nsdb_port(host));
		else
			xlog(L_ERROR, "NCE %s does not exist", nce);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		xlog(L_ERROR, "NSDB %s:%u has no such FSN %s",
			nsdb_hostname(host), nsdb_port(host), fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		xlog(L_ERROR, "FSN %s still has FSL entries", fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_REFERRAL:
			xlog(L_ERROR, "Encountered LDAP referral on %s:%u",
				nsdb_hostname(host), nsdb_port(host));
			break;
		case LDAP_CONFIDENTIALITY_REQUIRED:
			xlog(L_ERROR, "TLS security required for %s:%u",
				nsdb_hostname(host), nsdb_port(host));
			break;
		case LDAP_NOT_ALLOWED_ON_NONLEAF:
			xlog(L_ERROR, "Failed to delete: "
				"this FSN may have children");
			break;
		default:
			xlog(L_ERROR, "Failed to delete FSN %s: %s",
				fsn_uuid, ldap_err2string(ldap_err));
		}
		break;
	default:
		xlog(L_ERROR, "Failed to delete FSN %s: %s",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);
out_free:
	free(fsn_uuid);
	nsdb_free_nsdb(host);
out:
	return retval;
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

	nfsref_remove_delete_fsn(junct_path);

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
 * Remove any NFS junction information
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
		nfsref_remove_delete_fsn(junct_path);
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
