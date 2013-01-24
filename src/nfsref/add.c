/**
 * @file src/nfsref/add.c
 * @brief Add junction metadata to a local file system object
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

#include <sys/stat.h>
#include <sys/types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <uuid/uuid.h>

#include "fedfs.h"
#include "junction.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"
#include "nfsref.h"

/**
 * Default cache expiration for FSN information
 */
#define FSN_DEFAULT_TTL		(300)

/**
 * Display help message for "add" subcommand
 *
 * @param progname NUL-terminated C string containing name of program
 * @return program exit status
 */
int
nfsref_add_help(const char *progname)
{
	fprintf(stderr, " \n");

	fprintf(stderr, "Usage: %s [ -t type ] add <junction path> "
			"<server> <export> [ <server> <export> ... ]\n\n",
		progname);

	fprintf(stderr, "Add a new junction containing the specified list "
			"of fileset locations.\n");
	fprintf(stderr, "<junction path> is the filename of the new junction.  "
			"<server> is the hostname\n");
	fprintf(stderr, "or IP address of an NFS server where the fileset is "
			"located.  <export> is the\n");
	fprintf(stderr, "export pathname of the fileset on that server.\n\n");

	fprintf(stderr, "For NFS basic junctions, the location list is stored "
			"locally in the junction.\n");
	fprintf(stderr, "For FedFS junctions, the location list is stored "
			"as new FSN and FSL records\n");
	fprintf(stderr, "on an NSDB.\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
	return EXIT_SUCCESS;
}

/**
 * Fill in default settings for NFSv4.0 fs_locations4
 *
 * @param new NFS location structure to fill in
 *
 * See section 5.1.3.2 of the NSDB protocol draft.
 */
static void
nfsref_add_fsloc_defaults(struct nfs_fsloc *new)
{
	new->nfl_hostport = 0;
	new->nfl_flags.nfl_varsub = false;
	new->nfl_currency = -1;
	new->nfl_validfor = 0;
	new->nfl_genflags.nfl_writable = false;
	new->nfl_genflags.nfl_going = false;
	new->nfl_genflags.nfl_split = true;
	new->nfl_transflags.nfl_rdma = true;
	new->nfl_info.nfl_simul = 0;
	new->nfl_info.nfl_handle = 0;
	new->nfl_info.nfl_fileid = 0;
	new->nfl_info.nfl_writever = 0;
	new->nfl_info.nfl_change = 0;
	new->nfl_info.nfl_readdir = 0;
	new->nfl_info.nfl_readrank = 0;
	new->nfl_info.nfl_readorder = 0;
	new->nfl_info.nfl_writerank = 0;
	new->nfl_info.nfl_writeorder = 0;
}

/**
 * Convert a pair of command line arguments to one nfs_fsloc structure
 *
 * @param server NUL-terminated C string containing file server hostname
 * @param rootpath NUL-terminated C string containing POSIX-style export path
 * @param fsloc OUT: NFS location structure
 * @return a FedFsStatus code
 *
 * If nfsref_add_build_fsloc() returns FEDFS_OK, caller must free the
 * returned fsloc with nfs_free_location().
 */
static FedFsStatus
nfsref_add_build_fsloc(const char *server, const char *rootpath,
		struct nfs_fsloc **fsloc)
{
	struct nfs_fsloc *new;
	FedFsStatus retval;

	if (server == NULL || rootpath == NULL)
		return FEDFS_ERR_INVAL;

	xlog(D_GENERAL, "%s: Building fsloc for %s:%s",
		__func__, server, rootpath);

	new = nfs_new_location();
	if (new == NULL) {
		xlog(D_GENERAL, "%s: No memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	new->nfl_hostname = strdup(server);
	if (new->nfl_hostname == NULL) {
		nfs_free_location(new);
		xlog(D_GENERAL, "%s: No memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = nsdb_posix_to_path_array(rootpath, &new->nfl_rootpath);
	if (retval != FEDFS_OK) {
		free(new->nfl_hostname);
		nfs_free_location(new);
		return retval;
	}

	nfsref_add_fsloc_defaults(new);
	*fsloc = new;
	return FEDFS_OK;
}

/**
 * Convert array of command line arguments to list of nfs_fsloc structures
 *
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @param fslocs OUT: list of NFS locations
 * @return a FedFsStatus code
 *
 * If nfsref_add_build_fsloc_list() returns FEDFS_OK, caller must free the
 * returned list of fslocs with nfs_free_locations().
 */
static FedFsStatus
nfsref_add_build_fsloc_list(char **argv, int optind, struct nfs_fsloc **fslocs)
{
	struct nfs_fsloc *fsloc, *result = NULL;
	FedFsStatus retval;
	int i;

	for (i = optind + 2; argv[i] != NULL; i += 2) {
		retval = nfsref_add_build_fsloc(argv[i], argv[i + 1], &fsloc);
		if (retval != FEDFS_OK) {
			nfs_free_locations(result);
			return retval;
		}
		if (result == NULL)
			result = fsloc;
		else
			result->nfl_next = fsloc;
	}
	if (result == NULL)
		return FEDFS_ERR_INVAL;

	*fslocs = result;
	return FEDFS_OK;
}

/**
 * Add NFS locations to a junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @return program exit status
 */
static int
nfsref_add_nfs_basic(const char *junct_path, char **argv, int optind)
{
	struct nfs_fsloc *fslocs = NULL;
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: Adding basic junction to %s",
		__func__, junct_path);

	retval = nfsref_add_build_fsloc_list(argv, optind, &fslocs);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_INVAL:
		xlog(L_ERROR, "Missing arguments");
		return EXIT_FAILURE;
	case FEDFS_ERR_SVRFAULT:
		xlog(L_ERROR, "No memory");
		return EXIT_FAILURE;
	default:
		xlog(L_ERROR, "Failed to add NFS location metadata to %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	retval = nfs_add_junction(junct_path, fslocs);
	nfs_free_locations(fslocs);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_EXIST:
		xlog(L_ERROR, "%s already contains junction metadata",
			junct_path);
		return EXIT_FAILURE;
	default:
		xlog(L_ERROR, "Failed to add NFS location metadata to %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	printf("Created junction %s\n", junct_path);
	return EXIT_SUCCESS;
}

/**
 * Create a FedFS FSN record, return the new UUID
 *
 * @param host initialized NSDB host object
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid OUT: freshly generated FSN UUID
 * @return a FedFsStatus code
 *
 * If nfsref_add_create_fedfs_fsn() returns FEDFS_OK, caller must free
 * the returned FSN UUID with free(3).
 */
static FedFsStatus
nfsref_add_create_fedfs_fsn(nsdb_t host, const char *nce, char **fsn_uuid)
{
	unsigned int ldap_err;
	FedFsStatus retval;
	char *fsnuuid;
	uuid_t uu;

	fsnuuid = calloc(FEDFS_UUID_STRLEN, sizeof(char));
	if (fsnuuid == NULL) {
		xlog(D_GENERAL, "%s: No memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	uuid_generate_random(uu);
	uuid_unparse(uu, fsnuuid);

	retval = nsdb_create_fsn_s(host, nce, fsnuuid,
					FSN_DEFAULT_TTL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		xlog(D_GENERAL, "%s: Successfully created FSN record "
			"for %s under %s", __func__, fsnuuid, nce);
		*fsn_uuid = fsnuuid;
		return FEDFS_OK;
	case FEDFS_ERR_NSDB_NONCE:
		xlog(L_ERROR, "NCE %s does not exist", nce);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		xlog(L_ERROR, "Failed to create FSN: %s",
			ldap_err2string(ldap_err));
		break;
	default:
		xlog(L_ERROR, "Failed to create FSN: %s",
			nsdb_display_fedfsstatus(retval));
	}

	free(fsnuuid);
	return retval;
}

/**
 * Fill in default settings for NFSv4.0 fs_locations4
 *
 * @param server NUL-terminated C string containing fileserver hostname
 * @param rootpath NUL-terminated C string containing POSIX-style export path
 * @param new fedfs_fsl object to fill in
 *
 * See section 5.1.3.2 of the NSDB protocol draft.
 */
static FedFsStatus
nfsref_add_nfs_fsl_defaults(const char *server, const char *rootpath,
		struct fedfs_nfs_fsl *new)
{
	FedFsStatus retval;

	/* XXX: check the server hostname length */
	strcpy(new->fn_fslhost, server);
	new->fn_fslport = 0;

	retval = nsdb_posix_to_path_array(rootpath, &new->fn_nfspath);
	if (retval != FEDFS_OK)
		return retval;

	new->fn_currency = -1;
	new->fn_gen_writable = false;
	new->fn_gen_going = false;
	new->fn_gen_split = true;
	new->fn_trans_rdma = true;
	new->fn_class_simul = 0;
	new->fn_class_handle = 0;
	new->fn_class_fileid = 0;
	new->fn_class_writever = 0;
	new->fn_class_change = 0;
	new->fn_class_readdir = 0;
	new->fn_readrank = 0;
	new->fn_readorder = 0;
	new->fn_writerank = 0;
	new->fn_writeorder = 0;
	new->fn_varsub = false;
	new->fn_validfor = 0;

	return FEDFS_OK;
}

/**
 * Convert a pair of command line arguments to one fedfs_fsl structure
 *
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to use
 * @param server NUL-terminated C string containing file server hostname
 * @param rootpath NUL-terminated C string containing POSIX-style export path
 * @param fsl OUT: fedfs_fsl object
 * @return a FedFsStatus code
 *
 * If nfsref_add_build_fsl() returns FEDFS_OK, caller must free the
 * returned fsl with nsdb_free_fedfs_fsl().
 */
static FedFsStatus
nfsref_add_build_fsl(const char *fsn_uuid, const char *server,
		const char *rootpath, struct fedfs_fsl **fsl)
{
	struct fedfs_fsl *new;
	FedFsStatus retval;
	uuid_t uu;

	if (server == NULL || rootpath == NULL)
		return FEDFS_ERR_INVAL;

	new = nsdb_new_fedfs_fsl(FEDFS_NFS_FSL);
	if (new == NULL) {
		xlog(D_GENERAL, "%s: No memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	uuid_generate_random(uu);
	uuid_unparse(uu, new->fl_fsluuid);
	strncpy(new->fl_fsnuuid, fsn_uuid, sizeof(new->fl_fsnuuid));

	retval = nfsref_add_nfs_fsl_defaults(server, rootpath, &new->fl_u.fl_nfsfsl);
	if (retval != FEDFS_OK)
		return retval;

	*fsl = new;
	return FEDFS_OK;
}

/**
 * Convert command line options to a list of fedfs_fsl objects
 *
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to use
 * @param fsls OUT a list of fedfs_fsl objects
 * @return a FedFsStatus code
 *
 * If nfsref_add_build_fsl_list() returns FEDFS_OK, caller must free the
 * returned list of fsls with nsdb_free_fedfs_fsls().
 *
 */
static FedFsStatus
nfsref_add_build_fsl_list(char **argv, int optind,
		const char *fsn_uuid, struct fedfs_fsl **fsls)
{
	struct fedfs_fsl *fsl, *result = NULL;
	FedFsStatus retval;
	int i;

	for (i = optind + 2; argv[i] != NULL; i += 2) {
		retval = nfsref_add_build_fsl(fsn_uuid,
						argv[i], argv[i + 1], &fsl);
		if (retval != FEDFS_OK) {
			nsdb_free_fedfs_fsls(result);
			return retval;
		}
		if (result == NULL)
			result = fsl;
		else
			result->fl_next = fsl;
	}
	if (result == NULL)
		return FEDFS_ERR_INVAL;

	*fsls = result;
	return FEDFS_OK;
}

/**
 * Set up FedFS FSLs, create a FedFS junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param host an initialized and open NSDB object
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to use
 * @param fsls list of fedfs_fsl objects to create on NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
nfsref_add_create_fsls(const char *junct_path, nsdb_t host, const char *nce,
		const char *fsn_uuid, struct fedfs_fsl *fsls)
{
	unsigned int ldap_err;
	FedFsStatus retval;

	retval = nsdb_create_fsls_s(host, nce, fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_NONCE:
		xlog(L_ERROR, "NCE %s does not exist\n", nce);
		return retval;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		xlog(L_ERROR, "Failed to create FSL records: %s\n",
			ldap_err2string(ldap_err));
		return retval;
	default:
		xlog(D_GENERAL, "%s: Failed to create FSL records: %s\n",
			__func__, nsdb_display_fedfsstatus(retval));
		return retval;
	}

	retval = fedfs_add_junction(junct_path, fsn_uuid, host);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_EXIST:
		xlog(L_ERROR, "%s already contains junction metadata",
			junct_path);
		break;
	default:
		xlog(L_ERROR, "Failed to FedFS junction: %s\n",
			nsdb_display_fedfsstatus(retval));
	}
	return retval;
}

/**
 * Set up FedFS FSLs, a FedFS FSN, and add it to a local junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @param host an initialized and open NSDB object
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to use
 * @return a FedFsStatus code
 */
static FedFsStatus
nfsref_add_create_fedfs_junction(const char *junct_path, char **argv, int optind,
		nsdb_t host, const char *nce, const char *fsn_uuid)
{
	struct fedfs_fsl *fsls;
	FedFsStatus retval;

	retval = nfsref_add_build_fsl_list(argv, optind, fsn_uuid, &fsls);
	if (retval != FEDFS_OK)
		return retval;

	retval = nfsref_add_create_fsls(junct_path, host, nce, fsn_uuid, fsls);
	nsdb_free_fedfs_fsls(fsls);
	return retval;
}

/**
 * Set up FedFS FSLs, a FedFS FSN, and add it to a local junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @param host an initialized and open NSDB object
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @return program exit status
 */
static int
nfsref_add_nfs_fedfs_junction(const char *junct_path, char **argv, int optind,
		nsdb_t host, const char *nce)
{
	char *fsn_uuid = NULL;
	FedFsStatus retval;

	retval = nfsref_add_create_fedfs_fsn(host, nce, &fsn_uuid);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_INVAL:
		xlog(L_ERROR, "Missing arguments or environment variables");
		return EXIT_FAILURE;
	case FEDFS_ERR_SVRFAULT:
		xlog(L_ERROR, "No memory");
		return EXIT_FAILURE;
	default:
		xlog(L_ERROR, "Failed to add FedFS junction to %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	retval = nfsref_add_create_fedfs_junction(junct_path, argv, optind,
							host, nce, fsn_uuid);
	if (retval != FEDFS_OK) {
		unsigned int ldap_err;
		nsdb_delete_fsn_s(host, nce, fsn_uuid, false, &ldap_err);
		free(fsn_uuid);
		return EXIT_FAILURE;
	}

	printf("Created junction %s\n", junct_path);
	free(fsn_uuid);
	return EXIT_SUCCESS;
}

/**
 * Set up FedFS FSLs, a FedFS FSN, and add it to a local junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @return program exit status
 */
static int
nfsref_add_nfs_fedfs(const char *junct_path, char **argv, int optind)
{
	char *binddn, *nsdbname, *nce;
	unsigned short nsdbport;
	unsigned int ldap_err;
	FedFsStatus retval;
	nsdb_t host = NULL;
	int status = EXIT_FAILURE;

	xlog(D_GENERAL, "%s: Adding FedFS junction to %s",
		__func__, junct_path);

	nsdb_env(&nsdbname, &nsdbport, &binddn, &nce);
	if (nsdbname == NULL) {
		xlog(L_ERROR, "Cannot determine NSDB hostname");
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_lookup_nsdb(nsdbname, nsdbport, &host);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		xlog(L_ERROR, "No connection parameters for NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out;
	default:
		xlog(L_ERROR, "Failed to look up NSDB %s:%u: %s\n",
			nsdbname, nsdbport, nsdb_display_fedfsstatus(retval));
		goto out;
	}
	retval = FEDFS_ERR_INVAL;
	if (binddn == NULL)
		binddn = (char *)nsdb_default_binddn(host);
	if (binddn == NULL) {
		xlog(L_ERROR, "No NSDB bind DN was specified");
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
			nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_AUTH:
		xlog(L_ERROR, "Failed to establish secure connection to "
			"NSDB %s:%u", nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_INVALID_CREDENTIALS:
			xlog(L_ERROR, "Incorrect password for DN %s",
				binddn);
			break;
		default:
			xlog(L_ERROR, "Failed to bind to NSDB %s:%u: %s",
				nsdbname, nsdbport,
				ldap_err2string(ldap_err));
		}
		goto out_free;
	default:
		xlog(L_ERROR, "Failed to open NSDB %s:%u: %s",
			nsdbname, nsdbport, nsdb_display_fedfsstatus(retval));
		goto out_free;
	}

	status = nfsref_add_nfs_fedfs_junction(junct_path, argv, optind,
								host, nce);

	nsdb_close_nsdb(host);
out_free:
	nsdb_free_nsdb(host);
out:
	return status;
}

/**
 * Add locations to a junction
 *
 * @param type type of junction to add
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @param argv array of pointers to NUL-terminated C strings contains arguments
 * @param optind index of "argv" where "add" subcommand arguments start
 * @return program exit status
 */
int
nfsref_add(enum nfsref_type type, const char *junct_path, char **argv, int optind)
{
	if (mkdir(junct_path, 0755) == -1)
		if (errno != EEXIST) {
			xlog(L_ERROR, "Failed to create junction object: %m");
			return EXIT_FAILURE;
		}

	switch (type) {
	case NFSREF_TYPE_UNSPECIFIED:
	case NFSREF_TYPE_NFS_BASIC:
		return nfsref_add_nfs_basic(junct_path, argv, optind);
	case NFSREF_TYPE_NFS_FEDFS:
		return nfsref_add_nfs_fedfs(junct_path, argv, optind);
	default:
		xlog(L_ERROR, "Unrecognized junction type");
	}
	return EXIT_FAILURE;
}
