/**
 * @file src/nfsref/lookup.c
 * @brief Examine junction metadata from a local file system object
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

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include "fedfs.h"
#include "junction.h"
#include "nsdb.h"
#include "xlog.h"
#include "nfsref.h"

/**
 * Convert a boolean value into a displayable string constant
 *
 * @param value boolean value
 * @return NUL-terminated static constant C string
 */
static const char *
nfsref_lookup_display_boolean(_Bool value)
{
	return value ? "true" : "false";
}

/**
 * Display a single NFS location
 *
 * @param fsloc pointer to an NFS location structure
 */
static void
nfsref_lookup_display_nfs_location(struct nfs_fsloc *fsloc)
{
	char *rootpath;

	if (nsdb_path_array_to_posix(fsloc->nfl_rootpath, &rootpath) == FEDFS_OK) {
		printf("%s:%s\n", fsloc->nfl_hostname, rootpath);
		free(rootpath);
	} else
		printf("%s: - Invalid root path -\n", fsloc->nfl_hostname);
	printf("\n");

	printf("\tNFS port:\t%u\n", fsloc->nfl_hostport);
	printf("\tValid for:\t%d\n", fsloc->nfl_validfor);
	printf("\tCache TTL:\t%d\n", fsloc->nfl_ttl);
	printf("\tCurrency:\t%d\n", fsloc->nfl_currency);
	printf("\tFlags:\t\tvarsub(%s)\n",
		nfsref_lookup_display_boolean(fsloc->nfl_flags.nfl_varsub));

	printf("\tGenFlags:\twritable(%s), going(%s), split(%s)\n",
		nfsref_lookup_display_boolean(fsloc->nfl_genflags.nfl_writable),
		nfsref_lookup_display_boolean(fsloc->nfl_genflags.nfl_going),
		nfsref_lookup_display_boolean(fsloc->nfl_genflags.nfl_split));
	printf("\tTransFlags:\trdma(%s)\n",
		nfsref_lookup_display_boolean(fsloc->nfl_transflags.nfl_rdma));

	printf("\tClass:\t\tsimul(%u), handle(%u), fileid(%u)\n",
		fsloc->nfl_info.nfl_simul,
		fsloc->nfl_info.nfl_handle,
		fsloc->nfl_info.nfl_fileid);
	printf("\tClass:\t\twritever(%u), change(%u), readdir(%u)\n",
		fsloc->nfl_info.nfl_writever,
		fsloc->nfl_info.nfl_change,
		fsloc->nfl_info.nfl_readdir);
	printf("\tRead:\t\trank(%u), order(%u)\n",
		fsloc->nfl_info.nfl_readrank, fsloc->nfl_info.nfl_readorder);
	printf("\tWrite:\t\trank(%u), order(%u)\n",
		fsloc->nfl_info.nfl_writerank, fsloc->nfl_info.nfl_writeorder);

	printf("\n");
}

/**
 * Display a list of NFS locations
 *
 * @param fslocs list of NFS locations to display
 */
static void
nfsref_lookup_display_nfs_locations(struct nfs_fsloc *fslocs)
{
	struct nfs_fsloc *fsloc;

	for (fsloc = fslocs; fsloc != NULL; fsloc = fsloc->nfl_next)
		nfsref_lookup_display_nfs_location(fsloc);
}

/**
 * List NFS locations in an nfs-basic junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_lookup_nfs_basic(const char *junct_path)
{
	struct nfs_fsloc *fslocs = NULL;
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: Looking up basic junction in %s",
		__func__, junct_path);

	retval = nfs_is_junction(junct_path);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "%s is not an nfs-basic junction", junct_path);
		return EXIT_FAILURE;
	default:
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	retval = nfs_get_locations(junct_path, &fslocs);
	if (retval != FEDFS_OK) {
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	nfsref_lookup_display_nfs_locations(fslocs);

	nfs_free_locations(fslocs);
	return EXIT_SUCCESS;
}

/**
 * Convert a boolean value into a displayable string constant (LDAP style)
 *
 * @param value boolean value
 * @return NUL-terminated static constant C string
 */
static const char *
nfsref_lookup_display_ldap_boolean(_Bool value)
{
	return value ? "TRUE" : "FALSE";
}

/**
 * Display nfs_fsl portion of a fedfs_fsl structure
 *
 * @param nfsl pointer to a fedfs_nfs_fsl structure
 */
static void
nfsref_lookup_display_fedfs_nfs_fsl(struct fedfs_nfs_fsl *nfsl)
{
	char *rootpath;

	if (nsdb_path_array_to_posix(nfsl->fn_nfspath, &rootpath) == FEDFS_OK) {
		printf("\tfedfsNfsPath:\t\t\t%s\n", rootpath);
		free(rootpath);
	} else
		printf("\tfedfsNfsPath:\t\t\tInvalid\n");

	printf("\tfedfsNfsCurrency:\t\t%d\n", nfsl->fn_currency);
	printf("\tfedfsNfsGenFlagWritable:\t%s\n",
		nfsref_lookup_display_ldap_boolean(nfsl->fn_gen_writable));
	printf("\tfedfsNfsGenFlagGoing:\t\t%s\n",
		nfsref_lookup_display_ldap_boolean(nfsl->fn_gen_going));
	printf("\tfedfsNfsGenFlagSplit:\t\t%s\n",
		nfsref_lookup_display_ldap_boolean(nfsl->fn_gen_split));
	printf("\tfedfsNfsTransFlagRdma:\t\t%s\n",
		nfsref_lookup_display_ldap_boolean(nfsl->fn_trans_rdma));
	printf("\tfedfsNfsClassSimul:\t\t%u\n", nfsl->fn_class_simul);
	printf("\tfedfsNfsClassHandle:\t\t%u\n", nfsl->fn_class_handle);
	printf("\tfedfsNfsClassFileid:\t\t%u\n", nfsl->fn_class_fileid);
	printf("\tfedfsNfsClassWritever:\t\t%u\n", nfsl->fn_class_writever);
	printf("\tfedfsNfsClassChange:\t\t%u\n", nfsl->fn_class_change);
	printf("\tfedfsNfsClassReaddir:\t\t%u\n", nfsl->fn_class_readdir);
	printf("\tfedfsNfsReadRank:\t\t%d\n", nfsl->fn_readrank);
	printf("\tfedfsNfsReadOrder:\t\t%d\n", nfsl->fn_readorder);
	printf("\tfedfsNfsWriteRank:\t\t%d\n", nfsl->fn_writerank);
	printf("\tfedfsNfsWriteOrder:\t\t%d\n", nfsl->fn_writeorder);
	printf("\tfedfsNfsVarSub:\t\t\t%s\n",
		nfsref_lookup_display_ldap_boolean(nfsl->fn_varsub));
	printf("\tfedfsNfsValidFor:\t\t%d\n", nfsl->fn_validfor);
}

/**
 * Display a single FedFS fileset location
 *
 * @param fsl pointer to a fedfs_fsl structure
 */
static void
nfsref_lookup_display_fedfs_fsl(struct fedfs_fsl *fsl)
{
	int i;

	printf("FedFS Fileset Location:\n");

	printf("\tfedfsFslUuid:\t\t\t%s\n", fsl->fl_fsluuid);
	printf("\tfedfsFsnUuid:\t\t\t%s\n", fsl->fl_fsnuuid);
	printf("\tfedfsFslHost:\t\t\t%s\n", fsl->fl_fslhost);
	printf("\tfedfsFslPort:\t\t\t%u\n", fsl->fl_fslport);
	printf("\tfedfsFslTTL:\t\t\t%d\n", fsl->fl_fslttl);

	if (fsl->fl_annotations != NULL) {
		for (i = 0; fsl->fl_annotations[i] != NULL; i++)
			printf("\tfedfsAnnotation[%d]: %s\n", i,
				fsl->fl_annotations[i]);
	}

	if (fsl->fl_description != NULL) {
		for (i = 0; fsl->fl_description[i] != NULL; i++)
			printf("\tfedfsDescr[%d]: %s\n", i,
				fsl->fl_description[i]);
	}

	switch (fsl->fl_type) {
	case FEDFS_NFS_FSL:
		nfsref_lookup_display_fedfs_nfs_fsl(&fsl->fl_u.fl_nfsfsl);
		break;
	default:
		printf("\tUnknown FedFS FSL type\n");
	}

	printf("\n");
	fflush(stdout);
}

/**
 * Display a list of FedFS fileset locations
 *
 * @param fsls list of FedFS fileset locations to display
 */
static void
nfsref_lookup_display_fedfs_fsls(struct fedfs_fsl *fsls)
{
	struct fedfs_fsl *fsl;

	for (fsl = fsls; fsl != NULL; fsl = fsl->fl_next)
		nfsref_lookup_display_fedfs_fsl(fsl);
}

/**
 * Resolve a FedFS fileset name
 *
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to resolve
 * @param host an initialized NSDB handle
 * @return program exit status
 */
static int
nfsref_lookup_resolve_fsn(const char *fsn_uuid, nsdb_t host)
{
	int status = EXIT_FAILURE;
	struct fedfs_fsl *fsls;
	unsigned int ldap_err;
	FedFsStatus retval;

	xlog(D_GENERAL, "%s: resolving FSN UUID %s with NSDB %s:%u",
		__func__, fsn_uuid, nsdb_hostname(host), nsdb_port(host));

	if (nsdb_open_nsdb(host, NULL, NULL, &ldap_err) != FEDFS_OK)
		return status;

	retval = nsdb_resolve_fsn_s(host, NULL, fsn_uuid, &fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		nfsref_lookup_display_fedfs_fsls(fsls);
		nsdb_free_fedfs_fsls(fsls);
		status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		xlog(L_ERROR, "%s: No FSL entries for FSN %s",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		xlog(L_ERROR, "%s: No FSN %s found",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		xlog(L_ERROR, "%s: NSDB operation failed with %s",
			__func__, ldap_err2string(ldap_err));
		break;
	default:
		xlog(L_ERROR, "%s: Failed to resolve FSN %s: %s",
			__func__, fsn_uuid, nsdb_display_fedfsstatus(status));
	}

	nsdb_close_nsdb(host);
	return status;
}

/**
 * Resolve a local FedFS-style junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_lookup_nfs_fedfs(const char *junct_path)
{
	FedFsStatus retval;
	char *fsn_uuid;
	nsdb_t host;
	int status;

	xlog(D_GENERAL, "%s: Looking up FedFS junction in %s",
		__func__, junct_path);

	retval = fedfs_is_junction(junct_path);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NOTJUNCT:
		xlog(L_ERROR, "%s is not an nfs-fedfs junction", junct_path);
		return EXIT_FAILURE;
	default:
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	retval = fedfs_get_fsn(junct_path, &fsn_uuid, &host);
	if (retval != FEDFS_OK) {
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	status = nfsref_lookup_resolve_fsn(fsn_uuid, host);

	free(fsn_uuid);
	nsdb_free_nsdb(host);
	return status;
}

/**
 * Resolve either a FedFS or NFS basic junction
 *
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
static int
nfsref_lookup_unspecified(const char *junct_path)
{
	FedFsStatus retval;

	retval = nfs_is_junction(junct_path);
	if (retval == FEDFS_OK)
		return nfsref_lookup_nfs_basic(junct_path);
	if (retval != FEDFS_ERR_NOTJUNCT) {
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}
	retval = fedfs_is_junction(junct_path);
	if (retval == FEDFS_OK)
		return nfsref_lookup_nfs_fedfs(junct_path);
	if (retval != FEDFS_ERR_NOTJUNCT) {
		xlog(L_ERROR, "Failed to access %s: %s",
			junct_path, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}
	xlog(L_ERROR, "%s is not a junction", junct_path);
	return EXIT_FAILURE;
}

/**
 * Enumerate metadata of a junction
 *
 * @param type type of junction to add
 * @param junct_path NUL-terminated C string containing pathname of junction
 * @return program exit status
 */
int
nfsref_lookup(enum nfsref_type type, const char *junct_path)
{
	switch (type) {
	case NFSREF_TYPE_UNSPECIFIED:
		return nfsref_lookup_unspecified(junct_path);
	case NFSREF_TYPE_NFS_BASIC:
		return nfsref_lookup_nfs_basic(junct_path);
	case NFSREF_TYPE_NFS_FEDFS:
		return nfsref_lookup_nfs_fedfs(junct_path);
	default:
		xlog(L_ERROR, "Unrecognized junction type");
	}
	return EXIT_FAILURE;
}
