/**
 * @file src/nsdbc/nsdb-resolve-fsn.c
 * @brief Resolve an FSN UUID to FSL information using a target NSDB server
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

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <netdb.h>
#include <langinfo.h>

#include <uuid/uuid.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_resolve_fsn_opts[] = "?de:l:r:u:";

/**
 * Long form command line options
 */
static const struct option nsdb_resolve_fsn_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "fsnuuid", 1, NULL, 'u', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_resolve_fsn_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ] "
			"-u fsn-uuid\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-u, --fsnuuid        FSN UUID to resolve\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit(EXIT_FAILURE);
}

/**
 * Return presentation string for a boolean value
 *
 * @param value a boolean value
 * @return NUL-terminate C string
 */
static const char *
_display_bool(const _Bool value)
{
	return value ? "TRUE" : "FALSE";
}

/**
 * Display nfs_fsl portion of a fedfs_fsl structure
 *
 * @param nfsl pointer to a fedfs_nfs_fsl structure
 */
static void
nsdb_resolve_fsn_display_nfs_fsl(struct fedfs_nfs_fsl *nfsl)
{
	printf(" NFS fli_rootpath:\t\t%s\n", nfsl->fn_path);
	printf(" NFS major version:\t\t%d\n", nfsl->fn_majorver);
	printf(" NFS minor version:\t\t%d\n", nfsl->fn_minorver);
	printf(" NFS fls_currency:\t\t%d\n", nfsl->fn_currency);
	printf(" NFS FSLI4GF_WRITABLE:\t\t%s\n", _display_bool(nfsl->fn_gen_writable));
	printf(" NFS FSLI4GF_GOING:\t\t%s\n", _display_bool(nfsl->fn_gen_going));
	printf(" NFS FSLI4GF_SPLIT:\t\t%s\n", _display_bool(nfsl->fn_gen_split));
	printf(" NFS FSLI4TF_RDMA:\t\t%s\n", _display_bool(nfsl->fn_trans_rdma));
	printf(" NFS FSLI4BX_CLSIMUL:\t\t%d\n", nfsl->fn_class_simul);
	printf(" NFS FSLI4BX_CLHANDLE:\t\t%d\n", nfsl->fn_class_handle);
	printf(" NFS FSLI4BX_CLFILEID:\t\t%d\n", nfsl->fn_class_fileid);
	printf(" NFS FSLI4BX_CLWRITEVER:\t%d\n", nfsl->fn_class_writever);
	printf(" NFS FSLI4BX_CLCHANGE:\t\t%d\n", nfsl->fn_class_change);
	printf(" NFS FSLI4BX_CLREADDIR:\t\t%d\n", nfsl->fn_class_readdir);
	printf(" NFS FSLI4BX_READRANK:\t\t%d\n", nfsl->fn_readrank);
	printf(" NFS FSLI4BX_READORDER:\t\t%d\n", nfsl->fn_readorder);
	printf(" NFS FSLI4BX_WRITERANK:\t\t%d\n", nfsl->fn_writerank);
	printf(" NFS FSLI4BX_WRITEORDER:\t%d\n", nfsl->fn_writeorder);
	printf(" NFS FSLI4F_VAR_SUB:\t\t%s\n", _display_bool(nfsl->fn_varsub));
	printf(" NFS fli_valid_for:\t\t%d\n", nfsl->fn_validfor);

	printf("\n");
}

/**
 * Display one FSL
 *
 * @param fsl pointer to a fedfs_fsl structure
 */
static void
nsdb_resolve_fsn_display_fsl(struct fedfs_fsl *fsl)
{
	int i;

	printf("dn: %s\n\n", fsl->fl_dn);

	printf(" FSN UUID:\t\t%s\n", fsl->fl_fsnuuid);
	printf(" FSL UUID:\t\t%s\n", fsl->fl_fsluuid);
	if (fsl->fl_nsdbport == 0)
		printf(" NSDB:\t\t\t%s\n", fsl->fl_nsdbname);
	else
		printf(" NSDB:\t\t\t%s:%u\n", fsl->fl_nsdbname, fsl->fl_nsdbport);
	if (fsl->fl_fslport == 0)
		printf(" FSL host:\t\t%s\n", fsl->fl_fslhost);
	else
		printf(" FSL host:\t\t%s:%u\n", fsl->fl_fslhost, fsl->fl_fslport);
	printf(" TTL:\t\t\t%d\n\n", fsl->fl_fslttl);

	if (fsl->fl_annotations != NULL) {
		for (i = 0; fsl->fl_annotations[i] != NULL; i++)
			printf(" annotation[%d]: %s\n", i, fsl->fl_annotations[i]);
		printf("\n");
	}

	if (fsl->fl_description != NULL) {
		for (i = 0; fsl->fl_description[i] != NULL; i++)
			printf(" description[%d]: %s\n", i, fsl->fl_description[i]);
		printf("\n");
	}

	if (fsl->fl_type == FEDFS_NFS_FSL)
		nsdb_resolve_fsn_display_nfs_fsl(&fsl->fl_u.fl_nfsfsl);
}

/**
 * Display the returned FSL list
 *
 * @param fsls a list of fedfs_fsl structures
 */
static void
nsdb_resolve_fsn_display_fsls(struct fedfs_fsl *fsls)
{
	for ( ; fsls != NULL; fsls = fsls->fl_next)
		nsdb_resolve_fsn_display_fsl(fsls);
}

/**
 * Program entry point
 *
 * @param argc count of command line arguments
 * @param argv array of NUL-terminated C strings containing command line arguments
 * @return program exit status
 */
int
main(int argc, char **argv)
{
	char *progname, *nsdbname;
	unsigned short nsdbport;
	struct fedfs_fsl *fsls;
	unsigned int ldap_err;
	int arg, exit_status;
	char *nce, *fsn_uuid;
	FedFsStatus retval;
	nsdb_t host;
	uuid_t uu;

	(void)umask(S_IRWXO);

	/* Ensure UTF-8 strings can be handled transparently */
	if (setlocale(LC_CTYPE, "") == NULL ||
	    strcmp(nl_langinfo(CODESET), "UTF-8") != 0) {
		fprintf(stderr, "Failed to set locale and langinfo\n");
		exit(EXIT_FAILURE);
	}

	/* Set the basename */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	/* For the libraries */
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

	nsdb_env(&nsdbname, &nsdbport, NULL, &nce, NULL);

	fsn_uuid = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_resolve_fsn_opts,
			nsdb_resolve_fsn_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'e':
			nce = optarg;
			break;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_resolve_fsn_usage(progname);
			}
			break;
		case 'u':
			if (uuid_parse(optarg, uu) == -1) {
				fprintf(stderr, "Invalid FSN UUID: %s\n",
					optarg);
				nsdb_resolve_fsn_usage(progname);
			}
			fsn_uuid = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_resolve_fsn_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_resolve_fsn_usage(progname);
	}
	if (nsdbname == NULL || fsn_uuid == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_resolve_fsn_usage(progname);
	}

	exit_status = EXIT_FAILURE;

	retval = nsdb_lookup_nsdb(nsdbname, nsdbport, &host, NULL);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		fprintf(stderr, "No connection parameters for NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out;
	default:
		fprintf(stderr, "Failed to look up NSDB %s:%u: %s\n",
			nsdbname, nsdbport,
			nsdb_display_fedfsstatus(retval));
		goto out;
	}

	retval = nsdb_open_nsdb(host, NULL, NULL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_CONN:
		fprintf(stderr, "Failed to connect to NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_AUTH:
		fprintf(stderr, "Failed to authenticate to NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "Failed to authenticate to NSDB %s:%u: %s\n",
			nsdbname, nsdbport, ldap_err2string(ldap_err));
		goto out_free;
	default:
		fprintf(stderr, "Failed to bind to NSDB %s:%u: %s\n",
			nsdbname, nsdbport,
			nsdb_display_fedfsstatus(retval));
		goto out_free;
	}

	retval = nsdb_resolve_fsn_s(host, nce, fsn_uuid, &fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("For FSN UUID %s:\n\n", fsn_uuid);
		nsdb_resolve_fsn_display_fsls(fsls);
		nsdb_free_fsls(fsls);
		exit_status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		fprintf(stderr, "Failed to find FSL entries for FSN %s\n",
			fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		fprintf(stderr, "Failed to find FSN %s\n", fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "NSDB LDAP error: %s\n",
			ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "FedFsStatus code "
			"while resolving FSN UUID %s: %s\n",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit(exit_status);
}
