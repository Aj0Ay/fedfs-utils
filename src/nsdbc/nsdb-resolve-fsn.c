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

#include <rpcsvc/nfs_prot.h>
#include <uuid/uuid.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_resolve_fsn_opts[] = "?de:l:r:";

/**
 * Long form command line options
 */
static const struct option nsdb_resolve_fsn_longopts[] = {
	{ "debug", 0, NULL, 'd', },
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
			"fsn-uuid\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit((int)FEDFS_ERR_INVAL);
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
	FedFsStatus status;
	char *rootpath;

	status = nsdb_path_array_to_posix(nfsl->fn_nfspath, &rootpath);
	if (status != FEDFS_OK)
		return;

	if (nfsl->fn_fslport == 0 || nfsl->fn_fslport == NFS_PORT)
		printf(" NFS fls_server:\t\t%s\n", nfsl->fn_fslhost);
	else
		printf(" NFS fls_server:\t\t%s:%u\n", nfsl->fn_fslhost,
			nfsl->fn_fslport);

	printf(" NFS fli_rootpath:\t\t%s\n", rootpath);
	free(rootpath);

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

	printf("------------------------------------------------------\n");
	printf("dn: %s\n\n", fsl->fl_dn);

	printf(" FSN UUID:\t\t%s\n", fsl->fl_fsnuuid);
	printf(" FSL UUID:\t\t%s\n", fsl->fl_fsluuid);

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
 * Attempt to follow an LDAP referral to another NSDB
 *
 * @param host OUT: pointer to an initialized nsdb_t that may be replaced
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_resolve_fsn_follow_ldap_referral(nsdb_t *host)
{
	static unsigned int nest = 0;
	FedFsStatus retval;
	nsdb_t old, refer;

	old = *host;
	if (!nsdb_follow_referrals(old)) {
		fprintf(stderr, "LDAP referrals for NSDB %s:%u disallowed\n",
			nsdb_hostname(old), nsdb_port(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	}

	if (nest++ > 10) {
		fprintf(stderr, "Possible referral loop for NSDB %s:%u\n",
			nsdb_hostname(old), nsdb_port(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	}

	retval = nsdb_lookup_nsdb_by_uri(nsdb_referred_to(old), &refer);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		fprintf(stderr, "Encountered referral to unrecognized NSDB %s\n",
			nsdb_referred_to(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	default:
		fprintf(stderr, "Problem following referral: %s\n",
			nsdb_display_fedfsstatus(retval));
		return retval;
	}

	nsdb_close_nsdb(old);
	nsdb_free_nsdb(old);
	*host = refer;
	return FEDFS_OK;
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
	struct fedfs_fsn *fsn;
	unsigned int ldap_err;
	char *nce, *fsn_uuid;
	FedFsStatus retval;
	int fsn_ttl, arg;
	nsdb_t host;

	(void)setlocale(LC_ALL, "");
	(void)umask(S_IRWXO);

	/* Set the basename */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	/* For the libraries */
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

	nsdb_env(&nsdbname, &nsdbport, NULL, &nce);

	fsn_uuid = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_resolve_fsn_opts,
			nsdb_resolve_fsn_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			nsdb_enable_ldap_debugging();
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
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_resolve_fsn_usage(progname);
		}
	}
	if (argc == optind + 1) {
		uuid_t uu;
		fsn_uuid = argv[optind];
		if (uuid_parse(fsn_uuid, uu) == -1) {
			fprintf(stderr, "Invalid FSN UUID was specified\n");
			nsdb_resolve_fsn_usage(progname);
		}
	} else if (argc >  optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		nsdb_resolve_fsn_usage(progname);
	} else {
		fprintf(stderr, "No FSN UUID was specified\n");
		nsdb_resolve_fsn_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "No NSDB hostname was specified\n");
		nsdb_resolve_fsn_usage(progname);
	}

	retval = nsdb_lookup_nsdb(nsdbname, nsdbport, &host);
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

again:
	retval = nsdb_open_nsdb(host, NULL, NULL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_CONN:
		fprintf(stderr, "Failed to connect to NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_AUTH:
		fprintf(stderr, "Failed to establish secure connection "
			"to NSDB %s:%u\n", nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "Failed to bind to NSDB %s:%u: %s\n",
			nsdbname, nsdbport, ldap_err2string(ldap_err));
		goto out_free;
	default:
		fprintf(stderr, "Failed to open NSDB %s:%u: %s\n",
			nsdbname, nsdbport,
			nsdb_display_fedfsstatus(retval));
		goto out_free;
	}

	retval = nsdb_get_fsn_s(host, nce, fsn_uuid, &fsn, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		fsn_ttl = fsn->fn_fsnttl;
		nsdb_free_fedfs_fsn(fsn);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
		goto out_close;
	case FEDFS_ERR_NSDB_NOFSN:
		fprintf(stderr, "Failed to find FSN %s\n", fsn_uuid);
		goto out_close;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_REFERRAL:
			retval = nsdb_resolve_fsn_follow_ldap_referral(&host);
			if (retval == FEDFS_OK)
				goto again;
			break;
		case LDAP_CONFIDENTIALITY_REQUIRED:
			fprintf(stderr, "TLS security required for %s:%u\n",
				nsdbname, nsdbport);
			break;
		default:
			fprintf(stderr, "NSDB LDAP error: %s\n",
				ldap_err2string(ldap_err));
		}
		goto out_close;
	default:
		fprintf(stderr, "FedFsStatus code "
			"while retrieving FSN UUID %s: %s\n",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
		goto out_close;
	}

	retval = nsdb_resolve_fsn_s(host, nce, fsn_uuid, &fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("For FSN UUID: %s\n", fsn_uuid);
		printf("    FSN TTL: %d\n\n", fsn_ttl);
		nsdb_resolve_fsn_display_fsls(fsls);
		nsdb_free_fedfs_fsls(fsls);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		printf("For FSN UUID: %s\n", fsn_uuid);
		printf("    FSN TTL: %d\n", fsn_ttl);
		printf("    No FSL entries found\n");
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		fprintf(stderr, "Failed to find FSN %s\n", fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		if (ldap_err == LDAP_REFERRAL) {
			retval = nsdb_resolve_fsn_follow_ldap_referral(&host);
			if (retval != FEDFS_OK)
				break;
			goto again;
		}
		fprintf(stderr, "NSDB LDAP error: %s\n",
			ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "FedFsStatus code "
			"while resolving FSN UUID %s: %s\n",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

out_close:
	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
