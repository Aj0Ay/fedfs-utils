/**
 * @file src/nsdbc/nsdb-list.c
 * @brief List the DNs of all FedFs entries stored on a target NSDB server
 *
 * @todo
 *	When no NCE is given, it should display the NCE it found
 *	Maybe that doesn't really matter?
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
#include <netdb.h>
#include <locale.h>
#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_list_opts[] = "?de:f:l:r:";

/**
 * Long form command line options
 */
static const struct option nsdb_list_longopts[] = {
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
nsdb_list_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit((int)FEDFS_ERR_INVAL);
}

/**
 * Display the returned FSL list
 *
 * @param fsls a list of fedfs_fsl structures
 */
static void
nsdb_list_display_fsls(struct fedfs_fsl *fsls)
{
	for ( ; fsls != NULL; fsls = fsls->fl_next) {
		printf("      FSL UUID: %s\n", fsls->fl_fsluuid);
	}
}

/**
 * Resolve an FSN and display the returned FSL list
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 */
static void
nsdb_list_resolve_and_display_fsn(nsdb_t host, const char *nce, const char *fsn_uuid)
{
	struct fedfs_fsl *fsls;
	unsigned int ldap_err;
	FedFsStatus retval;

	printf("    FSN UUID: %s\n", fsn_uuid);

	retval = nsdb_resolve_fsn_s(host, nce, fsn_uuid, &fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		nsdb_list_display_fsls(fsls);
		nsdb_free_fedfs_fsls(fsls);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		printf("      No FSL entries found\n");
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "NSDB LDAP error: %s\n",
			ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "Failed to resolve FSN UUID %s: %s\n",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

	printf("\n");
}

/**
 * Display FSNs under a specific NCE
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_list_display_one_nce(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char **fsns;
	int i;

	retval = nsdb_list_s(host, nce, &fsns, ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("  NCE: %s\n\n", nce);
		for (i = 0; fsns[i] != NULL; i++)
			nsdb_list_resolve_and_display_fsn(host, nce, fsns[i]);
		nsdb_free_string_array(fsns);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		printf("  NCE %s has no FSN records\n", nce);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		printf("  NCE %s does not exist\n", nce);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		break;
	default:
		fprintf(stderr, "Failed to retrieve FSNs: %s\n",
			nsdb_display_fedfsstatus(retval));
	}
	return retval;
}

/**
 * Display FSNs under a specific NCE, with header
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_list_display_nce(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	printf("NSDB: %s:%u\n\n", nsdb_hostname(host), nsdb_port(host));
	return nsdb_list_display_one_nce(host, nce, ldap_err);

}

/**
 * Display FSNs under all NCEs, with header
 *
 * @param host an initialized and bound nsdb_t object
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_list_display_all_nces(nsdb_t host, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn, **contexts;
	int i;

	retval = nsdb_get_naming_contexts_s(host, &contexts, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	printf("NSDB: %s:%u\n\n", nsdb_hostname(host), nsdb_port(host));

	retval = FEDFS_ERR_NSDB_NONCE;
	for (i = 0; contexts[i] != NULL; i++) {
		retval = nsdb_get_ncedn_s(host, contexts[i], &dn, ldap_err);
		if (retval == FEDFS_OK) {
			retval = nsdb_list_display_one_nce(host, dn, ldap_err);
			free(dn);
			if (retval != FEDFS_OK)
				break;
		}
	}

	nsdb_free_string_array(contexts);
	return retval;
}

/**
 * Attempt to follow an LDAP referral to another NSDB
 *
 * @param host OUT: pointer to an initialized nsdb_t that may be replaced
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_list_follow_ldap_referral(nsdb_t *host)
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
		fprintf(stderr, "Problem following referral: %s",
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
	unsigned int ldap_err;
	FedFsStatus retval;
	nsdb_t host;
	char *nce;
	int arg;

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

	while ((arg = getopt_long(argc, argv, nsdb_list_opts,
			nsdb_list_longopts, NULL)) != -1) {
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
				nsdb_list_usage(progname);
			}
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_list_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_list_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_list_usage(progname);
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

	if (nce != NULL)
		retval = nsdb_list_display_nce(host, nce, &ldap_err);
	else
		retval = nsdb_list_display_all_nces(host, &ldap_err);
	if (retval == FEDFS_ERR_NSDB_LDAP_VAL) {
		switch (ldap_err) {
		case LDAP_REFERRAL:
			retval = nsdb_list_follow_ldap_referral(&host);
			if (retval == FEDFS_OK)
				goto again;
			break;
		case LDAP_CONFIDENTIALITY_REQUIRED:
			fprintf(stderr, "TLS security required for %s:%u\n",
				nsdbname, nsdbport);
			break;
		default:
			fprintf(stderr, "Failed to list FSNs: %s\n",
				ldap_err2string(ldap_err));
		}
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
