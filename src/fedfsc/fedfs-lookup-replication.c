/**
 * @file src/fedfsc/fedfs-lookup-replication.c
 * @brief Send a FEDFS_LOOKUP_REPLICATION RPC to a FedFS ADMIN server
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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

#include <rpc/clnt.h>
#include <uuid/uuid.h>
#include <ldap.h>

#include "fedfs.h"
#include "fedfs_admin.h"
#include "nsdb.h"
#include "junction.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Default RPC request timeout
 */
static struct timeval fedfs_lookup_replication_timeout = { 25, 0 };

/**
 * Short form command line options
 */
static const char fedfs_lookup_replication_opts[] = "?dh:n:t:";

/**
 * Long form command line options
 */
static const struct option fedfs_lookup_replication_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nettype", 1, NULL, 'n', },
	{ "resolvetype", 1, NULL, 't', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
fedfs_lookup_replication_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname] "
			"[-t <none|cache|nsdb>] path\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-t, --resolvetype    Type of desired result (default: 'none')\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit((int)FEDFS_ERR_INVAL);
}

/**
 * Parse name of resolvetype to resolvetype number
 *
 * @param resolvetype NUL-terminated C string containing name of requested resolvetype
 * @param resolve OUT: resolvetype number
 * @return true if "resolvetype" is a valid resolvetype
 */
static _Bool
fedfs_lookup_replication_get_resolvetype(const char *resolvetype, FedFsResolveType *resolve)
{
	if (strcmp(resolvetype, "0") == 0 ||
	    strcasecmp(resolvetype, "none") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_none") == 0) {
		*resolve = FEDFS_RESOLVE_NONE;
		return true;
	}
	if (strcmp(resolvetype, "1") == 0 ||
	    strcasecmp(resolvetype, "cache") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_cache") == 0) {
		*resolve = FEDFS_RESOLVE_CACHE;
		return true;
	}
	if (strcmp(resolvetype, "2") == 0 ||
	    strcasecmp(resolvetype, "nsdb") == 0 ||
	    strcasecmp(resolvetype, "fedfs_resolve_nsdb") == 0) {
		*resolve = FEDFS_RESOLVE_NSDB;
		return true;
	}
	return false;
}

/**
 * Display FSN UUID information in a FEDFS_LOOKUP_REPLICATION result
 *
 * @param pre_text NUL-terminated C string containing prefix to display
 * @param uuid UUID to display
 */
static void
fedfs_lookup_replication_print_uuid(const char *pre_text, const FedFsUuid uuid)
{
	char buf[FEDFS_UUID_STRLEN];
	uuid_t uu;

	memcpy(uu, uuid, sizeof(uu));
	uuid_unparse(uu, buf);
	printf("%s: %s\n", pre_text, buf);
}

/**
 * Display FSN NSDB information in a FEDFS_LOOKUP_REPLICATION result
 *
 * @param pre_text NUL-terminated C string containing prefix to display
 * @param nsdbname NSDB information to display
 */
static void
fedfs_lookup_replication_print_nsdbname(const char *pre_text,
		const FedFsNsdbName nsdbname)
{
	if (nsdbname.hostname.utf8string_val == NULL) {
		printf("%s: NSDB name was empty\n", pre_text);
		return;
	}
	printf("%s: %.*s:%u\n", pre_text,
		nsdbname.hostname.utf8string_len,
		nsdbname.hostname.utf8string_val,
		nsdbname.port);
}

/**
 * Display FSN information in a FEDFS_LOOKUP_REPLICATION result
 *
 * @param fsn FSN information to display
 */
static void
fedfs_lookup_replication_print_fsn(const FedFsFsn fsn)
{
	fedfs_lookup_replication_print_uuid("Fsn UUID", fsn.fsnUuid);
	fedfs_lookup_replication_print_nsdbname("Fsn NSDB name", fsn.nsdbName);
}

/**
 * Display one NFS FSL in a FEDFS_LOOKUP_REPLICATION result
 *
 * @param fsl FSL record to display
 */
static void
fedfs_lookup_replication_print_nfs_fsl(FedFsNfsFsl fsl)
{
	FedFsStatus status;
	char **path_array;
	unsigned int i;

	fedfs_lookup_replication_print_uuid("Fsl UUID", fsl.fslUuid);
	if (fsl.hostname.utf8string_val == NULL)
		printf("FSL hostname: empty\n");
	else
		printf("FSL hostname: %.*s:%u\n",
			fsl.hostname.utf8string_len,
			fsl.hostname.utf8string_val,
			fsl.port);
	status = nsdb_fedfspathname_to_path_array(fsl.path, &path_array);
	if (status != FEDFS_OK)
		printf("Returned NFS export pathname was invalid: %s\n",
			nsdb_display_fedfsstatus(status));
	else {
		if (path_array[0] == NULL)
			printf(" FSL NFS pathname: /\n");
		else {
			printf(" FSL NFS pathname: ");
			for (i = 0; path_array[i] != NULL; i++)
				printf("/%s", path_array[i]);
			printf("\n");
		}

		nsdb_free_string_array(path_array);
	}
}

/**
 * Display one FSL in a FEDFS_LOOKUP_REPLICATION result
 *
 * @param fsl FSL record to display
 */
static void
fedfs_lookup_replication_print_fsl(FedFsFsl fsl)
{
	switch (fsl.type) {
	case FEDFS_NFS_FSL:
		fedfs_lookup_replication_print_nfs_fsl(fsl.FedFsFsl_u. nfsFsl);
		break;
	default:
		printf("Unsupported FSL type\n");
	}
}

/**
 * Display results of a successful FEDFS_LOOKUP_REPLICATION request
 *
 * @param result results to display
 */
static void
fedfs_lookup_replication_print_resok(FedFsLookupResOk result)
{
	unsigned int i;

	fedfs_lookup_replication_print_fsn(result.fsn);

	if (result.fsl.fsl_len == 0) {
		printf("Empty FSL list\n");
		return;
	}
	printf("Returned FSLs:\n");
	for (i = 0; i <= result.fsl.fsl_len; i++)
		fedfs_lookup_replication_print_fsl(result.fsl.fsl_val[i]);
}

/**
 * Display results of FEDFS_LOOKUP_REPLICATION when an LDAP/NSDB failure is reported
 *
 * @param result results to display
 */
static void
fedfs_lookup_replication_print_ldapresultcode(FedFsLookupRes result)
{
	int ldap_err = result.FedFsLookupRes_u.ldapResultCode;

	fprintf(stderr, "LDAP result code (%d): %s\n",
		ldap_err, ldap_err2string(ldap_err));
}

/**
 * Display results of FEDFS_LOOKUP_JUNCTION request
 *
 * @param result results to display
 */
static void
fedfs_lookup_replication_print_result(FedFsLookupRes result)
{
	nsdb_print_fedfsstatus(result.status);
	switch (result.status) {
	case FEDFS_OK:
		fedfs_lookup_replication_print_resok(result.FedFsLookupRes_u.resok);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fedfs_lookup_replication_print_ldapresultcode(result);
		break;
	default:
		break;
	}
}

/**
 * Request a remote fileserver to resolve a replication
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param path NUL-terminated C string containing remote pathname of replication to resolve
 * @param resolvetype NUL-terminated C string containing name of requested resolvetype
 * @return a FedFsStatus code
 */
static int
fedfs_lookup_replication_call(const char *hostname, const char *nettype,
		const char *path, const char *resolvetype)
{
	FedFsLookupRes result;
	enum clnt_stat status;
	FedFsLookupArgs arg;
	char **path_array;
	CLIENT *client;

	memset(&arg, 0, sizeof(arg));

	if (!fedfs_lookup_replication_get_resolvetype(resolvetype, &arg.resolve))
		return FEDFS_ERR_INVAL;
	arg.path.type = FEDFS_PATH_SYS;
	result.status = nsdb_posix_to_path_array(path, &path_array);
	if (result.status != FEDFS_OK) {
		fprintf(stderr, "Failed to encode pathname: %s",
			nsdb_display_fedfsstatus(result.status));
		return result.status;
	}
	result.status = nsdb_path_array_to_fedfspathname(path_array,
						&arg.path.FedFsPath_u.adminPath);
	if (result.status != FEDFS_OK) {
		fprintf(stderr, "Failed to encode pathname: %s",
			nsdb_display_fedfsstatus(result.status));
		nsdb_free_string_array(path_array);
		return result.status;
	}

	client = clnt_create(hostname, FEDFS_PROG, FEDFS_V1, nettype);
	if (client == NULL) {
		clnt_pcreateerror("Failed to create FEDFS client");
		result.status = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	memset((char *)&result, 0, sizeof(result));
	status = clnt_call(client, FEDFS_LOOKUP_REPLICATION,
				(xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)&arg,
				(xdrproc_t)xdr_FedFsLookupRes, (caddr_t)&result,
				fedfs_lookup_replication_timeout);
	if (status != RPC_SUCCESS) {
		clnt_perror(client, "FEDFS_LOOKUP_REPLICATION call failed");
		result.status = FEDFS_ERR_SVRFAULT;
	} else {
		fedfs_lookup_replication_print_result(result);
		clnt_freeres(client,
			(xdrproc_t)xdr_FedFsLookupRes,
			(caddr_t)&result);
	}
	(void)clnt_destroy(client);

out:
	nsdb_free_fedfspathname(&arg.path.FedFsPath_u.adminPath);
	nsdb_free_string_array(path_array);
	return result.status;
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
	char *progname, *hostname, *nettype, *path, *resolvetype;
	unsigned int seconds;
	FedFsStatus status;
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

	hostname = "localhost";
	nettype = "netpath";
	resolvetype = "none";
	path = NULL;
	while ((arg = getopt_long(argc, argv, fedfs_lookup_replication_opts,
				fedfs_lookup_replication_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'n':
			nettype = optarg;
			break;
		case 'p':
			path = optarg;
			break;
		case 't':
			resolvetype = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			fedfs_lookup_replication_usage(progname);
		}
	}
	if (argc == optind + 1)
		path = argv[optind];
	else if (argc > optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		fedfs_lookup_replication_usage(progname);
	} else {
		fprintf(stderr, "No replication pathname was specified\n");
		fedfs_lookup_replication_usage(progname);
	}

	for (seconds = FEDFS_DELAY_MIN_SECS;; seconds = fedfs_delay(seconds)) {
		status = fedfs_lookup_replication_call(hostname, nettype,
							path, resolvetype);
		if (status != FEDFS_ERR_DELAY)
			break;

		xlog(D_GENERAL, "Delaying %u seconds...", seconds);
		if (sleep(seconds) != 0)
			break;
	}
	return (int)status;
}
