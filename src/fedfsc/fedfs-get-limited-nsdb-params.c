/**
 * @file src/fedfsc/fedfs-get-limited-nsdb-params.c
 * @brief Send a FEDFS_GET_LIMITED_NSDB_PARAMS RPC to a FedFS ADMIN server
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

#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

#include <rpc/clnt.h>
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
static struct timeval fedfs_get_limited_nsdb_params_timeout = { 25, 0 };

/**
 * Short form command line options
 */
static const char fedfs_get_limited_nsdb_params_opts[] = "?dh:l:n:r:";

/**
 * Long form command line options
 */
static const struct option fedfs_get_limited_nsdb_params_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nettype", 1, NULL, 'n', },
	{ "nsdbport", 1, NULL, 'r', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
fedfs_get_limited_nsdb_params_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname] "
			"[-l nsdbname] [-r nsdbport]\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit((int)FEDFS_ERR_INVAL);
}

/**
 * Display NSDB information
 *
 * @param result NSDB information to display
 */
static void
fedfs_get_limited_nsdb_params_print_result(FedFsGetNsdbParamsRes result)
{
	FedFsNsdbParams *params = &result.FedFsGetNsdbParamsRes_u.params;

	if (result.status == FEDFS_ERR_NSDB_PARAMS) {
		printf("No connection parameters found\n");
		return;
	}

	nsdb_print_fedfsstatus(result.status);
	if (result.status != FEDFS_OK)
		return;

	switch (params->secType) {
	case FEDFS_SEC_NONE:
		printf("ConnectionSec: FEDFS_SEC_NONE\n");
		break;
	case FEDFS_SEC_TLS:
		printf("ConnectionSec: FEDFS_SEC_TLS\n");
		break;
	default:
		printf("Unrecognized FedFsConnectionSec value: %u\n",
				params->secType);
	}
}

/**
 * Retrieve limited NSDB information from a remote fileserver
 *
 * @param hostname NUL-terminated UTF-8 string containing ADMIN server's hostname
 * @param nettype NUL-terminated C string containing nettype to use for connection
 * @param nsdbname NUL-terminated UTF-8 string containing name of NSDB node to retrieve
 * @param nsdbport port number of NSDB node to retrieve
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_get_limited_nsdb_params_call(const char *hostname, const char *nettype,
		char *nsdbname, const unsigned short nsdbport)
{
	FedFsGetNsdbParamsRes result;
	enum clnt_stat status;
	FedFsNsdbName arg;
	CLIENT *client;

	memset(&arg, 0, sizeof(arg));

	arg.hostname.utf8string_len = strlen(nsdbname);
	arg.hostname.utf8string_val = nsdbname;
	arg.port = nsdbport;

	client = clnt_create(hostname, FEDFS_PROG, FEDFS_V1, nettype);
	if (client == NULL) {
		clnt_pcreateerror("Failed to create FEDFS client");
		result.status = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	memset((char *)&result, 0, sizeof(result));
	status = clnt_call(client, FEDFS_GET_LIMITED_NSDB_PARAMS,
				(xdrproc_t)xdr_FedFsNsdbName, (caddr_t)&arg,
				(xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes, (caddr_t)&result,
				fedfs_get_limited_nsdb_params_timeout);
	if (status != RPC_SUCCESS) {
		clnt_perror(client, "FEDFS_GET_LIMITED_NSDB_PARAMS call failed");
		result.status = FEDFS_ERR_SVRFAULT;
	} else {
		fedfs_get_limited_nsdb_params_print_result(result);
		clnt_freeres(client,
			(xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes,
			(caddr_t)&result);
	}
	(void)clnt_destroy(client);

out:
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
	char *progname, *hostname, *nettype, *nsdbname;
	unsigned short nsdbport;
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

	nsdb_env(&nsdbname, &nsdbport, NULL, NULL);

	hostname = "localhost";
	nettype = "netpath";
	while ((arg = getopt_long(argc, argv, fedfs_get_limited_nsdb_params_opts, fedfs_get_limited_nsdb_params_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'h':
			hostname = optarg;
			break;
		case 'l':
			if (!nsdb_is_hostname_utf8(optarg)) {
				fprintf(stderr, "NSDB name %s is "
					"not a UTF-8 hostname\n", optarg);
				fedfs_get_limited_nsdb_params_usage(progname);
			}
			nsdbname = optarg;
			break;
		case 'n':
			nettype = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				fedfs_get_limited_nsdb_params_usage(progname);
			}
			break;
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			fedfs_get_limited_nsdb_params_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		fedfs_get_limited_nsdb_params_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		fedfs_get_limited_nsdb_params_usage(progname);
	}

	for (seconds = FEDFS_DELAY_MIN_SECS;; seconds = fedfs_delay(seconds)) {
		status = fedfs_get_limited_nsdb_params_call(hostname, nettype,
							nsdbname, nsdbport);
		if (status != FEDFS_ERR_DELAY)
			break;

		xlog(D_GENERAL, "Delaying %u seconds...", seconds);
		if (sleep(seconds) != 0)
			break;
	}
	return (int)status;
}
