/**
 * @file src/fedfsc/fedfs-null.c
 * @brief Send a NULL RPC to a FedFS ADMIN server
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

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>

#include <rpc/clnt.h>

#include "fedfs.h"
#include "fedfs_admin.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Default RPC request timeout
 */
static struct timeval fedfs_null_timeout = { 25, 0 };

/**
 * Short form command line options
 */
static const char fedfs_null_opts[] = "?dh:n:";

/**
 * Long form command line options
 */
static const struct option fedfs_null_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nettype", 1, NULL, 'n', },
	{ NULL, 0, NULL, 0, },
};

static void
fedfs_null_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'nettype')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fflush(stderr);

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit(EXIT_FAILURE);
}

static int
fedfs_null_call(const char *hostname, const char *nettype)
{
	enum clnt_stat status;
	int exit_status;
	CLIENT *client;
	char result;

	client = clnt_create(hostname, FEDFS_PROG, FEDFS_V1, nettype);
	if (client == NULL) {
		clnt_pcreateerror("Failed to create FEDFS client");
		return EXIT_FAILURE;
	}

	exit_status = EXIT_SUCCESS;
	memset((char *)&result, 0, sizeof(result));
	status = clnt_call(client, FEDFS_NULL,
				(xdrproc_t)xdr_void, (caddr_t)NULL,
				(xdrproc_t)xdr_void, (caddr_t)&result,
				fedfs_null_timeout);
	if (status != RPC_SUCCESS) {
		clnt_perror(client, "FEDFS_NULL call failed");
		exit_status = EXIT_FAILURE;
	} else
		printf("Call completed successfully\n");

	(void)clnt_destroy(client);
	return exit_status;
}

int
main(int argc, char **argv)
{
	char *progname, *hostname, *nettype;
	int exit_status, arg;

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
	while ((arg = getopt_long(argc, argv, fedfs_null_opts, fedfs_null_longopts, NULL)) != -1) {
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
		default:
			fprintf(stderr, "Invalid command line argument: %c\n", (char)arg);
		case '?':
			fedfs_null_usage(progname);
		}
	}
	if (optind != argc)
		fedfs_null_usage(progname);

	exit_status = fedfs_null_call(hostname, nettype);

	exit(exit_status);
}
