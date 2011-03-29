/**
 * @file src/fedfsc/fedfs-create-replication.c
 * @brief Send a FEDFS_CREATE_REPLICATION RPC to a FedFS ADMIN server
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

#include "fedfs.h"
#include "fedfs_admin.h"
#include "nsdb.h"
#include "junction.h"
#include "path.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Default RPC request timeout
 */
static struct timeval fedfs_create_replication_timeout = { 25, 0 };

/**
 * Short form command line options
 */
static const char fedfs_create_replication_opts[] = "?dh:l:n:p:r:u:";

/**
 * Long form command line options
 */
static const struct option fedfs_create_replication_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "hostname", 1, NULL, 'h', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nettype", 1, NULL, 'n', },
	{ "path", 1, NULL, 'p', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "fsnuuid", 1, NULL, 'u', },
	{ NULL, 0, NULL, 0, },
};

static void
fedfs_create_replication_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [-d] [-n nettype] [-h hostname] "
			"-p path -u fsn-uuid -l nsdbname [-r nsdbport]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-n, --nettype        RPC transport (default: 'netpath')\n");
	fprintf(stderr, "\t-h, --hostname       ADMIN server hostname (default: 'localhost')\n");
	fprintf(stderr, "\t-p, --path           Pathname of new junction\n");
	fprintf(stderr, "\t-u, --fsnuuid        FSN UUID to set\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname to set\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port to set\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit(EXIT_FAILURE);
}

static int
fedfs_create_replication_call(const char *hostname, const char *nettype,
		const char *path, const char *uuid, char *nsdbname,
		const unsigned short nsdbport)
{
	FedFsCreateArgs arg;
	enum clnt_stat status;
	int res, exit_status;
	FedFsStatus result;
	CLIENT *client;
	uuid_t uu;

	memset(&arg, 0, sizeof(arg));

	res = uuid_parse(uuid, uu);
	if (res != 0) {
		fprintf(stderr, "Failed to parse UUID %s\n", uuid);
		return EXIT_FAILURE;
	}
	memcpy(arg.fsn.fsnUuid, uu, sizeof(FedFsUuid));

	arg.fsn.nsdbName.hostname.utf8string_val = nsdbname;
	arg.fsn.nsdbName.hostname.utf8string_len = strlen(nsdbname);
	arg.fsn.nsdbName.port = nsdbport;

	arg.path.type = FEDFS_PATH_SYS;
	result = nsdb_posix_to_fedfspathname(path,
				&arg.path.FedFsPath_u.adminPath);
	if (result != FEDFS_OK) {
		fprintf(stderr, "Failed to encode pathname: %s",
			nsdb_display_fedfsstatus(result));
		return EXIT_FAILURE;
	}

	exit_status = EXIT_SUCCESS;

	client = clnt_create(hostname, FEDFS_PROG, FEDFS_V1, nettype);
	if (client == NULL) {
		clnt_pcreateerror("Failed to create FEDFS client");
		exit_status = EXIT_FAILURE;
		goto out;
	}

	memset((char *)&result, 0, sizeof(result));
	status = clnt_call(client, FEDFS_CREATE_REPLICATION,
				(xdrproc_t)xdr_FedFsCreateArgs,
				(caddr_t)&arg,
				(xdrproc_t)xdr_FedFsStatus, (caddr_t)&result,
				fedfs_create_replication_timeout);
	if (status != RPC_SUCCESS) {
		clnt_perror(client, "FEDFS_CREATE_REPLICATION call failed");
		exit_status = EXIT_FAILURE;
	} else
		nsdb_print_fedfsstatus(result);
	(void)clnt_destroy(client);

out:
	nsdb_free_fedfspathname(&arg.path.FedFsPath_u.adminPath);
	return exit_status;
}

int
main(int argc, char **argv)
{
	char *progname, *hostname, *nettype;
	char *uuid, *path, *nsdbname;
	unsigned short nsdbport;
	int arg, exit_status;

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
	uuid = path = NULL;
	while ((arg = getopt_long(argc, argv, fedfs_create_replication_opts,
			fedfs_create_replication_longopts, NULL)) != -1) {
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
				fedfs_create_replication_usage(progname);
			}
			nsdbname = optarg;
			break;
		case 'n':
			nettype = optarg;
			break;
		case 'p':
			path = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				fedfs_create_replication_usage(progname);
			}
			break;
		case 'u':
			uuid = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			fedfs_create_replication_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		fedfs_create_replication_usage(progname);
	}
	if (path == NULL || uuid == NULL || nsdbname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		fedfs_create_replication_usage(progname);
	}

	exit_status = fedfs_create_replication_call(hostname, nettype, path, uuid,
							nsdbname, nsdbport);

	exit(exit_status);
}
