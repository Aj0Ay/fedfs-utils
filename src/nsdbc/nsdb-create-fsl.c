/**
 * @file src/nsdbc/nsdb-create-fsl.c
 * @brief Create a FedFS FSL entry on a target NSDB server
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
static const char nsdb_create_fsl_opts[] = "?dD:e:l:o:p:r:s:w:u:x:";

/**
 * Long form command line options
 */
static const struct option nsdb_create_fsl_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "fsluuid", 1, NULL, 'x', },
	{ "fsnuuid", 1, NULL, 'u', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "servername", 1, NULL, 's', },
	{ "serverpath", 1, NULL, 'p', },
	{ "serverport", 1, NULL, 'o', },
	{ "password", 1, NULL, 'w', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_create_fsl_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] [ -w passwd ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ] "
			"-u fsn-uuid -x fsl-uuid -s servername "
			"[ -t serverport ] [ -p serverpath ]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-p, --serverpath     File server export path\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-s, --servername     File server hostname to set\n");
	fprintf(stderr, "\t-o, --serverport     File server port to set\n");
	fprintf(stderr, "\t-w, --password       Bind password\n");
	fprintf(stderr, "\t-u, --fsnuuid        FSN UUID of FSL's parent\n");
	fprintf(stderr, "\t-x, --fsluuid        New FSL UUID\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit(EXIT_FAILURE);
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
	char *nce, *fsn_uuid, *fsl_uuid, *servername, *serverpath;
	char *progname, *binddn, *passwd, *nsdbname;
	unsigned short nsdbport, serverport;
	unsigned int ldap_err;
	int arg, exit_status;
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

	nsdb_env(&nsdbname, &nsdbport, &binddn, &nce);

	serverport = 0;
	passwd = fsn_uuid = fsl_uuid = servername = serverpath = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_create_fsl_opts,
			nsdb_create_fsl_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'e':
			nce = optarg;
			break;
		case 'l':
			nsdbname = optarg;
			break;
		case 'o':
			if (!nsdb_parse_port_string(optarg, &serverport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_create_fsl_usage(progname);
			}
			break;
		case 'p':
			serverpath = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_create_fsl_usage(progname);
			}
			break;
		case 's':
			servername = optarg;
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'u':
			if (uuid_parse(optarg, uu) == -1) {
				fprintf(stderr, "Invalid FSN UUID: %s\n", optarg);
				nsdb_create_fsl_usage(progname);
			}
			fsn_uuid = optarg;
			break;
		case 'x':
			if (uuid_parse(optarg, uu) == -1) {
				fprintf(stderr, "Invalid FSL UUID: %s\n", optarg);
				nsdb_create_fsl_usage(progname);
			}
			fsl_uuid = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_create_fsl_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_create_fsl_usage(progname);
	}
	if (nce == NULL || fsn_uuid == NULL || fsl_uuid == NULL ||
	    nsdbname == NULL || servername == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_create_fsl_usage(progname);
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

	if (binddn == NULL)
		binddn = (char *)nsdb_default_binddn(host);
	retval = nsdb_open_nsdb(host, binddn, passwd, &ldap_err);
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

	if (nce == NULL)
		nce = (char *)nsdb_default_nce(host);
	retval = nsdb_create_fsl_s(host, nce, fsn_uuid, fsl_uuid, nsdbname, nsdbport,
					servername, serverport, serverpath, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully created FSL %s\n", fsl_uuid);
		exit_status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "Failed to create FSL %s: %s\n",
			fsl_uuid, ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "Failed to create FSL %s: %s\n",
			fsl_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit(exit_status);
}
