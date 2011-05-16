/**
 * @file src/nsdbc/nsdb-update-fsl.c
 * @brief Modify an attribute of a FedFS FSL entry on a target NSDB server
 *
 * @todo
 *	Add some logic to find the full DN given only the FSL uuid.
 *	For now, both the FSN and FSL uuids are required.
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

#include <uuid/uuid.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_update_fsl_opts[] = "?a:dD:e:l:r:u:v:w:x:";

/**
 * Long form command line options
 */
static const struct option nsdb_update_fsl_longopts[] = {
	{ "attribute", 1, NULL, 'a', },
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "fsluuid", 1, NULL, 'x', },
	{ "fsnuuid", 1, NULL, 'u', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "password", 1, NULL, 'w', },
	{ "value", 1, NULL, 'v', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_update_fsl_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] [ -w passwd ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ] [ -v value ] "
			"-a attribute -u fsn-uuid -x fsl-uuid\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-a, --attribute      LDAP attribute name\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-u, --fsnuuid        FSN UUID of parent FSN\n");
	fprintf(stderr, "\t-v, --value          New attribute value\n");
	fprintf(stderr, "\t-w, --password       Bind password\n");
	fprintf(stderr, "\t-x, --fsluuid        FSL UUID of FSL to update\n");

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
	char *progname, *binddn, *passwd, *nsdbname;
	char *nce, *fsn_uuid, *fsl_uuid, *attribute, *value;
	unsigned short nsdbport;
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

	passwd = fsn_uuid = fsl_uuid = attribute = value = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_update_fsl_opts,
			nsdb_update_fsl_longopts, NULL)) != -1) {
		switch (arg) {
		case 'a':
			attribute = optarg;
			break;
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
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_update_fsl_usage(progname);
			}
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'u':
			if (uuid_parse(optarg, uu) == -1) {
				fprintf(stderr, "Invalid FSN UUID: %s\n", optarg);
				nsdb_update_fsl_usage(progname);
			}
			fsn_uuid = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'x':
			if (uuid_parse(optarg, uu) == -1) {
				fprintf(stderr, "Invalid FSL UUID: %s\n", optarg);
				nsdb_update_fsl_usage(progname);
			}
			fsl_uuid = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_update_fsl_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_update_fsl_usage(progname);
	}
	if (nsdbname == NULL || attribute == NULL ||
	    fsn_uuid == NULL || fsl_uuid == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_update_fsl_usage(progname);
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
	retval = nsdb_update_fsl_s(host, nce, fsn_uuid, fsl_uuid,
					attribute, value, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully updated FSL record\n"
			"  fedfsFslUuid=%s,fedfsFsnUuid=%s,%s\n",
				fsl_uuid, fsn_uuid, nce);
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
		fprintf(stderr, "Failed to update FSL %s: %s\n",
			fsl_uuid, ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "Failed to update FSL %s: %s\n",
			fsl_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit(exit_status);
}
