/**
 * @file src/nsdbc/nsdb-simple-nce.c
 * @brief Create a simple NSDB container entry on a target NSDB server
 */

/*
 * Copyright 2012 Oracle.  All rights reserved.
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
#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_simple_nce_opts[] = "?dD:l:qr:";

/**
 * Long form command line options
 */
static const struct option nsdb_simple_nce_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
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
nsdb_simple_nce_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] "
			"[ -l nsdbname ] [ -r nsdbport ] "
			"parent-dn\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);

	exit((int)FEDFS_ERR_INVAL);
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
	char *progname, *binddn, *nsdbname, *nce, *parent;
	unsigned short nsdbport;
	unsigned int ldap_err;
	FedFsStatus retval;
	nsdb_t host;
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

	nsdb_env(&nsdbname, &nsdbport, &binddn, NULL);

	while ((arg = getopt_long(argc, argv, nsdb_simple_nce_opts,
			nsdb_simple_nce_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			nsdb_enable_ldap_debugging();
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_simple_nce_usage(progname);
			}
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_simple_nce_usage(progname);
		}
	}
	if (argc == optind + 1) {
		parent = argv[optind];
	} else if (argc > optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		nsdb_simple_nce_usage(progname);
	} else {
		fprintf(stderr, "No parent DN specified\n");
		nsdb_simple_nce_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_simple_nce_usage(progname);
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

	if (binddn == NULL)
		binddn = (char *)nsdb_default_binddn(host);
	retval = nsdb_open_nsdb(host, binddn, NULL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_INVAL:
		fprintf(stderr, "Missing or invalid password\n");
		goto out_free;
	case FEDFS_ERR_NSDB_CONN:
		fprintf(stderr, "Failed to connect to NSDB %s:%u\n",
			nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_AUTH:
		fprintf(stderr, "Failed to establish secure connection "
			"to NSDB %s:%u\n", nsdbname, nsdbport);
		goto out_free;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_INVALID_CREDENTIALS:
			fprintf(stderr, "Incorrect password for DN %s\n",
				binddn);
			break;
		default:
			fprintf(stderr, "Failed to bind to NSDB %s:%u: %s\n",
				nsdbname, nsdbport, ldap_err2string(ldap_err));
		}
		goto out_free;
	default:
		fprintf(stderr, "Failed to open NSDB %s:%u: %s\n",
			nsdbname, nsdbport,
			nsdb_display_fedfsstatus(retval));
		goto out_free;
	}

	retval = nsdb_create_simple_nce_s(host, parent, &nce, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "Failed to create NCE: %s\n",
			ldap_err2string(ldap_err));
		goto out_close;
	default:
		fprintf(stderr, "Failed to create NCE: %s\n",
			nsdb_display_fedfsstatus(retval));
		goto out_close;
	}

	retval = nsdb_update_nci_s(host, nce, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully created NCE %s\n", nce);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		/* XXX: should not occur */
		fprintf(stderr, "Entry %s is not a naming context "
			"for this NSDB\n", nce);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_REFERRAL:
			fprintf(stderr, "Encountered LDAP referral on %s:%u\n",
				nsdbname, nsdbport);
			break;
		case LDAP_CONFIDENTIALITY_REQUIRED:
			fprintf(stderr, "TLS security required for %s:%u\n",
				nsdbname, nsdbport);
			break;
		default:
			fprintf(stderr, "Failed to update NCI: %s\n",
				ldap_err2string(ldap_err));
		}
		break;
	default:
		fprintf(stderr, "Failed to update NCI: %s\n",
			nsdb_display_fedfsstatus(retval));
	}
	free(nce);

out_close:
	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
