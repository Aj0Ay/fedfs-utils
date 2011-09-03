/**
 * @file src/nsdbc/nsdb-create-nce.c
 * @brief Create a FedFS NCE on a target NSDB server
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
#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_create_nce_opts[] = "?adD:e:l:qr:w:x:";

/**
 * Long form command line options
 */
static const struct option nsdb_create_nce_longopts[] = {
	{ "aci", 0, NULL, 'a', },
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nceprefix", 1, NULL, 'x', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "password", 1, NULL, 'w', },
	{ "quick", 0, NULL, 'q', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_create_nce_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] [ -w passwd ] "
			"[ -l nsdbname ] [ -r nsdbport ] "
			"[ -e entry ] [ -x nceprefix ] [-a] [-q]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-a, --aci            Set default ACI on the new NCE\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --nce            DN of container entry to add\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-q, --quick          Create default o=fedfs entry\n");
	fprintf(stderr, "\t-w, --password       Bind password\n");
	fprintf(stderr, "\t-x, --nceprefix      NCE DN prefix\n");

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
	char *progname, *binddn, *passwd, *nsdbname;
	char *nce, *nceprefix;
	unsigned short nsdbport;
	unsigned int ldap_err;
	FedFsStatus retval;
	_Bool aci, quick;
	nsdb_t host;
	int arg;

	(void)umask(S_IRWXO);

	/* Ensure UTF-8 strings can be handled transparently */
	if (setlocale(LC_CTYPE, "") == NULL ||
	    strcmp(nl_langinfo(CODESET), "UTF-8") != 0) {
		fprintf(stderr, "Failed to set locale and langinfo\n");
		exit((int)FEDFS_ERR_INVAL);
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

	nsdb_env(&nsdbname, &nsdbport, &binddn, &nce, &passwd);
	if (nce == NULL)
		nce = NSDB_DEFAULT_NCE;

	aci = quick = false;
	nceprefix = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_create_nce_opts,
			nsdb_create_nce_longopts, NULL)) != -1) {
		switch (arg) {
		case 'a':
			aci = true;
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
		case 'q':
			quick = true;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_create_nce_usage(progname);
			}
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'x':
			nceprefix = optarg;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_create_nce_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_create_nce_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_create_nce_usage(progname);
	}

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

	if (quick)
		retval = nsdb_create_nce_s(host, aci, &ldap_err);
	else {
		if (nce == NULL)
			nce = (char *)nsdb_default_nce(host);
		retval = nsdb_update_nce_s(host, nce, nceprefix, &ldap_err);
	}
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully created NCE\n");
		break;
	case FEDFS_ERR_NSDB_NONCE:
		fprintf(stderr, "Entry %s is not a naming context "
			"for this NSDB\n", nce);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stderr, "Failed to create NCE: %s\n",
			ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stderr, "Failed to create NCE: %s\n",
			nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
