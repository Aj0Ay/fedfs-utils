/**
 * @file src/nsdbc/nsdb-describe.c
 * @brief Update the FedFsDescription attribute of a FedFS entry
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
static const char nsdb_describe_opts[] = "?a:dD:e:l:r:w:y";

/**
 * Long form command line options
 */
static const struct option nsdb_describe_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "delete", 0, NULL, 'y', },
	{ "description", 1, NULL, 'a', },
	{ "entry", 1, NULL, 'e', },
	{ "help", 0, NULL, '?', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "password", 1, NULL, 'w', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_describe_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -b ] [ -D binddn ] [ -w passwd ] "
			"[ -l nsdbname ] [ -r nsdbport ] -e entry "
			"[ -a description] [-y]\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-a, --description    Description value to modify\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --entry          DN of entry to update\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-w, --password       Bind password\n");
	fprintf(stderr, "\t-y, --delete         Delete specified description\n");

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
	char *description, *entry;
	unsigned short nsdbport;
	unsigned int ldap_err;
	int arg, exit_status;
	FedFsStatus retval;
	_Bool delete;
	nsdb_t host;

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

	nsdb_env(&nsdbname, &nsdbport, &binddn, NULL, &passwd);

	delete = false;
	entry = description = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_describe_opts,
			nsdb_describe_longopts, NULL)) != -1) {
		switch (arg) {
		case 'a':
			description = optarg;
			break;
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'e':
			entry = optarg;
			break;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_describe_usage(progname);
			}
			break;
		case 'w':
			passwd = optarg;
			break;
		case 'y':
			delete = true;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_describe_usage(progname);
		}
	}
	if (optind != argc) {
		fprintf(stderr, "Unrecognized command line argument\n");
		nsdb_describe_usage(progname);
	}
	if (nsdbname == NULL || entry == NULL) {
		fprintf(stderr, "Missing required command line argument\n");
		nsdb_describe_usage(progname);
	}
	if (description == NULL && !delete) {
		fprintf(stderr, "Missing description\n");
		nsdb_describe_usage(progname);
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

	if (delete)
		retval = nsdb_description_delete_s(host, entry,
							description, &ldap_err);
	else
		retval = nsdb_description_add_s(host, entry,
							description, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully %s description value %s %s\n",
			delete ? "removed" : "updated",
			delete ? "from" : "for", entry);
		exit_status = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_NO_SUCH_OBJECT:
			fprintf(stderr, "Entry \"%s\" not found\n", entry);
			break;
		case LDAP_NO_SUCH_ATTRIBUTE:
			fprintf(stderr, "Description value \"%s\" not found\n",
				description);
			break;
		default:
			fprintf(stderr, "Failed to %s description value for %s: %s\n",
				delete ? "remove" : "update", entry,
				ldap_err2string(ldap_err));
		}
		break;
	default:
		fprintf(stderr, "Failed to update description value for %s: %s\n",
			entry, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit(exit_status);
}
