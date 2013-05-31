/**
 * @file src/nsdbc/nsdb-annotate.c
 * @brief Annotate a FedFS entry on a target NSDB server
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

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_annotate_opts[] = "?adD:k:l:r:v:y";

/**
 * Long form command line options
 */
static const struct option nsdb_annotate_longopts[] = {
	{ "annotation", 1, NULL, 'a', },
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "delete", 0, NULL, 'y', },
	{ "help", 0, NULL, '?', },
	{ "keyword", 1, NULL, 'k', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "value", 1, NULL, 'v', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdb_annotate_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -a annotation ] "
			"[ -k keyword ] [ -v value ] [ -y ] "
			"distinguished-name\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-a, --annotation     Full annotation\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-k, --keyword        Annotation keyword\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-v, --value          Annotation value\n");
	fprintf(stderr, "\t-y, --delete         Delete specified annotation\n");

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
	char *progname, *binddn, *nsdbname;
	char *keyword, *value, *entry, *annotation;
	unsigned short nsdbport;
	unsigned int ldap_err;
	FedFsStatus retval;
	_Bool delete;
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

	delete = false;
	keyword = value = entry = annotation = NULL;
	while ((arg = getopt_long(argc, argv, nsdb_annotate_opts,
			nsdb_annotate_longopts, NULL)) != -1) {
		switch (arg) {
		case 'a':
			annotation = optarg;
			break;
		case 'd':
			xlog_config(D_ALL, 1);
			nsdb_enable_ldap_debugging();
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'k':
			keyword = optarg;
			break;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_annotate_usage(progname);
			}
			break;
		case 'v':
			value = optarg;
			break;
		case 'y':
			delete = true;
			break;
		case '?':
			nsdb_annotate_usage(progname);
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
			nsdb_annotate_usage(progname);
		}
	}
	if (argc == optind + 1)
		entry = argv[optind];
	else if (argc > optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		nsdb_annotate_usage(progname);
	} else {
		fprintf(stderr, "No distinguished name was specified\n");
		nsdb_annotate_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "No NSDB hostname was specified\n");
		nsdb_annotate_usage(progname);
	}

	/*
	 * Delete must use the full annotation, but Add can use either
	 * the full annotation or keyword/value pair (but not both).
	 */
	if (delete) {
		if (keyword != NULL || value != NULL) {
			fprintf(stderr, "Specify only \"-a\" when deleting\n");
			nsdb_annotate_usage(progname);
		}
		if (annotation == NULL) {
			fprintf(stderr, "Missing annotation\n");
			nsdb_annotate_usage(progname);
		}
	} else {
		if (annotation != NULL && (keyword != NULL || value != NULL)) {
			fprintf(stderr, "Specify only \"-a\" or "
				"\"-k/-v\" when adding\n");
			nsdb_annotate_usage(progname);
		}
		if (annotation == NULL && keyword == NULL && value == NULL) {
			fprintf(stderr, "Specify either \"-a\" or "
				"\"-k/-v\" when adding\n");
			nsdb_annotate_usage(progname);
		}
		if (keyword == NULL && value != NULL) {
			fprintf(stderr, "Missing keyword\n");
			nsdb_annotate_usage(progname);
		}
		if (keyword != NULL && value == NULL) {
			fprintf(stderr, "Missing value\n");
			nsdb_annotate_usage(progname);
		}
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
	retval = FEDFS_ERR_INVAL;
	if (binddn == NULL)
		binddn = (char *)nsdb_default_binddn(host);
	if (binddn == NULL) {
		fprintf(stderr, "No NDSB bind DN was specified\n");
		goto out_free;
	}

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

	if (delete)
		retval = nsdb_annotation_delete_s(host, entry, annotation,
							&ldap_err);
	else {
		if (annotation == NULL) {
			retval = nsdb_construct_annotation(keyword, value,
								&annotation);
			if (retval != FEDFS_OK) {
				fprintf(stderr, "Failed to construct annotation: "
					"%s\n", nsdb_display_fedfsstatus(retval));
				goto out_close;
			}

			retval = nsdb_annotation_add_s(host, entry,
							annotation, &ldap_err);
			free(annotation);
		} else
			retval = nsdb_annotation_add_s(host, entry,
							annotation, &ldap_err);
	}
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully %s annotation \"%s\" = \"%s\" %s %s\n",
			delete ? "removed" : "updated", keyword, value,
			delete ? "from" : "for", entry);
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
		case LDAP_NO_SUCH_ATTRIBUTE:
			fprintf(stderr, "Annotation \"%s\" = \"%s\" not found\n",
				keyword, value);
			break;
		default:
			fprintf(stderr, "Failed to %s annotation \"%s\" = \"%s\": %s\n",
				delete ? "remove" : "update",
				keyword, value, ldap_err2string(ldap_err));
		}
		break;
	default:
		fprintf(stderr, "Failed to %s annotation \"%s\" = \"%s\": %s\n",
			delete ? "remove" : "update",
			keyword, value, nsdb_display_fedfsstatus(retval));
	}

out_close:
	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
