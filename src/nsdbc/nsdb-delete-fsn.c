/**
 * @file src/nsdbc/nsdb-delete-fsn.c
 * @brief Delete a FedFS FSN entry from a target NSDB server
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
static const char nsdb_delete_fsn_opts[] = "?dD:e:l:r:y";

/**
 * Long form command line options
 */
static const struct option nsdb_delete_fsn_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "leavefsn", 0, NULL, 'y', },
	{ "nce", 1, NULL, 'e', },
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
nsdb_delete_fsn_usage(const char *progname)
{
	fprintf(stderr, "\n%s version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ] [-y] "
			"fsn-uuid\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-y, --leavefsn       Delete FSLs but leave FSN\n");

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
	unsigned short nsdbport;
	unsigned int ldap_err;
	char *nce, *fsn_uuid;
	FedFsStatus retval;
	_Bool leave_fsn;
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

	nsdb_env(&nsdbname, &nsdbport, &binddn, &nce);

	leave_fsn = false;
	while ((arg = getopt_long(argc, argv, nsdb_delete_fsn_opts,
			nsdb_delete_fsn_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			nsdb_enable_ldap_debugging();
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
				nsdb_delete_fsn_usage(progname);
			}
			break;
		case 'y':
			leave_fsn = true;
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_delete_fsn_usage(progname);
		}
	}
	if (argc == optind + 1) {
		uuid_t uu;
		fsn_uuid = argv[optind];
		if (uuid_parse(fsn_uuid, uu) == -1) {
			fprintf(stderr, "Invalid FSN UUID was specified\n");
			nsdb_delete_fsn_usage(progname);
		}
	} else if (argc > optind + 1) {
		fprintf(stderr, "Unrecognized positional parameters\n");
		nsdb_delete_fsn_usage(progname);
	} else {
		fprintf(stderr, "No FSN UUID was specified\n");
		nsdb_delete_fsn_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "No NSDB hostname specified\n");
		nsdb_delete_fsn_usage(progname);
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
	if (nce == NULL)
		nce = (char *)nsdb_default_nce(host);
	if (nce == NULL) {
		fprintf(stderr, "No NCE was specified\n");
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

	retval = nsdb_delete_fsn_s(host, nce, fsn_uuid, leave_fsn, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		if (leave_fsn)
			printf("Successfully deleted FSL records for FSN %s under %s\n",
				fsn_uuid, nce);
		else
			printf("Successfully deleted FSN record %s under %s\n",
				fsn_uuid, nce);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		fprintf(stderr, "NSDB %s:%u has no such FSN %s\n",
			nsdbname, nsdbport, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		fprintf(stderr, "FSN %s still has FSL entries\n", fsn_uuid);
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
		case LDAP_NOT_ALLOWED_ON_NONLEAF:
			fprintf(stderr, "Failed to delete: "
				"this FSN may have children\n");
			break;
		default:
			fprintf(stderr, "Failed to delete FSN %s: %s\n",
				fsn_uuid, ldap_err2string(ldap_err));
		}
		break;
	default:
		fprintf(stderr, "Failed to delete FSN %s: %s\n",
			fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);

out:
	exit((int)retval);
}
