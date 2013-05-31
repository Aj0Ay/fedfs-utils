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

#include <rpcsvc/nfs_prot.h>
#include <uuid/uuid.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdb_create_fsl_opts[] = "?dD:e:l:o:r:";

/**
 * Long form command line options
 */
static const struct option nsdb_create_fsl_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "debug", 0, NULL, 'd', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "serverport", 1, NULL, 'o', },
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
	fprintf(stderr, "Usage: %s [ -d ] [ -D binddn ] "
			"[ -l nsdbname ] [ -r nsdbport ] [ -e nce ] "
			"[ -o serverport ] "
			"fsn-uuid fsl-uuid servername serverpath\n\n",
			progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Bind DN\n");
	fprintf(stderr, "\t-e, --nce            DN of NSDB container entry\n");
	fprintf(stderr, "\t-l, --nsdbname       NSDB hostname\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-o, --serverport     File server port to set\n");

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
	char *nce, *fsn_uuid, *fsl_uuid, *servername, *serverpath;
	char *progname, *binddn, *nsdbname;
	unsigned short nsdbport, serverport;
	struct fedfs_fsl *fsl;
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

	nsdb_env(&nsdbname, &nsdbport, &binddn, &nce);

	serverport = NFS_PORT;
	while ((arg = getopt_long(argc, argv, nsdb_create_fsl_opts,
			nsdb_create_fsl_longopts, NULL)) != -1) {
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
		case 'o':
			if (!nsdb_parse_port_string(optarg, &serverport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_create_fsl_usage(progname);
			}
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdb_create_fsl_usage(progname);
			}
			break;
		default:
			fprintf(stderr, "Invalid command line "
				"argument: %c\n", (char)arg);
		case '?':
			nsdb_create_fsl_usage(progname);
		}
	}
	if (argc == optind + 4) {
		uuid_t uu;
		fsn_uuid = argv[optind];
		if (uuid_parse(fsn_uuid, uu) == -1) {
			fprintf(stderr, "Invalid FSN UUID was specified\n");
			nsdb_create_fsl_usage(progname);
		}
		fsl_uuid = argv[optind + 1];
		if (uuid_parse(fsl_uuid, uu) == -1) {
			fprintf(stderr, "Invalid FSL UUID was specified\n");
			nsdb_create_fsl_usage(progname);
		}
		servername = argv[optind + 2];
		if (!nsdb_is_hostname_utf8(servername)) {
			fprintf(stderr, "NSDB name %s is "
				"not a UTF-8 hostname\n", servername);
			nsdb_create_fsl_usage(progname);
		}
		serverpath = argv[optind + 3];
	} else {
		fprintf(stderr, "Ambiguous positional parameters\n");
		nsdb_create_fsl_usage(progname);
	}
	if (nsdbname == NULL) {
		fprintf(stderr, "No NSDB hostname was specified\n");
		nsdb_create_fsl_usage(progname);
	}

	retval = FEDFS_ERR_SVRFAULT;
	fsl = nsdb_new_fedfs_fsl(FEDFS_NFS_FSL);
	if (fsl == NULL) {
		fprintf(stderr, "Failed to allocate FSL\n");
		goto out;
	}
	strcpy(fsl->fl_fsluuid, fsl_uuid);
	strcpy(fsl->fl_fsnuuid, fsn_uuid);

	retval = FEDFS_ERR_NAMETOOLONG;
	if (strlen(servername) >= sizeof(fsl->fl_u.fl_nfsfsl.fn_fslhost)) {
		fprintf(stderr, "Fileserver hostname too large\n");
		goto out;
	}
	strcpy(fsl->fl_u.fl_nfsfsl.fn_fslhost, servername);

	fsl->fl_u.fl_nfsfsl.fn_fslport = serverport;
	retval = nsdb_posix_to_path_array(serverpath,
						&fsl->fl_u.fl_nfsfsl.fn_nfspath);
	if (retval != FEDFS_OK) {
		fprintf(stderr, "Failed to encode serverpath\n");
		goto out;
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
		fprintf(stderr, "Failed to establish security connection "
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

	retval = nsdb_create_fsls_s(host, nce, fsl, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		printf("Successfully created FSL record for %s under %s\n",
				fsl_uuid, nce);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		if (nce == NULL)
			fprintf(stderr, "NSDB %s:%u has no NCE\n",
				nsdbname, nsdbport);
		else
			fprintf(stderr, "NCE %s does not exist\n", nce);
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
			fprintf(stderr, "Failed to create FSL %s: %s\n",
				fsl_uuid, ldap_err2string(ldap_err));
		}
		break;
	default:
		fprintf(stderr, "Failed to create FSL %s: %s\n",
			fsl_uuid, nsdb_display_fedfsstatus(retval));
	}

	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);
	nsdb_free_fedfs_fsl(fsl);

out:
	exit((int)retval);
}
