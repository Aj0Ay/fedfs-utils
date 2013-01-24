/**
 * @file src/nsdbparams/update.c
 * @brief Update an item in the local NSDB connection parameters database
 */

/*
 * Copyright 2010, 2011 Oracle.  All rights reserved.
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"
#include "nsdbparams.h"

/**
 * Short form command line options
 */
static const char nsdbparams_update_opts[] = "?dD:e:g:l:r:R:f:t:u:";

/**
 * Long form command line options
 */
static const struct option nsdbparams_update_longopts[] = {
	{ "binddn", 1, NULL, 'D', },
	{ "certfile", 1, NULL, 'f', },
	{ "debug", 0, NULL, 'd', },
	{ "gid", 1, NULL, 'g', },
	{ "help", 0, NULL, '?', },
	{ "nce", 1, NULL, 'e', },
	{ "nsdbname", 1, NULL, 'l', },
	{ "nsdbport", 1, NULL, 'r', },
	{ "referral", 1, NULL, 'R', },
	{ "sectype", 1, NULL, 't', },
	{ "uid", 1, NULL, 'u', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display subcommand synopsis
 *
 * @param progname NUL-terminate C string containing name of program
 */
static void
nsdbparams_update_usage(const char *progname)
{
	fprintf(stderr, "\nUsage: %s update [options] NSDBNAME\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-D, --binddn         Default bind DN\n");
	fprintf(stderr, "\t-e, --nce            Default DN of NCE\n");
	fprintf(stderr, "\t-f, --certfile       Pathname to server certificate\n");
	fprintf(stderr, "\t-g, --gid            Run as this effective gid\n");
	fprintf(stderr, "\t-r, --nsdbport       NSDB port\n");
	fprintf(stderr, "\t-R, --referral       Toggle follow-referral flag\n");
	fprintf(stderr, "\t-t, --sectype        Sectype for this NSDB\n");
	fprintf(stderr, "\t-u, --uid            Run as this effective uid\n\n");

	fprintf(stderr, "\tSECTYPE is one of 0, 1, none, tls, "
			"FEDFS_SEC_NONE, or FEDFS_SEC_TLS\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
}

/**
 * Ping NSDB server
 *
 * @param nsdbname NUL-terminated C string containing DNS hostname of NSDB
 * @param nsdbport port number of NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdbparams_test_nsdb(const char *nsdbname, unsigned short nsdbport)
{
	unsigned int ldap_err;
	FedFsStatus retval;

	printf("Pinging NSDB %s:%u...\n", nsdbname, nsdbport);
	fflush(stdout);

	retval = nsdb_ping_s(nsdbname, nsdbport, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		xlog(D_GENERAL, "%s:%u passed ping test", nsdbname, nsdbport);
		break;
	case FEDFS_ERR_NSDB_NONCE:
		xlog(L_WARNING, "Warning: %s:%u is not an NSDB: %s",
			nsdbname, nsdbport, nsdb_display_fedfsstatus(retval));
		retval = FEDFS_OK;
		break;
	case FEDFS_ERR_NSDB_AUTH:
		xlog(L_WARNING, "Warning: TLS is required for NSDB %s:%u",
			nsdbname, nsdbport);
		retval = FEDFS_OK;
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		xlog(L_WARNING, "Failed to ping NSDB %s:%u: %s",
			nsdbname, nsdbport, ldap_err2string(ldap_err));
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to ping NSDB %s:%u: %s",
			nsdbname, nsdbport, nsdb_display_fedfsstatus(retval));
	}
	return retval;
}

/**
 * Parse FedFS security type
 *
 * @param arg NUL-terminated string containing input argument
 * @param type OUT: numeric FedFS security type value
 * @return false if could not parse security type
 */
static _Bool
nsdbparams_sectype(const char *arg, FedFsConnectionSec *type)
{
	unsigned long tmp;
	char *endptr;

	errno = 0;
	tmp = strtoul(arg, &endptr, 10);
	if (errno != 0 || *endptr != '\0')
		goto try_symbolic;
	switch (tmp) {
	case FEDFS_SEC_NONE:
	case FEDFS_SEC_TLS:
		*type = tmp;
		return true;
	}
try_symbolic:
	if (strcasecmp(arg, "FEDFS_SEC_NONE") == 0) {
		*type = FEDFS_SEC_NONE;
		return true;
	} else if (strcasecmp(arg, "none") == 0) {
		*type = FEDFS_SEC_NONE;
		return true;
	} else if (strcasecmp(arg, "FEDFS_SEC_TLS") == 0) {
		*type = FEDFS_SEC_TLS;
		return true;
	} else if (strcasecmp(arg, "tls") == 0) {
		*type = FEDFS_SEC_TLS;
		return true;
	}
	return false;
}

/**
 * Update the security setting for this NSDB
 *
 * @param nsdbname NUL-terminated UTF-8 string containing NSDB hostname
 * @param nsdbport NSDB's IP port number
 * @param type connection security type for this NSDB
 * @param certfile NUL-terminated UTF-8 string containing pathname of file
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdbparams_update_security(const char *nsdbname, unsigned short nsdbport,
		FedFsConnectionSec type, const char *certfile)
{
	FedFsStatus retval;

	switch (type) {
	case FEDFS_SEC_NONE:
		if (certfile != NULL)
			xlog(L_ERROR, "The specified certfile was ignored");

		retval = nsdb_connsec_set_none(nsdbname, nsdbport);
		if (retval != FEDFS_OK) {
			xlog(L_ERROR, "Failed to update security pararmeters: %s",
				nsdb_display_fedfsstatus(retval));
			return retval;
		}
		break;
	case FEDFS_SEC_TLS:
		if (certfile == NULL) {
			xlog(L_ERROR, "No certfile was specified");
			return FEDFS_ERR_INVAL;
		}

		retval = nsdb_connsec_set_tls_file(nsdbname, nsdbport,
							certfile);
		if (retval != FEDFS_OK) {
			xlog(L_ERROR, "Failed to update security pararmeters: %s",
				nsdb_display_fedfsstatus(retval));
			return retval;
		}
		break;
	default:
		xlog(L_ERROR, "Unrecognized connection security type");
		return FEDFS_ERR_INVAL;
	}

	return FEDFS_OK;
}

/**
 * Update an NSDB entry in our NSDB connection parameter database
 *
 * @param progname NUL-terminated UTF-8 string containing name of this program
 * @param argc count of command line arguments
 * @param argv array of NUL-terminated C strings containing command line arguments
 * @return program exit status
 */
int
nsdbparams_update(const char *progname, int argc, char **argv)
{
	char *binddn, *certfile, *nce, *nsdbname, *endptr, *data = NULL;
	unsigned short nsdbport = LDAP_PORT;
	FedFsConnectionSec type = FEDFS_SEC_NONE;
	_Bool update_security = false;
	int arg, follow_referrals;
	FedFsStatus retval;
	unsigned long tmp;
	struct passwd *pw;
	struct group *grp;
	nsdb_t host;
	uid_t uid;
	gid_t gid;
	int rc;

	/* Discover the user ID who owns the store */
	uid = 99;
	gid = 99;
	pw = getpwnam(FEDFS_USER);
	if (pw != NULL) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		xlog(D_GENERAL, "Found user %s: UID %u and GID %u",
			FEDFS_USER, uid, gid);
	}

	rc = EXIT_FAILURE;
	nce = certfile = binddn = NULL;
	follow_referrals = 0;

	/* so that getopt_long(3)'s error messages are meaningful */
	while ((arg = getopt_long(argc, argv, nsdbparams_update_opts,
			nsdbparams_update_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			xlog_stderr(1);
			break;
		case 'D':
			binddn = optarg;
			break;
		case 'e':
			nce = optarg;
			break;
		case 'f':
			type = FEDFS_SEC_TLS;
			certfile = optarg;
			update_security = true;
			break;
		case 'g':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid gid specified");
				nsdbparams_update_usage(progname);
				goto out;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				grp = getgrnam(optarg);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					goto out;
				}
			} else {
				grp = getgrgid((gid_t)tmp);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					goto out;
				}
			}
			gid = grp->gr_gid;
			break;
		case 'h':
		case '?':
			nsdbparams_update_usage(progname);
			goto out;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				xlog(L_ERROR, "Bad port number: %s",
					optarg);
				nsdbparams_update_usage(progname);
				goto out;
			}
			break;
		case 'R':
			if (strcmp(optarg, "yes") == 0)
				follow_referrals = 2;
			else if (strcmp(optarg, "no") == 0)
				follow_referrals = 1;
			else {
				xlog(L_ERROR, "Bad referral flag: %s",
					optarg);
				nsdbparams_update_usage(progname);
				goto out;
			}
			break;
		case 't':
			if (!nsdbparams_sectype(optarg, &type)) {
				xlog(L_ERROR, "Bad security type: %s",
					optarg);
				nsdbparams_update_usage(progname);
				goto out;
			}
			update_security = true;
			break;
		case 'u':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid uid specified");
				nsdbparams_update_usage(progname);
				goto out;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				pw = getpwnam(optarg);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					goto out;
				}
			} else {
				pw = getpwuid((uid_t)tmp);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					goto out;
				}
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		default:
			xlog(L_ERROR, "Invalid command line "
				"argument: %c\n", (char)arg);
			nsdbparams_update_usage(progname);
			goto out;
		}
	}

	if (argc == optind + 1)
		nsdbname = argv[optind];
	else if (argc > optind + 1) {
		xlog(L_ERROR, "Unrecognized positional parameters");
		nsdbparams_update_usage(progname);
		goto out;
	} else {
		xlog(L_ERROR, "No NSDB hostname was specified");
		nsdbparams_update_usage(progname);
		goto out;
	}

	if (!nsdbparams_drop_privileges(uid, gid))
		goto out;

	if (!nsdb_init_database())
		goto out;

	retval = nsdb_lookup_nsdb(nsdbname, nsdbport, &host);
	switch (retval) {
	case FEDFS_OK:
		nsdb_free_nsdb(host);
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		retval = nsdbparams_test_nsdb(nsdbname, nsdbport);
		if (retval != FEDFS_OK)
			goto out;
		retval = nsdb_create_nsdb(nsdbname, nsdbport);
		if (retval != FEDFS_OK) {
			xlog(L_ERROR, "Failed to create NSDB "
				"connection parameters for %s:%d: %s",
				nsdbname, nsdbport,
				nsdb_display_fedfsstatus(retval));
			goto out;
		}
		break;
	default:
		xlog(L_ERROR, "Failed to access NSDB "
			"connection parameter database: %s",
				nsdb_display_fedfsstatus(retval));
		goto out;
	}

	if (update_security) {
		retval = nsdbparams_update_security(nsdbname, nsdbport,
							type, certfile);
		if (retval != FEDFS_OK)
			goto out;
	}

	if (binddn != NULL)
		if (nsdb_update_default_binddn(nsdbname, nsdbport,
							binddn) != FEDFS_OK)
			goto out;

	if (nce != NULL)
		if (nsdb_update_default_nce(nsdbname, nsdbport,
							nce) != FEDFS_OK)
			goto out;

	if (follow_referrals != 0) {
		_Bool follow = follow_referrals == 2 ? true : false;
		if (nsdb_update_follow_referrals(nsdbname, nsdbport,
							follow) != FEDFS_OK)
			goto out;
	}

	printf("NSDB connection parameters updated successfully.\n");
	rc = EXIT_SUCCESS;
out:
	free(data);
	return rc;
}
