/**
 * @file src/nsdbparams/main.c
 * @brief Manage local NSDB connection parameters database
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
#include <sys/capability.h>
#include <sys/prctl.h>
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
#include <pwd.h>
#include <grp.h>

#include <uuid/uuid.h>
#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "junction.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char nsdbparams_opts[] = "?dD:e:g:l:r:R:f:t:u:";

/**
 * Long form command line options
 */
static const struct option nsdbparams_longopts[] = {
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
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdbparams_usage(const char *progname)
{
	fprintf(stderr, "\n%s: version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s [ COMMAND [ ARGUMENTS ]]\n\n", progname);

	fprintf(stderr, "COMMAND is one of:\n");
	fprintf(stderr, "\tdelete     Delete connection parameters\n");
	fprintf(stderr, "\tinit       Initialize the store\n");
	fprintf(stderr, "\tlist       Enumerate the store\n");
	fprintf(stderr, "\tupdate     Update connection parameters\n");
	fprintf(stderr, "\tshow       Show connection parameters for one NSDB\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
}

/**
 * Drop root privileges
 *
 * @param uid run as this effective uid
 * @param gid run as this effective gid
 * @return true if privileges were dropped, otherwise false
 *
 * Set our effective UID and GID to that of our on-disk cert database.
 */
static _Bool
nsdbparams_drop_privileges(const uid_t uid, const gid_t gid)
{
	(void)umask(S_IWGRP | S_IWOTH);

	/*
	 * Don't clear capabilities when dropping root.
	 */
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                xlog(L_ERROR, "prctl(PR_SET_KEEPCAPS) failed: %m");
		return false;
	}

	if (setgroups(0, NULL) == -1) {
		if (errno == EPERM)
			xlog(L_ERROR, "Root permission is required");
		else
			xlog(L_ERROR, "Failed to drop supplementary groups: %m");
		return false;
	}

	/*
	 * ORDER
	 *
	 * setgid(2) first, as setuid(2) may remove privileges needed
	 * to set the group id.
	 */
	if (setgid(gid) == -1 || setuid(uid) == -1) {
		xlog(L_ERROR, "Failed to drop privileges: %m");
		return false;
	}

	xlog(D_CALL, "%s: Effective UID, GID: %u, %u",
			__func__, geteuid(), getegid());

	return true;
}

/**
 * Parse FedFS security type
 *
 * @param arg NUL-terminated string containing input argument
 * @param type OUT: numeric FedFS security type value
 * @return false if could not parse security type
 */
static _Bool
nsdbparams_sectype(const char *arg, unsigned int *type)
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
	} else if (strcasecmp(arg, "FEDFS_SEC_TLS") == 0) {
		*type = FEDFS_SEC_TLS;
		return true;
	}
	return false;
}

/**
 * Delete an NSDB entry in our NSDB connection parameter database
 *
 * @param progname NUL-terminated UTF-8 string containing name of this program
 * @param nsdbname NUL-terminated UTF-8 string containing DNS hostname of target NSDB
 * @param nsdbport IP port number of target NSDB
 * @return a program exit code
 */
static int
nsdbparams_delete(const char *progname, const char *nsdbname,
		const unsigned short nsdbport)
{
	if (nsdbname == NULL) {
		xlog(L_ERROR, "Missing required command line argument\n");
		nsdbparams_usage(progname);
		return EXIT_FAILURE;
	}

	if (nsdb_delete_nsdb(nsdbname, nsdbport) != FEDFS_OK)
		return EXIT_FAILURE;

	printf("%s: %s:%u deleted successfully\n",
		progname, nsdbname, nsdbport);
	return EXIT_SUCCESS;
}

/**
 * Initialize (create) our NSDB connection parameter database
 *
 * @param progname NUL-terminated UTF-8 string containing name of this program
 * @return a program exit code
 */
static int
nsdbparams_init(const char *progname)
{
	if (!nsdb_init_database())
		return EXIT_FAILURE;

	printf("%s: NSDB certificate store initialized\n",
		progname);
	return EXIT_SUCCESS;
}

/**
 * List all entries in our NSDB connection parameter database
 *
 * @return a program exit code
 */
static int
nsdbparams_list(void)
{
	FedFsStatus status;
	unsigned int i;
	char **list;

	status = nsdb_enumerate_nsdbs(&list);
	switch (status) {
	case FEDFS_OK:
		for (i = 0; list[i] != NULL; i++)
			printf("\t%s\n", list[i]);
		nsdb_free_string_array(list);
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		printf("The NSDB list is empty.\n");
		break;
	default:
		xlog(L_ERROR, "fedfs_enumerate_nsdbs returned %s",
			nsdb_display_fedfsstatus(status));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/**
 * Update an NSDB entry in our NSDB connection parameter database
 *
 * @param progname NUL-terminated UTF-8 string containing name of this program
 * @param nsdbname NUL-terminated UTF-8 string containing DNS hostname of target NSDB
 * @param nsdbport IP port number of target NSDB
 * @param type new FEDFS_SEC value for target NSDB
 * @param certfile NUL-terminated UTF-8 string containing filename of X.509 cert
 * @param binddn NUL-terminated UTF-8 string containing admin bind DN of target NSDB
 * @param nce NUL-terminated UTF-8 string containing default NCE of target NSDB
 * @param follow_referrals 0 means do not set; 1 means set to false; 2 means set to true
 * @return a program exit code
 */
static int
nsdbparams_update(const char *progname, const char *nsdbname,
		const unsigned short nsdbport, const unsigned int type,
		const char *certfile, const char *binddn,
		const char *nce, const _Bool follow_referrals)
{
	struct fedfs_secdata secdata = {
		.type		= type,
	};
	int rc;

	rc = EXIT_FAILURE;

	if (nsdbname == NULL) {
		xlog(L_ERROR, "Missing required command line argument\n");
		nsdbparams_usage(progname);
		goto out;
	}

	if (type != FEDFS_SEC_NONE) {
		if (certfile == NULL) {
			xlog(L_ERROR, "Missing required command line argument\n");
			nsdbparams_usage(progname);
			goto out;
		}

		if (nsdb_read_certfile(certfile, &secdata.data,
				&secdata.len) != FEDFS_OK) {
			xlog(L_ERROR, "Failed to read certfile\n");
			goto out;
		}
	}

	/*
	 * Ensure entry for this NSDB exists before trying to
	 * update bind DN, NCE, and referral flags for it.
	 */
	if (nsdb_update_nsdb(nsdbname, nsdbport, &secdata) == FEDFS_OK) {
		printf("NSDB list was updated successfully.\n");
		rc = EXIT_SUCCESS;
	}

	free(secdata.data);

	if (binddn != NULL)
		if (nsdb_update_default_binddn(nsdbname, nsdbport,
						binddn) != FEDFS_OK) {
			rc = EXIT_FAILURE;
			goto out;
		}

	if (nce != NULL)
		if (nsdb_update_default_nce(nsdbname, nsdbport,
						nce) != FEDFS_OK) {
			rc = EXIT_FAILURE;
			goto out;
		}
	if (follow_referrals != 0) {
		_Bool follow = follow_referrals == 2 ? true : false;
		if (nsdb_update_follow_referrals(nsdbname, nsdbport,
						follow) != FEDFS_OK) {
			rc = EXIT_FAILURE;
			goto out;
		}
	}

out:
	return rc;
}

/**
 * Show one NSDB entry in our NSDB connection parameter database
 *
 * @param progname NUL-terminated UTF-8 string containing name of this program
 * @param nsdbname NUL-terminated UTF-8 string containing DNS hostname of target NSDB
 * @param nsdbport IP port number of target NSDB
 * @return a program exit code
 */
static int
nsdbparams_show(const char *progname, const char *nsdbname,
		const unsigned short nsdbport)
{
	struct fedfs_secdata secdata = {
		.type		= 0,
	};
	FedFsStatus status;
	nsdb_t host;
	char *tmp;
	int rc;

	rc = EXIT_FAILURE;

	if (nsdbname == NULL) {
		xlog(L_ERROR, "Missing required command line argument");
		nsdbparams_usage(progname);
		goto out;
	}

	status = nsdb_lookup_nsdb(nsdbname, nsdbport, &host, &secdata);
	switch (status) {
	case FEDFS_OK:
		printf("%s:%u:\n", nsdbname, nsdbport);
		printf("\tconnection security: %s\n",
			nsdb_display_fedfsconnectionsec(secdata.type));
		printf("\tfollow referrals: %s\n",
			nsdb_follow_referrals(host) ? "true" : "false");
		tmp = (char *)nsdb_default_binddn(host);
		if (tmp != NULL)
			printf("\tdefault bind DN: %s\n", tmp);
		tmp = (char *)nsdb_default_nce(host);
		if (tmp != NULL)
			printf("\tdefault NCE: %s\n", tmp);
		nsdb_free_nsdb(host);
		if (secdata.type != FEDFS_SEC_NONE)
			printf("secdata:\n%s\n", secdata.data);
		rc = EXIT_SUCCESS;
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		xlog(L_ERROR, "No record for %s was found", nsdbname);
		rc = EXIT_SUCCESS;
		break;
	default:
		xlog(L_ERROR, "nsdb_lookup_nsdb returned %s",
			nsdb_display_fedfsstatus(status));
		rc = EXIT_FAILURE;
	}

out:
	return rc;
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
	char *progname, *command, *binddn, *certfile, *nce, *nsdbname, *endptr;
	int arg, exit_status, follow_referrals;
	unsigned short nsdbport = LDAP_PORT;
	unsigned int type = FEDFS_SEC_NONE;
	unsigned long tmp;
	struct passwd *pw;
	struct group *grp;
	uid_t uid;
	gid_t gid;

	exit_status = EXIT_FAILURE;

	/* Ensure UTF-8 strings can be handled transparently */
	if (setlocale(LC_CTYPE, "") == NULL)
		goto out;
	if (strcmp(nl_langinfo(CODESET), "UTF-8") != 0)
		goto out;

	/* Set the basename */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	if (argc < 2) {
		nsdbparams_usage(progname);
		goto out;
	}

	/* For the libraries */
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

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

	nsdbname = nce = certfile = binddn = NULL;
	follow_referrals = 0;

	/* so that getopt_long(3)'s error messages are meaningful */
	command = argv[1];
	argv[1] = argv[0];
	while ((arg = getopt_long(argc - 1, argv + 1, nsdbparams_opts,
			nsdbparams_longopts, NULL)) != -1) {
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
			certfile = optarg;
			break;
		case 'g':
			if (optarg == NULL || *optarg == '\0') {
				fprintf(stderr, "Invalid gid specified");
				nsdbparams_usage(progname);
				goto out;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				grp = getgrnam(optarg);
				if (grp == NULL) {
					fprintf(stderr, "Invalid gid specified");
					goto out;
				}
			} else {
				grp = getgrgid((gid_t)tmp);
				if (grp == NULL) {
					fprintf(stderr, "Invalid gid specified");
					goto out;
				}
			}
			gid = grp->gr_gid;
			break;
		case 'h':
		case '?':
			nsdbparams_usage(progname);
			goto out;
		case 'l':
			nsdbname = optarg;
			break;
		case 'r':
			if (!nsdb_parse_port_string(optarg, &nsdbport)) {
				fprintf(stderr, "Bad port number: %s\n",
					optarg);
				nsdbparams_usage(progname);
				goto out;
			}
			break;
		case 'R':
			if (strcmp(optarg, "yes") == 0)
				follow_referrals = 2;
			else if (strcmp(optarg, "no") == 0)
				follow_referrals = 1;
			else {
				fprintf(stderr, "Bad referral flag: %s\n",
					optarg);
				nsdbparams_usage(progname);
				goto out;
			}
			break;
		case 't':
			if (!nsdbparams_sectype(optarg, &type)) {
				fprintf(stderr, "Bad security type: %s\n",
					optarg);
				nsdbparams_usage(progname);
				goto out;
			}
			break;
		case 'u':
			if (optarg == NULL || *optarg == '\0') {
				fprintf(stderr, "Invalid uid specified");
				nsdbparams_usage(progname);
				goto out;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				pw = getpwnam(optarg);
				if (pw == NULL) {
					fprintf(stderr, "Invalid uid specified");
					goto out;
				}
			} else {
				pw = getpwuid((uid_t)tmp);
				if (pw == NULL) {
					fprintf(stderr, "Invalid uid specified");
					goto out;
				}
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		default:
			xlog(L_ERROR, "Invalid command line "
				"argument: %c\n", (char)arg);
			nsdbparams_usage(progname);
			goto out;
		}
	}

	if (!nsdbparams_drop_privileges(uid, gid))
		goto out;

	if (strcasecmp(command, "delete") == 0)
		exit_status = nsdbparams_delete(progname, nsdbname, nsdbport);
	else if (strcasecmp(command, "init") == 0)
		exit_status = nsdbparams_init(progname);
	else if (strcasecmp(command, "list") == 0)
		exit_status = nsdbparams_list();
	else if (strcasecmp(command, "update") == 0)
		exit_status = nsdbparams_update(progname, nsdbname, nsdbport,
						type, certfile, binddn, nce,
						follow_referrals);
	else if (strcasecmp(command, "show") == 0)
		exit_status = nsdbparams_show(progname, nsdbname, nsdbport);
	else {
		xlog(L_ERROR, "Unrecognized command\n");
		nsdbparams_usage(progname);
	}

out:
	exit(exit_status);
}
