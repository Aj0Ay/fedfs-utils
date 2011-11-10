/**
 * @file src/nsdbparams/list.c
 * @brief List entries in local NSDB connection parameters database
 */

/*
 * Copyright 2011 Oracle.  All rights reserved.
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

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
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
static const char nsdbparams_list_opts[] = "?dg:u:";

/**
 * Long form command line options
 */
static const struct option nsdbparams_list_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "gid", 1, NULL, 'g', },
	{ "help", 0, NULL, '?', },
	{ "uid", 1, NULL, 'u', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display subcommand synopsis
 *
 * @param progname NUL-terminate C string containing name of program
 */
static void
nsdbparams_list_usage(const char *progname)
{
	fprintf(stderr, "\nUsage: %s list [options]\n\n", progname);

	fprintf(stderr, "\t-?, --help           Print this help\n");
	fprintf(stderr, "\t-d, --debug          Enable debug messages\n");
	fprintf(stderr, "\t-g, --gid            Run as this effective gid\n");
	fprintf(stderr, "\t-u, --uid            Run as this effective uid\n");

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
}

/**
 * List all entries in our NSDB connection parameter database
 *
 * @param progname NUL-terminate C string containing name of program
 * @param argc count of command line arguments
 * @param argv array of NUL-terminated C strings containing command line arguments
 * @return program exit status
 */
int
nsdbparams_list(const char *progname, int argc, char **argv)
{
	char **list, *endptr;
	FedFsStatus status;
	unsigned long tmp;
	struct passwd *pw;
	struct group *grp;
	unsigned int i;
	uid_t uid;
	gid_t gid;
	int arg;

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

	while ((arg = getopt_long(argc, argv, nsdbparams_list_opts,
					nsdbparams_list_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			xlog_stderr(1);
			break;
		case 'g':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid gid specified");
				nsdbparams_list_usage(progname);
				return EXIT_FAILURE;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				grp = getgrnam(optarg);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					return EXIT_FAILURE;
				}
			} else {
				grp = getgrgid((gid_t)tmp);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					return EXIT_FAILURE;
				}
			}
			gid = grp->gr_gid;
			break;
		case 'h':
		case '?':
			nsdbparams_list_usage(progname);
			return EXIT_FAILURE;
		case 'u':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid uid specified");
				nsdbparams_list_usage(progname);
				return EXIT_FAILURE;
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				pw = getpwnam(optarg);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					return EXIT_FAILURE;
				}
			} else {
				pw = getpwuid((uid_t)tmp);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					return EXIT_FAILURE;
				}
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		default:
			xlog(L_ERROR, "Invalid command line "
				"argument: %c", (char)arg);
			nsdbparams_list_usage(progname);
			return EXIT_FAILURE;
		}
	}

	if (argc != optind) {
		xlog(L_ERROR, "Unrecognized command line argument");
		nsdbparams_list_usage(progname);
		return EXIT_FAILURE;
	}

	if (!nsdbparams_drop_privileges(uid, gid))
		return EXIT_FAILURE;

	if (!nsdb_init_database())
		return EXIT_FAILURE;

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
