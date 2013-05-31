/**
 * @file src/fedfsd/main.c
 * @brief Program initialization.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <memory.h>
#include <getopt.h>
#include <langinfo.h>
#include <locale.h>
#include <pwd.h>
#include <grp.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "xlog.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char fedfsd_opts[] = "?dFg:o:u:";

/**
 * Long form command line options
 */
static const struct option fedfsd_longopts[] =
{
	{ "debug", 0, NULL, 'd', },
	{ "foreground", 0, NULL, 'F', },
	{ "help", 0, NULL, '?', },
	{ "gid", 1, NULL, 'g', },
	{ "port", 1, NULL, 'o', },
	{ "uid", 1, NULL, 'u', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void fedfsd_usage(const char *progname)
{
	fprintf(stderr, "\nUsage: %s [options]\n\n", progname);

	fprintf(stderr, "\t-?, --help        Print this help\n");
	fprintf(stderr, "\t-d, --debug       Enable debug messages\n");
	fprintf(stderr, "\t-F, --foreground  Stay in foreground\n");
	fprintf(stderr, "\t-g, --gid         Run as this effective gid\n");
	fprintf(stderr, "\t-o, --port        Listen on this port\n");
	fprintf(stderr, "\t-u, --uid         Run as this effective uid\n");

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
int main(int argc, char **argv)
{
	_Bool foreground = false;
	uint16_t listen_port = 0;
	char *progname, *endptr;
	struct passwd *pw;
	struct group *grp;
	unsigned long tmp;
	uid_t uid;
	gid_t gid;
	int arg;

	(void)setlocale(LC_ALL, "");

	xlog_stderr(0);
	xlog_syslog(1);

	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];
	xlog_open(progname);

	/* start with system defaults */
	uid = 99;
	gid = 99;
	pw = getpwnam(FEDFS_USER);
	if (pw != NULL) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		xlog(L_NOTICE, "Found user %s: UID %u and GID %u",
				FEDFS_USER, uid, gid);
	}

	while ((arg = getopt_long(argc, argv, fedfsd_opts,
					fedfsd_longopts, NULL)) != EOF) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			break;
		case 'F':
			xlog_stderr(1);
			xlog_syslog(0);
			foreground = true;
			break;
		case 'g':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid gid specified");
				fedfsd_usage(progname);
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				grp = getgrnam(optarg);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					exit(EXIT_FAILURE);
				}
			} else {
				grp = getgrgid((gid_t)tmp);
				if (grp == NULL) {
					xlog(L_ERROR, "Invalid gid specified");
					exit(EXIT_FAILURE);
				}
			}
			gid = grp->gr_gid;
			break;
		case '?':
			fprintf(stderr, "Version " VERSION
					", built on %s at %s\n\n",
					__DATE__, __TIME__);
			fedfsd_usage(progname);
			break;
		case 'o':
			if (!nsdb_parse_port_string(optarg, &listen_port)) {
				fprintf(stderr, "Bad listener port number: %s\n",
					optarg);
				fedfsd_usage(progname);
			}
			break;
		case 'u':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid uid specified");
				fedfsd_usage(progname);
			}

			errno = 0;
			tmp = strtoul(optarg, &endptr, 10);
			if (errno != 0 || *endptr != '\0' || tmp > UINT_MAX) {
				pw = getpwnam(optarg);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					exit(EXIT_FAILURE);
				}
			} else {
				pw = getpwuid((uid_t)tmp);
				if (pw == NULL) {
					xlog(L_ERROR, "Invalid uid specified");
					exit(EXIT_FAILURE);
				}
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		default:
			fprintf(stderr, "Invalid command line argument: %c\n",
				(char)arg);
			fedfsd_usage(progname);
		}
	}

	if (!fedfsd_drop_privileges(uid, gid))
		exit(EXIT_FAILURE);

	if (!nsdb_init_database())
		exit(EXIT_FAILURE);

	if (!foreground) {
		if (chdir(FEDFS_DEFAULT_STATEDIR) == -1) {
			xlog(L_ERROR, "chdir: %m");
			exit(EXIT_FAILURE);
		}
		if (daemon(0, 0) == -1) {
			xlog(L_ERROR, "daemon: %m");
			exit(EXIT_FAILURE);
		}
	}

	xlog(L_NOTICE, "Version " VERSION " (built %s at %s) starting",
			__DATE__, __TIME__);

	nsdb_connsec_crypto_startup();

	/* Normally doesn't return */
	fedfsd_svc_create("fedfs", FEDFS_PROG, FEDFS_V1,
			fedfsd_dispatch_1, listen_port);

	nsdb_connsec_crypto_shutdown();

	xlog(L_WARNING, "Exiting unexpectedly");
	exit(EXIT_FAILURE);
}
