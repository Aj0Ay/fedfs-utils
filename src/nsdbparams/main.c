/**
 * @file src/nsdbparams/main.c
 * @brief Manage local NSDB connection parameters database
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

#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <grp.h>

#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "xlog.h"
#include "gpl-boiler.h"
#include "nsdbparams.h"

/**
 * Capabilies that nsdbparams should retain, in text format.
 */
#define NSDBPARAMS_CAPABILITIES "cap_dac_override=ep"

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
nsdbparams_usage(const char *progname)
{
	fprintf(stderr, "\n%s: version " VERSION "\n", progname);
	fprintf(stderr, "Usage: %s SUBCOMMAND [ ARGUMENTS ]\n\n", progname);

	fprintf(stderr, "SUBCOMMAND is one of:\n");
	fprintf(stderr, "\tdelete     Delete connection parameters\n");
	fprintf(stderr, "\tlist       Enumerate the store\n");
	fprintf(stderr, "\tshow       Show connection parameters for one NSDB\n");
	fprintf(stderr, "\tupdate     Update connection parameters\n");

	fprintf(stderr, "\nUse \"%s SUBCOMMAND -?\" for details.\n", progname);

	fprintf(stderr, "%s", fedfs_gpl_boilerplate);
}

/**
 * Clear all capabilities but a certain few.
 *
 * @return true if successful
 *
 * This permits callers to create directories anywhere, but all other
 * capabilities are dropped.
 */
static _Bool
nsdbparams_clear_capabilities(void)
{
	cap_t caps;
	char *text;

	caps = cap_from_text(NSDBPARAMS_CAPABILITIES);
	if (caps == NULL) {
		xlog(L_ERROR, "Failed to allocate capability: %m");
		return false;
	}

	if (cap_set_proc(caps) == -1) {
		xlog(L_ERROR, "Failed to set capability flags: %m");
		(void)cap_free(caps);
		return false;
	}

	(void)cap_free(caps);

	caps = cap_get_proc();
	if (caps == NULL)
		goto out;

	text = cap_to_text(caps, NULL);
	if (text == NULL)
		goto out_free;

	xlog(D_CALL, "Process capabilities: %s", text);
	(void)cap_free(text);

out_free:
	(void)cap_free(caps);

out:
	return true;
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
_Bool
nsdbparams_drop_privileges(const uid_t uid, const gid_t gid)
{
	_Bool result;

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

	result = nsdbparams_clear_capabilities();

	xlog(D_CALL, "%s: Effective UID, GID: %u, %u",
			__func__, geteuid(), getegid());
	return result;
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
	int exit_status;
	char *progname;

	exit_status = EXIT_FAILURE;

	(void)setlocale(LC_ALL, "");

	/* Set the basename */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];

	/* For the libraries */
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

	if (argc < 2) {
		nsdbparams_usage(progname);
		goto out;
	}

	nsdb_connsec_crypto_startup();

	if (strcasecmp(argv[1], "delete") == 0)
		exit_status = nsdbparams_delete(progname, argc - 1, argv + 1);
	else if (strcasecmp(argv[1], "list") == 0)
		exit_status = nsdbparams_list(progname, argc - 1, argv + 1);
	else if (strcasecmp(argv[1], "update") == 0)
		exit_status = nsdbparams_update(progname, argc - 1, argv + 1);
	else if (strcasecmp(argv[1], "show") == 0)
		exit_status = nsdbparams_show(progname, argc - 1, argv + 1);
	else {
		xlog(L_ERROR, "Unrecognized subcommand: %s", argv[1]);
		nsdbparams_usage(progname);
	}

	nsdb_connsec_crypto_shutdown();

out:
	exit(exit_status);
}
