/**
 * @file src/libjunction/display-junction.c
 * @brief Tool to retrieve and display junction XML document
 */

/*
 * Copyright 2012 Oracle.  All rights reserved.
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
#include <unistd.h>
#include <fcntl.h>
#include <locale.h>
#include <langinfo.h>

#include <attr/xattr.h>

#include "junction.h"
#include "junction-internal.h"
#include "xlog.h"

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
	char *progname, *pathname, *buf = NULL;
	FedFsStatus retval;
	int fd;

	(void)setlocale(LC_ALL, "");

	/* For the libraries */
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];
	xlog_stderr(1);
	xlog_syslog(0);
	xlog_open(progname);

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pathname>\n", progname);
		return EXIT_FAILURE;
	}
	pathname = argv[1];

	retval = junction_open_path(pathname, &fd);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_PERM:
		fprintf(stderr, "Failed to open junction %s: not running as root\n",
			pathname);
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "Failed to open junction %s: %s\n",
			pathname, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	retval = junction_read_xattr(fd, pathname, JUNCTION_XATTR_NAME_NFS, &buf);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_ACCESS:
		fprintf(stderr, "Object %s is not a junction\n", pathname);
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "Failed to read junction %s: %s\n",
			pathname, nsdb_display_fedfsstatus(retval));
		return EXIT_FAILURE;
	}

	printf("%s\n", buf);

	free(buf);
	(void)close(fd);
	return retval;
}
