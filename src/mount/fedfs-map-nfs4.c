/**
 * @file src/mount/fedfs-map-nfs4.c
 * @brief Convert FedFS domain name key to automounter map entry
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <netdb.h>
#include <langinfo.h>

#include "nls.h"
#include "getsrvinfo.h"
#include "token.h"
#include "gpl-boiler.h"

/**
 * Name of SRV record containing NFSv4 FedFS root
 */
#define FEDFS_NFS_DOMAINROOT	"_nfs-domainroot._tcp"

/**
 * Export pathname of NFSv4 FedFS root
 */
#define FEDFS_NFS_EXPORTPATH	"/.domainroot"

static char *progname;

/**
 * Display usage message
 */
static void
fedfs_map_usage(void)
{
	printf(_("\nUsage: %s [domain]\n\n"), progname);

	printf("%s", fedfs_gpl_boilerplate);
}

/**
 * Construct an NFSv4 map entry for "domainname" with one server
 *
 * @param si single-entry list of SRV records
 * @param domainname NUL-terminated UTF-8 string containing name of FedFS domain
 * @return command exit status
 */
static int fedfs_map_nfs4_oneserver(struct srvinfo *si, const char *domainname)
{
	printf("-fstype=nfs,vers=4,fg");
	if (si->si_port != 2049)
		printf(",port=%u", si->si_port);
	printf(" %s:%s/%s\n", si->si_target, FEDFS_NFS_EXPORTPATH, domainname);
	return 0;
}

/**
 * Construct an NFSv4 map entry for "domainname" with multiple servers
 *
 * @param si list of SRV records for requested FedFS domain
 * @param domainname NUL-terminated UTF-8 string containing name of FedFS domain
 * @return command exit status
 */
static int fedfs_map_nfs4_replicas(struct srvinfo *si, const char *domainname)
{
	struct srvinfo *cur;
	unsigned short port;
	_Bool comma;

	/*
	 * Unfortunately our automounter can't handle a list of
	 * replicas where the various servers live on different
	 * ports from one another.
	 */
	port = si->si_port;
	for (cur = si; cur != NULL; cur = cur->si_next)
		if (cur->si_port != port) {
			fprintf(stderr, _("%s: Replicas on different ports not supported\n"),
				progname);
			return 1;
		}

	if (port != 2049)
		printf("-fstype=nfs,vers=4,fg,port=%u ", port);
	else
		printf("-fstype=nfs,vers=4,fg ");

	/*
	 * Note that the export path is required to be indentical
	 * for all domain root servers for this domain.
	 */
	for (comma = false, cur = si; cur != NULL; cur = cur->si_next) {
		if (comma)
			printf(",");
		printf("%s(%u)", cur->si_target, cur->si_weight);
		comma = true;
	}
	printf(":%s/%s\n", FEDFS_NFS_EXPORTPATH, domainname);

	return 0;
}

/**
 * Construct an NFSv4 map entry for "domainname"
 *
 * @param domainname NUL-terminated UTF-8 string containing name of FedFS domain
 * @return command exit status
 */
static int fedfs_map_nfs4(const char *domainname)
{
	struct srvinfo *cur, *si = NULL;
	unsigned int count;
	int error, result;

	result = 1;
	error = getsrvinfo(FEDFS_NFS_DOMAINROOT, domainname, &si);
	switch (error) {
	case ESI_SUCCESS:
		break;
	case ESI_NONAME:
		fprintf(stderr, _("%s: Domain name %s not found\n"),
			progname, domainname);
		goto out;
	case ESI_SERVICE:
		fprintf(stderr, _("%s: No FedFS domain root available for %s\n"),
			progname, domainname);
		goto out;
	default:
		fprintf(stderr, _("%s: Failed to resolve %s: %s\n"),
			progname, domainname, gsi_strerror(error));
		goto out;
	}

	for (count = 0, cur = si; cur != NULL; cur = cur->si_next)
		count++;
	if (count == 1)
		result = fedfs_map_nfs4_oneserver(si, domainname);
	else
		result = fedfs_map_nfs4_replicas(si, domainname);

out:
	freesrvinfo(si);
	return result;
}

/**
 * Program entry point
 *
 * @param argc count of command line arguments
 * @param argv array of NUL-terminated C strings containing command line arguments
 * @return program exit status
 */
int main(int argc, char *argv[])
{
	(void)setlocale(LC_ALL, "");

	progname = basename(argv[0]);

	if (argc != 2) {
		fedfs_map_usage();
		return 1;
	}

	if (strcmp(progname, "fedfs-map-nfs4") == 0)
		return fedfs_map_nfs4(argv[1]);
#ifdef EXAMPLE
	/* CIFS support might plug in here */
	else if (strcmp(progname, "fedfs-map-cifs") == 0)
		return fedfs_map_cifs(argv[1]);
#endif

	fprintf(stderr, _("%s: Unsupported file system type\n"), progname);
	return 1;
}
