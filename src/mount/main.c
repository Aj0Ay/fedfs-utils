/**
 * @file src/mount/main.c
 * @brief Linux FedFS mount
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
 * Top-level directory on client under which we mount NFSv4 domain roots
 */
#define FEDFS_NFS4_TLDIR		"nfs4"

/**
 * Name of SRV record containing NFSv4 FedFS root
 */
#define FEDFS_NFS_DOMAINROOT	"_nfs-domainroot._tcp"

/**
 * Export path of NFSv4 FedFS root
 */
#define FEDFS_NFS_EXPORTPATH	"/.domainroot"

/**
 * Pathname to mount.nfs
 */
#define MOUNT_NFS_EXECUTABLE		"/sbin/mount.nfs"

/**
 * Mount status values, lifted from util-linux
 */
enum {
	EX_SUCCESS	= 0,
	EX_USAGE	= 1,
	EX_FAIL		= 32,
};

static char *progname;
static int nomtab;
static int verbose;
static _Bool readonly;
static _Bool sloppy;
static _Bool fake;

/**
 * Short form command line options
 */
static const char fedfs_opts[] = "fhno:rsvVw";

/**
 * Long form command line options
 */
static const struct option fedfs_longopts[] =
{
	{ "fake", 0, NULL, 'f' },
	{ "help", 0, NULL, 'h' },
	{ "no-mtab", 0, NULL, 'n' },
	{ "options", 1, NULL, 'o' },
	{ "read-only", 0, NULL, 'r' },
	{ "read-write", 0, NULL, 'w' },
	{ "ro", 0, NULL, 'r' },
	{ "rw", 0, NULL, 'w' },
	{ "sloppy", 0, NULL, 's' },
	{ "verbose", 0, NULL, 'v' },
	{ "version", 0, NULL, 'V' },
	{ NULL, 0, NULL, 0 }
};

/**
 * Display mount.fedfs usage message
 */
static void
mount_usage(void)
{
	printf(_("\nUsage: %s remotedir localdir [-fhnrsvVw]\n\n"), progname);
	printf(_("options:\n"));
	printf(_("\t-f\t\tFake mount, do not actually mount\n"));
	printf(_("\t-h\t\tPrint this help\n"));
	printf(_("\t-n\t\tDo not update /etc/mtab\n"));
	printf(_("\t-r\t\tMount file system readonly\n"));
	printf(_("\t-s\t\tTolerate sloppy mount options\n"));
	printf(_("\t-v\t\tVerbose\n"));
	printf(_("\t-V\t\tPrint version\n"));
	printf(_("\t-w\t\tMount file system read-write\n"));

	printf("%s", fedfs_gpl_boilerplate);
}

/**
 * Concatenate three strings
 *
 * @param s NUL-terminated C string
 * @param t NUL-terminated C string
 * @param u NUL-terminated C string
 * @return pointer to NUL-terminated C string or NULL
 *
 * Caller must free the returned string with free(3).  Always frees
 * its first arg - typical use: s = xstrconcat3(s,t,u);
 *
 * Lifted from util-linux.
 */
static char *
xstrconcat3(char *s, const char *t, const char *u)
{
	_Bool free_s = true;
	char *result;

	if (s == NULL) {
		s = "";
		free_s = false;
	}
	if (t == NULL)
		t = "";
	if (u == NULL)
		u = "";
	result = malloc(strlen(s) + strlen(t) + strlen(u) + 1);
	if (result == NULL)
		goto out;

	strcpy(result, s);
	strcat(result, t);
	strcat(result, u);

out:
	if (free_s)
		free(s);
	return result;
}

/**
 * Exec mount.nfs
 *
 * @param server NUL-terminated C string containing name of NFS server
 * @param port server port to use when mounting
 * @param domainname NUL-terminated C string containing FedFS domain name
 * @param export_path NUL-terminated C string containing server export path
 * @param mounted_on_dir NUL-terminated C string containing local mounted-on directory
 * @param text_options NUL-terminated C string containing user's mount options
 *
 */
static void
exec_mount_nfs4(const char *server, unsigned short port,
		const char *domainname, const char *export_path,
		const char *mounted_on_dir, const char *text_options)
{
	static char special[2048];
	static char options[2048];
	char *args[16];
	int count = 0;

	snprintf(special, sizeof(special), "%s:%s/%s%s", server,
			FEDFS_NFS_EXPORTPATH, domainname, export_path);

	if (text_options != NULL && strcmp(text_options, "") != 0)
		snprintf(options, sizeof(options), "%s,vers=4,fg,port=%u",
				text_options, port);
	else
		snprintf(options, sizeof(options), "vers=4,fg,port=%u", port);

	if (verbose) {
		printf(_("%s: Special device:       %s\n"),
			progname, special);
		printf(_("%s: Mounted-on directory: %s\n"),
			progname, mounted_on_dir);
		printf(_("%s: Mount options:        %s\n"),
			progname, options);
	}

	args[count++] = MOUNT_NFS_EXECUTABLE;
	args[count++] = special;
	args[count++] = (char *)mounted_on_dir;
	if (verbose)
		args[count++] = "-v";
	if (fake)
		args[count++] = "-f";
	if (nomtab)
		args[count++] = "-n";
	if (readonly)
		args[count++] = "-r";
	if (sloppy)
		args[count++] = "-s";
	args[count++] = "-o";
	args[count++] = options;

	args[count] = NULL;
	execv(args[0], args);
}

/**
 * Mount a FedFS domain root via NFSv4
 *
 * @param domainname NUL-terminated C string containing FedFS domain name
 * @param export_path NUL-terminated C string containing server export path
 * @param mounted_on_dir NUL-terminated C string containing local mounted-on directory
 * @param text_options NUL-terminated C string containing user's mount options
 * @return exit status code from the mount.nfs command
 *
 * Construct the server:/export string and the mounted-on directory string
 * based on the DNS SRV query results, then fork and exec mount.nfs to do
 * the actual mount request.
 */
static int
nfs4_mount(const char *domainname, const char *export_path,
		const char *mounted_on_dir, const char *text_options)
{
	struct srvinfo *tmp, *si = NULL;
	int error, status;

	status = EX_FAIL;

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

	/*
	 * The srvinfo list is already in RFC 2782 sorted order.  Try each
	 * SRV record once, in the foreground.  Go with the first one that
	 * works.
	 */
	for (tmp = si; tmp != NULL; tmp = tmp->si_next) {
		pid_t pid;

		pid = fork();
		switch (pid) {
		case 0:
			exec_mount_nfs4(tmp->si_target, tmp->si_port,
					domainname, export_path, mounted_on_dir,
					text_options);
			/*NOTREACHED*/
			fprintf(stderr, _("%s: Failed to exec: %s\n"),
				progname, strerror(errno));
			exit(EX_FAIL);
		case -1:
			fprintf(stderr, _("%s: Failed to fork: %s\n"),
				progname, strerror(errno));
			goto out;
		default:
			waitpid(pid, &status, 0);
			if (status == EX_SUCCESS)
				goto out;
		}
	}

out:
	freesrvinfo(si);
	return status;
}

/**
 * Try one mount request
 *
 * @param source NUL-terminated C string containing name of "special device"
 * @param target NUL-terminated C string containing local mounted-on directory
 * @param text_options NUL-terminated C string containing user's mount options
 * @return an exit status code
 *
 * Parse the pathname in "source."  It contains the file system protocol
 * and FedFS domain name.  Then pass these arguments to the appropriate
 * mount helper subcommand.
 */
static int
try_mount(const char *source, const char *target, const char *text_options)
{
	char *global_name, *topdir, *domainname, *remaining;
	int result;

	remaining = NULL;
	result = EX_FAIL;

	global_name = strdup(source);
	if (global_name == NULL) {
		fprintf(stderr, _("%s: Unable to parse globally useful name\n"),
				progname);
		goto out;
	}

	topdir = strtok(global_name, "/");
	if (topdir == NULL) {
		fprintf(stderr, _("%s: Invalid globally useful name: %s\n"),
			progname, source);
		goto out;
	}
	if (verbose)
		printf(_("%s: Top-level directory:  %s\n"),
			progname, topdir);

	domainname = strtok(NULL, "/");
	if (domainname == NULL) {
		fprintf(stderr, _("%s: Missing domain name in globally "
				"useful name: %s\n"), progname, source);
		goto out;
	}
	if (verbose)
		printf(_("%s: Domain name:          %s\n"),
			progname, domainname);

	remaining = strtok(NULL, "/");
	if (remaining == NULL) {
		remaining = strdup("/");
		if (remaining == NULL) {
			fprintf(stderr, _("%s: No memory\n"), progname);
			goto out;
		}
	} else {
		char *tmp;

		tmp = malloc(strlen(remaining) + 1);
		if (tmp == NULL) {
			fprintf(stderr, _("%s: No memory\n"), progname);
			remaining = NULL;
			goto out;
		}
		strcpy(tmp, "/");
		strcat(tmp, remaining);
		remaining = tmp;
	}
	if (verbose)
		printf(_("%s: Export path:          %s\n"),
			progname, remaining);

	if (strcmp(topdir, FEDFS_NFS4_TLDIR) == 0)
		result = nfs4_mount(domainname, remaining, target, text_options);
#if 0
	/* example: SMB support plugs in here */
	else if (strcmp(topdir, FEDFS_SMB_TLDIR) == 0)
		result = smb_mount(domainname, remaining, target, text_options);
#endif
	else
		fprintf(stderr, _("%s: Unrecognized file system protocol\n"), progname);

out:
	free(global_name);
	free(remaining);

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
	char *source, *target, *text_options;
	int c, mnt_err;

	(void)setlocale(LC_ALL, "");

	progname = basename(argv[0]);

	if (argv[1] && argv[1][0] == '-') {
		if(argv[1][1] == 'V')
			printf("%s ("PACKAGE_STRING")\n", progname);
		else
			mount_usage();
		exit(EX_SUCCESS);
	}

	if (argc < 3) {
		mount_usage();
		exit(EX_USAGE);
	}

	source = argv[1];
	target = argv[2];

	mnt_err = EX_USAGE;
	text_options = NULL;
	readonly = false;
	sloppy = false;
	fake = false;
	argv[2] = argv[0]; /* so that getopt error messages are correct */
	while ((c = getopt_long(argc - 2, argv + 2, fedfs_opts,
				fedfs_longopts, NULL)) != -1) {
		switch (c) {
		case 'f':
			fake = true;
			break;
		case 'n':
			++nomtab;
			break;
		case 'o':
			/* Ugh. */
			if (text_options != NULL)
				text_options = xstrconcat3(text_options, ",", optarg);
			else
				text_options = strdup(optarg);
			if (text_options == NULL) {
				fprintf(stderr, _("%s: No memory\n"), progname);
				goto out;
			}
			break;
		case 'r':
			readonly = true;
			break;
		case 's':
			sloppy = true;
			break;
		case 'v':
			++verbose;
			break;
		case 'V':
			printf("%s: ("PACKAGE_STRING")\n", progname);
			mnt_err = EX_SUCCESS;
			goto out;
		case 'w':
			readonly = false;
			break;
		case 'h':
		default:
			mount_usage();
			goto out;
		}
	}

	/* Extra non-option words at the end are bogus...  */
	if (optind != argc - 2) {
		mount_usage();
		goto out;
	}

	if (getuid() != 0 && geteuid() != 0) {
		fprintf(stderr, _("%s: Not installed setuid - "
			    "\"user\" FedFS mounts are not supported\n"), progname);
		mnt_err = EX_FAIL;
		goto out;
	}

	mnt_err = try_mount(source, target, text_options);

out:
	free(text_options);
	exit(mnt_err);
}
