/**
 * @file src/resolve-junction/main.c
 * @brief Resolve a local FedFS junction to a list of FSLs
 *
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
#include <pwd.h>
#include <grp.h>

#include <uuid/uuid.h>
#include <langinfo.h>

#include "fedfs.h"
#include "nsdb.h"
#include "junction.h"
#include "xlog.h"
#include "privilege.h"
#include "gpl-boiler.h"

/**
 * Short form command line options
 */
static const char resolve_junction_opts[] = "?dg:p:u:";

/**
 * Long form command line options
 */
static const struct option resolve_junction_longopts[] = {
	{ "debug", 0, NULL, 'd', },
	{ "gid", 1, NULL, 'g', },
	{ "help", 0, NULL, '?', },
	{ "path", 1, NULL, 'p', },
	{ "uid", 1, NULL, 'u', },
	{ NULL, 0, NULL, 0, },
};

/**
 * Display program synopsis
 *
 * @param progname NUL-terminated C string containing name of program
 */
static void
resolve_junction_usage(const char *progname)
{
	xlog(L_NOTICE, "Version " VERSION ", built on %s at %s",
		__DATE__, __TIME__);
	xlog(L_NOTICE, "usage: %s [-d] [-u uid] [-g gid] [-p pathname]\n",
		progname);

	xlog(L_NOTICE, "\t-?, --help        Print this usage message\n");
	xlog(L_NOTICE, "\t-g, --gid         Run as this effective gid\n");
	xlog(L_NOTICE, "\t-d, --debug       Enable debug messages\n");
	xlog(L_NOTICE, "\t-p, --path        Pathname of FedFS junction\n");
	xlog(L_NOTICE, "\t-u, --uid         Run as this effective uid\n");

	xlog(L_NOTICE, "%s", fedfs_gpl_boilerplate);

	exit(EXIT_FAILURE);
}

#if 0
/**
 * Display the results of the FSN resolution
 *
 * @param fsls a list of fedfs_fsl structures to display
 *
 * Adapted from an earlier implementation by Trond Myklebust.
 * Copyright (c) 2009 Trond Myklebust <Trond.Myklebust@netapp.com>
 *
 * Note that the upcall reply API uses ':' and '@' as field
 * separators, thus our hostname and path arguments must not contain
 * these characters.  For one thing, we can't support a non-standard
 * FSL port, since that is expressed as "hostname:port".
 *
 * That may not matter for NFS FSLs (which is all that is handled
 * here), as NFSv4 defines its port number as the fixed, well-known
 * port 2049.
 *
 * Additionally, we can return only one cache TTL value to the
 * kernel, per upcall reply.  We choose the smallest in the list
 * of FSLs.
 */
static void
resolve_junction_display_results(const struct fedfs_fsl *fsls)
{
	const char *fmt, *last_path;
	const struct fedfs_fsl *fsl;
	int ttl;

	ttl = INT_MAX;
	for (fsl = fsls; fsl != NULL; fsl = fsl->fl_next)
		if (fsl->fl_fslttl != 0 && fsl->fl_fslttl < ttl)
			ttl = fsl->fl_fslttl;
	fprintf(stdout, "FSL TTL: %s\n", ttl);

	fprintf(stdout, "refer=");

	fmt = "%s@%s";
	last_path = NULL;
	for (fsl = fsls; fsl != NULL; fsl = fsl->fl_next) {
		const char *path = fsl->fl_u.fl_nfsfsl.fn_path;
		const char *hostname = fsl->fl_fslhost;
		const unsigned short port = fsl->fl_fslport;

		if (fsl->fl_type != FEDFS_NFS_FSL) {
			xlog(D_GENERAL, "%s: Can't support non-NFS FSL",
				__func__);
			continue;
		}
		if (port != 0 && port != NFS_PORT) {
			xlog(D_GENERAL, "%s: Cannot support FSL port %u ",
				__func__, port);
			continue;
		}
		if (strchr(path, ':') != NULL ||
		    strchr(path, '@') != NULL) {
			xlog(D_GENERAL, "%s: Cannot support FSL path '%s'",
				__func__, path);
			continue;
		}

		if (last_path && strcmp(path, last_path) == 0) {
			fprintf(stdout, "+%s", hostname);
			continue;
		}

		fprintf(stdout, fmt, path, hostname);
		fmt = ":%s@%s";
		last_path = path;
	}

	fflush(stdout);
}
#endif

/**
 * Return presentation string for a boolean value
 *
 * @param value a boolean value
 * @return NUL-terminate C string
 */
static const char *
_display_bool(const _Bool value)
{
	return value ? "T" : "F";
}

/**
 * Display nfs_fsl portion of a fedfs_fsl structure
 *
 * @param nfsl pointer to a fedfs_nfs_fsl structure
 */
static void
resolve_junction_display_nfs_fsl(struct fedfs_nfs_fsl *nfsl)
{
	fprintf(stdout, "fli_rootpath_len: %zu\n", strlen(nfsl->fn_path));
	fprintf(stdout, "fli_rootpath: %s\n", nfsl->fn_path);
	fprintf(stdout, "major version: %d\n", nfsl->fn_majorver);
	fprintf(stdout, "minor version: %d\n", nfsl->fn_minorver);
	fprintf(stdout, "fls_currency: %d\n", nfsl->fn_currency);
	fprintf(stdout, "FSLI4GF_WRITABLE: %s\n",
					_display_bool(nfsl->fn_gen_writable));
	fprintf(stdout, "FSLI4GF_GOING: %s\n",
					_display_bool(nfsl->fn_gen_going));
	fprintf(stdout, "FSLI4GF_SPLIT: %s\n",
					_display_bool(nfsl->fn_gen_split));
	fprintf(stdout, "FSLI4TF_RDMA: %s\n",
					_display_bool(nfsl->fn_trans_rdma));
	fprintf(stdout, "FSLI4BX_CLSIMUL: %d\n", nfsl->fn_class_simul);
	fprintf(stdout, "FSLI4BX_CLHANDLE: %d\n", nfsl->fn_class_handle);
	fprintf(stdout, "FSLI4BX_CLFILEID: %d\n", nfsl->fn_class_fileid);
	fprintf(stdout, "FSLI4BX_CLWRITEVER: %d\n", nfsl->fn_class_writever);
	fprintf(stdout, "FSLI4BX_CLCHANGE: %d\n", nfsl->fn_class_change);
	fprintf(stdout, "FSLI4BX_CLREADDIR: %d\n", nfsl->fn_class_readdir);
	fprintf(stdout, "FSLI4BX_READRANK: %d\n", nfsl->fn_readrank);
	fprintf(stdout, "FSLI4BX_READORDER: %d\n", nfsl->fn_readorder);
	fprintf(stdout, "FSLI4BX_WRITERANK: %d\n", nfsl->fn_writerank);
	fprintf(stdout, "FSLI4BX_WRITEORDER: %d\n", nfsl->fn_writeorder);
	fprintf(stdout, "FSLI4F_VAR_SUB: %s\n", _display_bool(nfsl->fn_varsub));
	fprintf(stdout, "fli_valid_for: %d\n", nfsl->fn_validfor);
}

/**
 * Display one FSL
 *
 * @param fsl pointer to a fedfs_fsl structure
 */
static void
resolve_junction_display_fsl(struct fedfs_fsl *fsl)
{
	int i;

	/* Result layout version, and output separator */
	fprintf(stdout, "Version: 0.1\n");

	fprintf(stdout, "FSN UUID: %s\n", fsl->fl_fsnuuid);
	fprintf(stdout, "FSL UUID: %s\n", fsl->fl_fsluuid);
	fprintf(stdout, "NSDB: %s:%u\n", fsl->fl_nsdbname, fsl->fl_nsdbport);
	fprintf(stdout, "Host: %s:%u\n", fsl->fl_fslhost, fsl->fl_fslport);
	fprintf(stdout, "TTL: %d\n", fsl->fl_fslttl);

	if (fsl->fl_annotations != NULL) {
		for (i = 0; fsl->fl_annotations[i] != NULL; i++)
			fprintf(stdout, "Annotation[%d]: %s\n", i,
				fsl->fl_annotations[i]);
	}

	if (fsl->fl_description != NULL) {
		for (i = 0; fsl->fl_description[i] != NULL; i++)
			fprintf(stdout, "Description[%d]: %s\n", i,
				fsl->fl_description[i]);
	}

	if (fsl->fl_type == FEDFS_NFS_FSL)
		resolve_junction_display_nfs_fsl(&fsl->fl_u.fl_nfsfsl);
}

/**
 * Display the returned FSL list
 *
 * @param fsls a list of fedfs_fsl structures
 * @return true if successful
 */
static _Bool
resolve_junction_display_results(struct fedfs_fsl *fsls)
{
	for (;fsls != NULL; fsls = fsls->fl_next)
		resolve_junction_display_fsl(fsls);
	return true;
}

/**
 * Resolve the FSN UUID contained in the given FedFS junction
 *
 * @param pathname a NUL-terminated C string containing POSIX pathname of junction
 * @return true if successful
 */
static _Bool
resolve_junction(const char *pathname)
{
	struct fedfs_fsl *fsls;
	unsigned int ldap_err;
	_Bool result = false;
	FedFsStatus status;
	char *fsn_uuid;
	nsdb_t host;

	status = fedfs_get_fsn(pathname, &fsn_uuid, &host);
	if (status != FEDFS_OK)
		return result;

	xlog(D_GENERAL, "%s: resolving FSN UUID %s with NSDB %s:%u",
		__func__, fsn_uuid, nsdb_hostname(host), nsdb_port(host));

	if (nsdb_open_nsdb(host, NULL, NULL, &ldap_err) != FEDFS_OK)
		goto out_free;

	status = nsdb_resolve_fsn_s(host, NULL, fsn_uuid, &fsls, &ldap_err);
	switch (status) {
	case FEDFS_OK:
		result = resolve_junction_display_results(fsls);
		nsdb_free_fedfs_fsls(fsls);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		fprintf(stdout, "No results\n");
		xlog(L_ERROR, "%s: No FSL entries for FSN %s",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		fprintf(stdout, "No results\n");
		xlog(L_ERROR, "%s: No FSN %s found",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		fprintf(stdout, "No results\n");
		xlog(L_ERROR, "%s: NSDB operation failed with %s",
			__func__, ldap_err2string(ldap_err));
		break;
	default:
		fprintf(stdout, "No results\n");
		xlog(L_ERROR, "%s: Failed to resolve FSN %s: %s",
			__func__, fsn_uuid, nsdb_display_fedfsstatus(status));
	}

	fflush(stdout);
	nsdb_close_nsdb(host);

out_free:
	nsdb_free_nsdb(host);
	free(fsn_uuid);
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
	char *progname, *pathname, *endptr;
	unsigned long tmp;
	struct passwd *pw;
	struct group *grp;
	uid_t uid;
	gid_t gid;
	int arg;

	/* Ensure UTF-8 strings can be handled transparently */
	if (setlocale(LC_CTYPE, "") == NULL ||
	    strcmp(nl_langinfo(CODESET), "UTF-8") != 0) {
		fprintf(stderr, "Failed to set locale and langinfo\n");
		exit(EXIT_FAILURE);
	}

	xlog_stderr(0);
	xlog_syslog(1);
	if ((progname = strrchr(argv[0], '/')) != NULL)
		progname++;
	else
		progname = argv[0];
	xlog_open(progname);

	uid = 99;	/* nobody */
	gid = 99;
	pw = getpwnam(FEDFS_USER);
	if (pw != NULL) {
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		xlog(L_NOTICE, "Found user %s: UID %u and GID %u",
			FEDFS_USER, uid, gid);
	}

	pathname = NULL;
	while ((arg = getopt_long(argc, argv, resolve_junction_opts,
			resolve_junction_longopts, NULL)) != -1) {
		switch (arg) {
		case 'd':
			xlog_config(D_ALL, 1);
			xlog_stderr(1);
			break;
		case 'g':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid gid specified");
				resolve_junction_usage(progname);
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
		case 'h':
		case '?':
			resolve_junction_usage(progname);
			break;
		case 'p':
			pathname = optarg;
			break;
		case 'u':
			if (optarg == NULL || *optarg == '\0') {
				xlog(L_ERROR, "Invalid uid specified");
				resolve_junction_usage(progname);
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
			xlog(L_ERROR, "Invalid command line "
				"argument: %c\n", (char)arg);
			resolve_junction_usage(progname);
		}
	}
	if (optind != argc) {
		xlog(L_ERROR, "Unrecognized command line argument\n");
		resolve_junction_usage(progname);
	}
	if (pathname == NULL) {
		xlog(L_ERROR, "Missing required command line argument\n");
		resolve_junction_usage(progname);
	}

	/* Must be able to access trusted xattrs and the cert store */
	if (!resolve_junction_drop_privileges(uid, gid))
		exit(EXIT_FAILURE);

	if (resolve_junction(pathname))
		exit(EXIT_FAILURE);
	exit(EXIT_SUCCESS);
}
