/**
 * @file src/fedfsd/svc.c
 * @brief Convert incoming FedFS admin RPC requests into local function calls.
 *
 * @todo
 *	Support RPCGSS authentication of clients
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
#include <sys/socket.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>

#include <netinet/in.h>
#include <uuid/uuid.h>
#include <rpc/rpc.h>
#include <rpc/svc.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "junction.h"
#include "xlog.h"

/**
 * Report calling client's IP address via xlog()
 *
 * @param rqstp incoming RPC request
 * @param buf OUT: NUL-terminated C string containing presentation address
 * @param buflen length of "buf"
 */
static void
fedfsd_caller(struct svc_req *rqstp, char *buf, const size_t buflen)
{
	const struct sockaddr_in6 *sin6 = svc_getcaller(rqstp->rq_xprt);
	const struct sockaddr *sap = (struct sockaddr *)sin6;
	socklen_t salen;

	switch (sap->sa_family) {
	case AF_INET:
		salen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		salen = sizeof(struct sockaddr_in6);
		break;
	default:
		goto out_unknown;
	}

	if (getnameinfo(sap, salen, buf, buflen, NULL, 0, NI_NUMERICHOST))
		goto out_unknown;

	return;

out_unknown:
	(void)snprintf(buf, buflen, "unknown address");
}

/**
 * Construct an nsdb_t from a FedFsNsdbName
 *
 * @param name FedFsNsdbName type name of NSDB server
 * @param hostname OUT: pointer to NUL-terminated UTF-8 C string containing hostname of NSDB; caller must free with free(3)
 * @param port OUT: integer port number of NSDB
 * @return a FedFsStatus code
 *
 * @verbatim

   Can return:

    FEDFS_OK:
  	"host" points to an intialized nsdb_t object
    FEDFS_ERR_BADCHAR:
        "name" was not a valid U-name string
    FEDFS_ERR_SVRFAULT:
  	memory was not available
    FEDFS_ERR_INVAL:
  	"name" was too long, or port number was not valid
   @endverbatim
 */
FedFsStatus
fedfsd_nsdbname(const FedFsNsdbName name, char **hostname,
		unsigned short *port)
{
	char buf[NI_MAXHOST];

	/* Ensure hostname is NUL-terminated, and a reasonable length */
	if (name.hostname.utf8string_len >= sizeof(buf)) {
		xlog(D_GENERAL, "%s: Hostname too large", __func__);
		return FEDFS_ERR_INVAL;
	}
	strncpy(buf, name.hostname.utf8string_val, name.hostname.utf8string_len);
	buf[name.hostname.utf8string_len] = '\0';

	if (!nsdb_is_hostname_utf8(buf)) {
		xlog(D_GENERAL, "%s: Hostname contains a bad character",
			__func__);
		return FEDFS_ERR_BADCHAR;
	}

	if (name.port > UINT16_MAX) {
		xlog(D_GENERAL, "%s: Port is invalid", __func__);
		return FEDFS_ERR_INVAL;
	}

	*hostname = strdup(buf);
	if (*hostname == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	*port = name.port;

	return FEDFS_OK;
}

/**
 * Extract FedFsNsdbName from an nsdb_t object
 *
 * @param host an initialized nsdb_t object
 * @param name OUT: full nsdbName corresponding to "host"; caller must free the hostname.utf8string_val field with free(3)
 * @return a FedFsStatus code
 *
 * @verbatim

   Can return:

    FEDFS_OK:
  	"name" points to a valid FedFsNsdbName
    FEDFS_ERR_SVRFAULT:
  	memory was not available
   @endverbatim
 */
FedFsStatus
fedfsd_nsdb_to_nsdbname(const nsdb_t host, FedFsNsdbName *name)
{
	name->hostname.utf8string_val = strdup(nsdb_hostname(host));
	if (name->hostname.utf8string_val == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate memory", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	name->hostname.utf8string_len = nsdb_hostname_len(host);
	name->port = nsdb_port(host);
	return FEDFS_OK;
}

/*
 * "pathname" refers to a non-terminal component
 *
 * If it does not exist, return FEDFS_ERR_INVAL
 * If it is not a directory, return FEDFS_ERR_INVAL
 * If we don't have access, return FEDFS_ERR_ACCESS
 * If it is a junction, return FEDFS_ERR_NOTLOCAL
 *
 * Return FEDFS_OK if it's OK to continue walking this path.
 */
static FedFsStatus
fedfsd_pathwalk_check_nonterm(const char *pathname)
{
	FedFsStatus retval;

	retval = fedfs_is_junction(pathname);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		retval = FEDFS_OK;
		break;
	case FEDFS_OK:
		xlog(D_CALL, "%s: Pathname contains a junction",
			__func__);
		retval = FEDFS_ERR_NOTLOCAL;
		break;
	default:
		break;
	}
	return retval;
}

/*
 * "pathname" refers to a terminal component
 *
 * If it's '.' or '..', return FEDFS_ERR_INVAL
 * If we don't have access, return FEDFS_ERR_ACCESS
 * If it doesn't exist, return FEDFS_OK
 * If it's a junction, return FEDFS_ERR_EXIST
 * If it's a prejunction, return FEDFS_ERR_NOTJUNCT
 * If it's not a prejunction, return FEDFS_ERR_INVAL
 */
static FedFsStatus
fedfsd_pathwalk_check_term(const char *pathname)
{
	FedFsStatus retval;
	char *c;

	c = strrchr(pathname, '/');
	if (c == NULL)
		c = (char *)pathname;
	if (strcmp(pathname, ".") == 0 ||
	    strcmp(pathname, "..") == 0) {
		xlog(D_CALL, "%s: terminal '.' or '..' detected",
			__func__);
		return FEDFS_ERR_INVAL;
	}

	retval = fedfs_is_junction(pathname);
	switch (retval) {
	case FEDFS_OK:
		xlog(D_CALL, "%s: Pathname ends with a junction",
			__func__);
		return FEDFS_ERR_EXIST;
	case FEDFS_ERR_INVAL:
		xlog(D_CALL, "%s: Pathname ends with a non-existant object",
			__func__);
		return FEDFS_OK;
	case FEDFS_ERR_NOTJUNCT:
		break;
	default:
		goto out_err;
	}

	retval = fedfs_is_prejunction(pathname);
	if (retval != FEDFS_OK)
		goto out_err;

	xlog(D_CALL, "%s: Pathname ends with a pre-junction",
		__func__);
	return FEDFS_ERR_NOTJUNCT;

out_err:
	xlog(D_CALL, "%s: Failed with %s",
		__func__, nsdb_display_fedfsstatus(retval));
	return retval;
}

/**
 * Convert a FedFsPathName to a valid local POSIX pathname
 *
 * @param fpath FedFsPathName
 * @param pathname OUT: NUL-terminated C string containing a POSIX pathname
 * @return a FedFsStatus code
 *
 * "fpath" contains a numbered array of components, each expressed as a
 * UTF-8 string.  Decode each component and insert appropriate local
 * pathname separators.  Strict checking of pathname length is applied.
 * All components, if they exist, MUST exist in the local file system.
 *
 * This function is used by both the junction create and delete
 * operations, thus several successful error return values are needed.
 * By "successful" we mean that a pathname is returned in the
 * "pathname" argument in these cases.  Caller must free the returned
 * pathname with free(3).
 *
 *   1.	FEDFS_ERR_NOTJUNCT
 *
 *	All components of the pathname exist and are valid local
 *	objects.  The object the pathname refers to is a pre-junction.
 *
 *   2.	FEDFS_ERR_EXIST
 *
 *	All components of the pathname exist and are valid local
 *	objects.  The object the pathname refers to is a junction.
 *
 *   3.	FEDFS_OK
 *
 *	All components of the pathname except the terminal component
 *	exist and are valid local objects.
 *
 *  All other return values signal error conditions, and do not
 *  alter the "pathname" argument.  Most particularly, we MUST ensure
 *  that no component of "pathname" is a junction.
 */
FedFsStatus
fedfsd_pathwalk(const FedFsPathName fpath, char **pathname)
{
	FedFsStatus retval;
	char *result, *tmp;
	unsigned int i;

	result = malloc(PATH_MAX);
	if (result == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate buffer for result",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}
	result[0] = '\0';

	if (fpath.FedFsPathName_len == 0) {
		xlog(D_CALL, "%s: Zero-component pathname", __func__);
		strcat(result, "/");
		retval = fedfsd_pathwalk_check_term(result);
		if (retval != FEDFS_OK) {
			free(result);
			return retval;
		}
		*pathname = result;
		return FEDFS_OK;
	}

	for (i = 0; i < fpath.FedFsPathName_len; i++) {
		FedFsPathComponent fcomp = fpath.FedFsPathName_val[i];
		char *component = fcomp.utf8string_val;
		unsigned int len = fcomp.utf8string_len;

		xlog(D_CALL, "%s: Visiting component '%s'",
			__func__, component);

		if ((long)len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component too long",
				__func__);
			free(result);
			return FEDFS_ERR_NAMETOOLONG;
		}

		if (len != 0) {
			if (strchr(component, '/') != NULL) {
				xlog(D_GENERAL, "%s: Component contains local "
					"pathname separator character", __func__);
				free(result);
				return FEDFS_ERR_BADNAME;
			}
			if (strlen(result) + strlen("/") + len >= PATH_MAX) {
				xlog(D_GENERAL, "%s: Pathname too long",
					__func__);
				free(result);
				return FEDFS_ERR_NAMETOOLONG;
			}
			strcat(result, "/");
			strcat(result, component);
		} else {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			free(result);
			return FEDFS_ERR_BADNAME;
		}

		/* Look for non-last component being a junction */
		if (i < fpath.FedFsPathName_len - 1) {
			retval = fedfsd_pathwalk_check_nonterm(result);
			if (retval != FEDFS_OK) {
				free(result);
				return retval;
			}
		}
	}

	if (!nsdb_pathname_is_utf8(result)) {
		free(result);
		return FEDFS_ERR_BADCHAR;
	}

	tmp = nsdb_normalize_path(result);
	free(result);
	if (tmp == NULL)
		return FEDFS_ERR_SVRFAULT;

	retval = fedfsd_pathwalk_check_term(tmp);
	switch (retval) {
	case FEDFS_OK:
	case FEDFS_ERR_EXIST:
	case FEDFS_ERR_NOTJUNCT:
		*pathname = tmp;
		break;
	default:
		free(tmp);
	}

	return retval;
}

/**
 * Return a void reply to a calling client
 *
 * @param xprt transport on which to send reply
 * @param procname NUL-terminated C string containing procedure name
 */
static void
fedfsd_send_null_reply(SVCXPRT *xprt, const char *procname)
{
	if (!svc_sendreply(xprt, (xdrproc_t)xdr_void, NULL)) {
		xlog(L_WARNING, "Failed to send %s reply", procname);
		svcerr_systemerr(xprt);
	}
}

/**
 * Service a FEDFS NULL request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is VOID.
 */
static void
fedfsd_svc_null_1(SVCXPRT *xprt)
{
	xlog(D_CALL, "%s: Replying with void", __func__);
	fedfsd_send_null_reply(xprt, "NULLPROC");
}

/**
 * Attempt to create a directory to be used as a junction
 *
 * @param pathname NUL-terminated C string containing pathname of new dir
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfsd_mkdir(const char *pathname)
{
	if (mkdir(pathname, 0755) == 0)
		return FEDFS_OK;

	xlog(D_GENERAL, "%s: mkdir(2): %m", __func__);
	switch (errno) {
	case EACCES:
	case EPERM:
		return FEDFS_ERR_ACCESS;
	case EEXIST:
		return fedfs_is_prejunction(pathname);
	case ELOOP:
		return FEDFS_ERR_LOOP;
	case ENAMETOOLONG:
		return FEDFS_ERR_NAMETOOLONG;
	case ENOENT:
	case ENOTDIR:
		return FEDFS_ERR_INVAL;
	case ENOSPC:
		return FEDFS_ERR_NOSPC;
	case EROFS:
		return FEDFS_ERR_ROFS;
	default:
		return FEDFS_ERR_SVRFAULT;
	}
}

/**
 * Service a FEDFS CREATE_JUNCTION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is a FedFsStatus code.
 */
static void
fedfsd_svc_create_junction_1(SVCXPRT *xprt)
{
	char fsn_uuid[FEDFS_UUID_STRLEN];
	char *pathname = NULL;
	char *hostname = NULL;
	FedFsCreateArgs args;
	unsigned short port;
	nsdb_t host = NULL;
	FedFsStatus result;
	uuid_t uu;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsCreateArgs, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode CREATE_JUNCTION arguments");
		svcerr_decode(xprt);
		return;
	}

	result = FEDFS_ERR_PATH_TYPE_UNSUPP;
	if (args.path.type != FEDFS_PATH_SYS)
		goto out;

	result = fedfsd_nsdbname(args.fsn.nsdbName, &hostname, &port);
	if (result != FEDFS_OK)
		goto out;

	result = nsdb_lookup_nsdb(hostname, port, &host, NULL);
	if (result != FEDFS_OK)
		goto out;

	/* RFC 4122 UUID string representation */
	memcpy(uu, args.fsn.fsnUuid, sizeof(uu));
	uuid_unparse(uu, fsn_uuid);

	result = fedfsd_pathwalk(args.path.FedFsPath_u.adminPath, &pathname);
	switch (result) {
	case FEDFS_OK:
		result = fedfsd_mkdir(pathname);
		if (result != FEDFS_OK)
			goto out;
		break;
	case FEDFS_ERR_NOTJUNCT:
		break;
	default:
		goto out;
	}

	result = fedfs_save_mode(pathname);
	if (result != FEDFS_OK) {
		xlog(D_GENERAL, "%s: fedfs_save_mode", __func__);
		goto out;
	}

	result = fedfs_store_fsn(pathname, fsn_uuid, host);
	if (result != FEDFS_OK)
		xlog(D_GENERAL, "%s: fedfs_store_fsn", __func__);
	else {
		xlog(D_CALL, "%s: uuid: %s",
			__func__, fsn_uuid);
		xlog(D_CALL, "%s: nsdb: %s:%u",
			__func__, nsdb_hostname(host), nsdb_port(host));
	}

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsStatus, &result)) {
		xlog(L_WARNING, "Failed to send CREATE_JUNCTION reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsCreateArgs, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free CREATE_JUNCTION arguments");

	nsdb_free_nsdb(host);
	free(hostname);
	free(pathname);
}

/**
 * Attempt to remove a directory that was a junction
 *
 * @param pathname NUL-terminated C string containing pathname of dir
 *
 * If the fedfs UID and GID own this directory, that means we
 * created it via FEDFS_CREATE_JUNCTION, so remove it.
 *
 */
static void
fedfsd_rmdir(const char *pathname)
{
	struct stat stb;

	/*
	 * Explicitly check the UID and GID because we run with
	 * CAP_DAC_OVERRIDE, which would allow us to delete anything.
	 */
	if (lstat(pathname, &stb) == -1) {
		xlog(D_GENERAL, "%s: lstat(%s): %m",
			__func__, pathname);
		return;
	}
	if (stb.st_uid != geteuid() ||
	    stb.st_gid != getegid()) {
		xlog(D_CALL, "%s: skipping deletion of %s",
			__func__, pathname);
		return;
	}

	if (rmdir(pathname) == -1)
		xlog(D_GENERAL, "%s: rmdir(%s): %m",
			__func__, pathname);
	else
		xlog(D_CALL, "%s: deleted %s", __func__, pathname);
}

/**
 * Service a FEDFS DELETE_JUNCTION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is a FedFsStatus code.
 */
static void
fedfsd_svc_delete_junction_1(SVCXPRT *xprt)
{
	char *pathname = NULL;
	FedFsStatus result;
	FedFsPath args;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsPath, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode DELETE_JUNCTION arguments");
		svcerr_decode(xprt);
		return;
	}

	result = fedfsd_pathwalk(args.FedFsPath_u.adminPath, &pathname);
	switch (result) {
	case FEDFS_ERR_EXIST:
		break;
	case FEDFS_OK:
	case FEDFS_ERR_NOTJUNCT:
		result = FEDFS_ERR_INVAL;
		goto out;
	default:
		goto out;
	}

	result = fedfs_restore_mode(pathname);
	if (result != FEDFS_OK)
		goto out;

	result = fedfs_remove_fsn(pathname);
	if (result!= FEDFS_OK)
		goto out;

	fedfsd_rmdir(pathname);
	result = FEDFS_OK;

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsStatus, &result)) {
		xlog(L_WARNING, "Failed to send DELETE_JUNCTION reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsPath, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free DELETE_JUNCTION arguments");
	free(pathname);
}

static void
fedfsd_free_fedfsfsl(FedFsFsl *rpcfsl)
{
	free(rpcfsl->FedFsFsl_u.nfsFsl.hostname.utf8string_val);
	nsdb_free_fedfspathname(&rpcfsl->FedFsFsl_u.nfsFsl.path);
}

static void
fedfsd_free_fedfslookupresok(FedFsLookupResOk *resok)
{
	unsigned int i;

	for (i = 0; i < resok->fsl.fsl_len; i++)
		fedfsd_free_fedfsfsl(&resok->fsl.fsl_val[i]);
	free(resok->fsl.fsl_val);
	free(resok->fsn.nsdbName.hostname.utf8string_val);
}

/**
 * Fill in one FedFsFsl structure
 *
 * @param fsl struct fedfs_fsl containing relevant FSL data
 * @param new pointer to FedFsFsl struct to fill in
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfsd_fill_in_fedfsfsl(const struct fedfs_fsl *fsl, FedFsFsl *new)
{
	FedFsStatus retval;
	uuid_t uu;

	if (fsl->fl_type != FEDFS_NFS_FSL) {
		xlog(L_ERROR, "%s: Unrecognized FSL type", __func__);
		return FEDFS_ERR_NSDB_NOFSL;
	}
	new->type = fsl->fl_type;

	retval = FEDFS_ERR_SVRFAULT;
	if (uuid_parse(fsl->fl_fsluuid, uu)) {
		xlog(D_GENERAL, "%s: Failed to parse FSL uuid", __func__);
		goto out_free;
	}
	memcpy(new->FedFsFsl_u.nfsFsl.fslUuid, &uu, sizeof(uu));

	new->FedFsFsl_u.nfsFsl.port = fsl->fl_fslport;
	new->FedFsFsl_u.nfsFsl.hostname.utf8string_len = strlen(fsl->fl_fslhost);
	new->FedFsFsl_u.nfsFsl.hostname.utf8string_val = strdup(fsl->fl_fslhost);
	if (new->FedFsFsl_u.nfsFsl.hostname.utf8string_val == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate hostname", __func__);
		goto out_free;
	}

	retval = nsdb_path_array_to_fedfspathname(fsl->fl_u.fl_nfsfsl.fn_nfspath,
					&new->FedFsFsl_u.nfsFsl.path);
	if (retval != FEDFS_OK)
		goto out_free;

	return FEDFS_OK;

out_free:
	fedfsd_free_fedfsfsl(new);
	return retval;
}

/**
 * Prepare a LOOKUP_NSDB type FEDFS_LOOKUP_JUNCTION reply 
 *
 * @param fsls a list of struct fedfs_fsl items
 * @param result LOOKUP_JUNCTION result to fill in
 *
 * Derive an array of FedFsFsl structures from the list of fedfs_fsl's.
 */
static FedFsStatus
fedfsd_prepare_fedfsfsl_array(const struct fedfs_fsl *fsls,
		FedFsLookupResOk *result)
{
	const struct fedfs_fsl *fsl;
	unsigned int count, i;

	for (fsl = fsls, count = 0; fsl != NULL; fsl = fsl->fl_next, count++);

	result->fsl.fsl_len = count;
	result->fsl.fsl_val = calloc(count, sizeof(FedFsFsl));
	if (result->fsl.fsl_val == NULL)
		return FEDFS_ERR_SVRFAULT;

	for (fsl = fsls, i = 0; fsl != NULL; fsl = fsl->fl_next, i++) {
		FedFsStatus retval;

		retval = fedfsd_fill_in_fedfsfsl(fsl, &result->fsl.fsl_val[i]);
		switch (retval) {
		case FEDFS_OK:
			continue;
		case FEDFS_ERR_NSDB_NOFSL:
			result->fsl.fsl_len--;
			i--;
			continue;
		default:
			fedfsd_free_fedfslookupresok(result);
			return FEDFS_ERR_SVRFAULT;
		}
	}

	return FEDFS_OK;
}

/**
 * Service a FEDFS LOOKUP_JUNCTION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is FedFsLookupRes.
 */
static void
fedfsd_svc_lookup_junction_1(SVCXPRT *xprt)
{
	unsigned int ldap_err = 0;
	FedFsLookupRes result;
	FedFsLookupResOk *resok = &result.FedFsLookupRes_u.resok;
	FedFsLookupArgs args;
	struct fedfs_fsl *fsls;
	char *fsn_uuid = NULL;
	char *pathname = NULL;
	nsdb_t host = NULL;
	uuid_t uu;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode LOOKUP_JUNCTION arguments");
		svcerr_decode(xprt);
		return;
	}

	memset(&result, 0, sizeof(result));
	result.status = FEDFS_ERR_PATH_TYPE_UNSUPP;
	if (args.path.type != FEDFS_PATH_SYS)
		goto out;

	result.status = FEDFS_ERR_BADXDR;
	switch (args.resolve) {
	case FEDFS_RESOLVE_NONE:
	case FEDFS_RESOLVE_CACHE:
	case FEDFS_RESOLVE_NSDB:
		break;
	default:
		goto out;
	}

	result.status = fedfsd_pathwalk(args.path.FedFsPath_u.adminPath,
								&pathname);
	switch (result.status) {
	case FEDFS_ERR_EXIST:
		break;
	case FEDFS_OK:
	case FEDFS_ERR_NOTJUNCT:
		result.status = FEDFS_ERR_INVAL;
		goto out;
	default:
		goto out;
	}

	memset(&result, 0, sizeof(result));

	result.status = fedfs_get_fsn(pathname, &fsn_uuid, &host);
	if (result.status != FEDFS_OK) {
		goto out;
	}

	result.status = fedfsd_nsdb_to_nsdbname(host, &resok->fsn.nsdbName);
	if (result.status != FEDFS_OK)
		goto out;
	if (uuid_parse(fsn_uuid, uu)) {
		xlog(D_GENERAL, "%s: Failed to parse FSN uuid", __func__);
		result.status = FEDFS_ERR_SVRFAULT;
		goto out;
	}
	memcpy(resok->fsn.fsnUuid, &uu, sizeof(uu));

	switch (args.resolve) {
	case FEDFS_RESOLVE_NONE:
	case FEDFS_RESOLVE_CACHE:
		break;
	case FEDFS_RESOLVE_NSDB:
		result.status = nsdb_open_nsdb(host, NULL, NULL, &ldap_err);
		if (result.status != FEDFS_OK)
			break;

		result.status = nsdb_resolve_fsn_s(host, NULL, fsn_uuid,
								&fsls, &ldap_err);
		nsdb_close_nsdb(host);
		if (result.status == FEDFS_ERR_NSDB_LDAP_VAL) {
			result.FedFsLookupRes_u.ldapResultCode = ldap_err;
			break;
		}
		if (result.status != FEDFS_OK)
			break;
		result.status = fedfsd_prepare_fedfsfsl_array(fsls, resok);
		nsdb_free_fedfs_fsls(fsls);
		break;
	default:
		result.status = FEDFS_ERR_SVRFAULT;
	}

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result.status));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsLookupRes, &result)) {
		xlog(L_WARNING, "Failed to send LOOKUP_JUNCTION reply");
		svcerr_systemerr(xprt);
	}

	fedfsd_free_fedfslookupresok(resok);
	free(fsn_uuid);
	nsdb_free_nsdb(host);
	free(pathname);

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free LOOKUP_JUNCTION arguments");
}

/**
 * Service a SET_NSDB_PARAMS request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is a FedFsStatus code.
 */
static void
fedfsd_svc_set_nsdb_params_1(SVCXPRT *xprt)
{
	struct fedfs_secdata secdata;
	FedFsSetNsdbParamsArgs args;
	char *hostname = NULL;
	unsigned int ldap_err;
	unsigned short port;
	FedFsStatus result;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsSetNsdbParamsArgs, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode SET_NSDB_PARAMS arguments");
		svcerr_decode(xprt);
		return;
	}

	result = fedfsd_nsdbname(args.nsdbName, &hostname, &port);
	if (result != FEDFS_OK)
		goto out;

	result = nsdb_ping_s(hostname, port, &ldap_err);
	switch (result) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		xlog(L_ERROR, "Failed to ping NSDB %s:%u: %s\n",
			hostname, port, ldap_err2string(ldap_err));
		goto out;
	default:
		xlog(L_ERROR, "Warning: %s:%u is not an NSDB: %s",
			hostname, port, nsdb_display_fedfsstatus(result));
		goto out;
	}

	switch (args.params.secType) {
	case FEDFS_SEC_NONE:
		secdata.len = 0;
		secdata.data = "";
		break;
	case FEDFS_SEC_TLS:
		secdata.len =
			args.params.FedFsNsdbParams_u.secData.secData_len;
		secdata.data =
			args.params.FedFsNsdbParams_u.secData.secData_val;
		break;
	default:
		result = FEDFS_ERR_BADXDR;
		goto out;
	}
	secdata.type = args.params.secType;

	result = nsdb_update_nsdb(hostname, port, &secdata);

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsStatus, &result)) {
		xlog(L_WARNING, "Failed to send SET_NSDB_PARAMS reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsSetNsdbParamsArgs, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free SET_NSDB_PARAMS arguments");

	free(hostname);
}

/**
 * Service a GET_NSDB_PARAMS request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is FedFsGetNsdbParamsRes.
 */
static void
fedfsd_svc_get_nsdb_params_1(SVCXPRT *xprt)
{
	FedFsGetNsdbParamsRes result;
	struct fedfs_secdata secdata;
	char *hostname = NULL;
	unsigned short port;
	FedFsNsdbName args;
	nsdb_t host;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsNsdbName, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode GET_NSDB_PARAMS arguments");
		svcerr_decode(xprt);
		return;
	}

	memset(&result, 0, sizeof(result));

	result.status = fedfsd_nsdbname(args, &hostname, &port);
	if (result.status != FEDFS_OK)
		goto out;

	result.status = nsdb_lookup_nsdb(hostname, port, &host, &secdata);
	if (result.status == FEDFS_OK) {
		FedFsNsdbParams *params = &result.FedFsGetNsdbParamsRes_u.params;
		params->secType = (FedFsConnectionSec)secdata.type;
		params->FedFsNsdbParams_u.secData.secData_len =
							secdata.len;
		params->FedFsNsdbParams_u.secData.secData_val =
							secdata.data;
	}

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result.status));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsGetNsdbParamsRes, &result)) {
		xlog(L_WARNING, "Failed to send GET_NSDB_PARAMS reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsNsdbName, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free GET_NSDB_PARAMS arguments");

	nsdb_free_nsdb(host);
	free(hostname);
	free(secdata.data);
}

/**
 * Service a GET_LIMITED_ NSDB_PARAMS request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is FedFsGetLimitedNsdbParamsRes.
 */
static void
fedfsd_svc_get_limited_nsdb_params_1(SVCXPRT *xprt)
{
	FedFsGetLimitedNsdbParamsRes result;
	struct fedfs_secdata secdata;
	char *hostname = NULL;
	unsigned short port;
	FedFsNsdbName args;
	nsdb_t host;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsNsdbName, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode GET_LIMITED_NSDB_PARAMS arguments");
		svcerr_decode(xprt);
		return;
	}

	memset(&result, 0, sizeof(result));

	result.status = fedfsd_nsdbname(args, &hostname, &port);
	if (result.status != FEDFS_OK)
		goto out;

	result.status = nsdb_lookup_nsdb(hostname, port, &host, &secdata);
	if (result.status == FEDFS_OK)
		result.FedFsGetLimitedNsdbParamsRes_u.secType =
				(FedFsConnectionSec)secdata.type;
	nsdb_free_nsdb(host);
	free(hostname);

out:
	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result.status));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsGetLimitedNsdbParamsRes, &result)) {
		xlog(L_WARNING, "Failed to send GET_LIMITED_NSDB_PARAMS reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsNsdbName, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free GET_LIMITED_NSDB_PARAMS arguments");
}

/**
 * Service a FEDFS CREATE_REPLICATION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is a FedFsStatus code.
 */
static void
fedfsd_svc_create_replication_1(SVCXPRT *xprt)
{
	FedFsCreateArgs args;
	FedFsStatus result;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsCreateArgs, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode CREATE_REPLICATION arguments");
		svcerr_decode(xprt);
		return;
	}

	result = FEDFS_ERR_NOTSUPP;

	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsStatus, &result)) {
		xlog(L_WARNING, "Failed to send CREATE_REPLICATION reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsCreateArgs,
								(caddr_t)&args))
		xlog(L_WARNING, "Failed to free CREATE_REPLICATION arguments");
}

/**
 * Service a FEDFS DELETE_REPLICATION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is a FedFsStatus code.
 */
static void
fedfsd_svc_delete_replication_1(SVCXPRT *xprt)
{
	FedFsStatus result;
	FedFsPathName args;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsPathName, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode DELETE_REPLICATION arguments");
		svcerr_decode(xprt);
		return;
	}

	result = FEDFS_ERR_NOTSUPP;

	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsStatus, &result)) {
		xlog(L_WARNING, "Failed to send DELETE_REPLICATION reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsPathName, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free DELETE_REPLICATION arguments");
}

/**
 * Service a FEDFS LOOKUP_REPLICATION request
 *
 * @param xprt transport on which to send reply
 *
 * RPC reply is FedFsLookupRes.
 */
static void
fedfsd_svc_lookup_replication_1(SVCXPRT *xprt)
{
	FedFsLookupRes result;
	FedFsLookupArgs args;

	memset(&args, 0, sizeof(args));
	if (!svc_getargs(xprt, (xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)&args)) {
		xlog(L_WARNING, "Failed to decode LOOKUP_REPLICATION arguments");
		svcerr_decode(xprt);
		return;
	}

	memset(&result, 0, sizeof(result));
	result.status = FEDFS_ERR_NOTSUPP;

	xlog(D_CALL, "%s: Replying with %s",
			__func__, nsdb_display_fedfsstatus(result.status));

	if (!svc_sendreply(xprt, (xdrproc_t)xdr_FedFsLookupRes, &result)) {
		xlog(L_WARNING, "Failed to send LOOKUP_REPLICATION reply");
		svcerr_systemerr(xprt);
	}

	if (!svc_freeargs(xprt, (xdrproc_t)xdr_FedFsLookupArgs, (caddr_t)&args))
		xlog(L_WARNING, "Failed to free LOOKUP_REPLICATION arguments");
}

/**
 * Server-side entry point for RPC procedure calls
 *
 * @param rqstp incoming RPC request
 * @param xprt transport on which to send reply
 */
void
fedfsd_dispatch_1(struct svc_req *rqstp, SVCXPRT *xprt)
{
	char addrbuf[INET6_ADDRSTRLEN];

	fedfsd_caller(rqstp, addrbuf, sizeof(addrbuf));
	switch (rqstp->rq_proc) {
	case NULLPROC:
		xlog(D_CALL, "%s: Received NULLPROC request from %s",
				__func__, addrbuf);
		fedfsd_svc_null_1(xprt);
		break;
	case FEDFS_CREATE_JUNCTION:
		xlog(D_CALL, "%s: Received CREATE_JUNCTION request from %s",
				__func__, addrbuf);
		fedfsd_svc_create_junction_1(xprt);
		break;
	case FEDFS_DELETE_JUNCTION:
		xlog(D_CALL, "%s: Received DELETE_JUNCTION request from %s",
				__func__, addrbuf);
		fedfsd_svc_delete_junction_1(xprt);
		break;
	case FEDFS_LOOKUP_JUNCTION:
		xlog(D_CALL, "%s: Received LOOKUP_JUNCTION request from %s",
				__func__, addrbuf);
		fedfsd_svc_lookup_junction_1(xprt);
		break;
	case FEDFS_SET_NSDB_PARAMS:
		xlog(D_CALL, "%s: Received SET_NSDB_PARAMS request from %s",
				__func__, addrbuf);
		fedfsd_svc_set_nsdb_params_1(xprt);
		break;
	case FEDFS_GET_NSDB_PARAMS:
		xlog(D_CALL, "%s: Received GET_NSDB_PARAMS request from %s",
				__func__, addrbuf);
		fedfsd_svc_get_nsdb_params_1(xprt);
		break;
	case FEDFS_GET_LIMITED_NSDB_PARAMS:
		xlog(D_CALL, "%s: Received GET_LIMITED_NSDB_PARAMS request from %s",
				__func__, addrbuf);
		fedfsd_svc_get_limited_nsdb_params_1(xprt);
		break;
	case FEDFS_CREATE_REPLICATION:
		xlog(D_CALL, "%s: Received CREATE_REPLICATION request from %s",
				__func__, addrbuf);
		fedfsd_svc_create_replication_1(xprt);
		break;
	case FEDFS_DELETE_REPLICATION:
		xlog(D_CALL, "%s: Received DELETE_REPLICATION request from %s",
				__func__, addrbuf);
		fedfsd_svc_delete_replication_1(xprt);
		break;
	case FEDFS_LOOKUP_REPLICATION:
		xlog(D_CALL, "%s: Received LOOKUP_REPLICATION request from %s",
				__func__, addrbuf);
		fedfsd_svc_lookup_replication_1(xprt);
		break;
	default:
		xlog(L_WARNING, "Unrecognized RPC procedure number %d",
				rqstp->rq_proc);
		svcerr_noproc(xprt);
	}
}
