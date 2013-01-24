/**
 * @file src/plug-ins/nfs-plugin.c
 * @brief DLL to resolve junction information
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

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <libxml/parser.h>

#include "fedfs_admin.h"
#include "nfs-plugin.h"
#include "junction.h"

struct nfs_fsloc_set {
	int			  ns_ttl;
	struct nfs_fsloc	 *ns_current;
	struct nfs_fsloc	 *ns_list;
};

static _Bool debug = false;

/**
 * Write a debugging message to stderr
 *
 * @param fmt NUL-terminated C string containing output format specification
 *
 * NB:	Caller may have already opened syslog for her own use.  We can't
 *	hijack it here, so using xlog() is right out.  Thus output is
 *	directed to stderr via fprintf(3).
 */
static void
nfs_jp_debug(const char *fmt, ...)
{
	va_list args;

	if (!debug)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

/**
 * Perform any plug-in startup processing
 *
 * @param want_debugging true if caller wants to enable debugging output
 * @return a junction status code
 */
static enum jp_status
nfs_jp_init(_Bool want_debugging)
{
	debug = want_debugging;
	nfs_jp_debug("%s: Junction plug-in version " VERSION "\n", __func__);
	xmlInitParser();
	return JP_OK;
}

/**
 * Perform any plug-in shutdown processing
 *
 * Nothing to be done for NFS junctions.
 */
static void
nfs_jp_done(void)
{
	nfs_jp_debug("%s: Finishing\n", __func__);
	xmlCleanupParser();
	return;
}

/**
 * Given an status code, return a pointer to a static error message
 *
 * @param status a junction plug-in status code
 * @return a static NUL-terminated string
 */
static const char *
nfs_jp_error(enum jp_status status)
{
	static char buf[128];

	switch (status) {
	case JP_OK:
		return "Success";
	case JP_INVAL:
		return "Invalid parameter";
	case JP_ACCESS:
		return "Permission denied";
	case JP_EXIST:
		return "Object cannot be made into a junction";
	case JP_TYPE_NOT_SUPP:
		return "Junction type not supported";
	case JP_OP_NOT_SUPP:
		return "Junction method not supported";
	case JP_ISJUNCTION:
		return "Object is a junction";
	case JP_NOTJUNCTION:
		return "Object is not a junction";
	case JP_NSDBLOCAL:
		return "A local NSDB configuration error occurred";
	case JP_NSDBREMOTE:
		return "An error occurred on the NSDB";
	case JP_MEMORY:
		return "Memory allocation failure";
	case JP_SYSTEM:
		snprintf(buf, sizeof(buf), "System error (%d): %s",
				status, strerror(errno));
		return buf;
	case JP_PARSE:
		return "Failed to parse locations data";
	case JP_EMPTY:
		return "No more locations in location set";
	}

	snprintf(buf, sizeof(buf), "Unknown error (%d)", status);
	return buf;
}

/**
 * Release a set of NFS locations
 *
 * @param locset set of NFS locations to release
 */
static void
nfs_jp_put_locations(nfs_fsloc_set_t locset)
{
	if (locset == NULL) {
		nfs_jp_debug("%s: Invalid parameters\n", __func__);
		return;
	}

	nfs_jp_debug("%s: Freeing location set %p, ns_list=%p\n",
		__func__, locset, locset->ns_list);
	nfs_free_locations(locset->ns_list);
	free(locset);
}

/**
 * Internal function to allocate a set of NFS locations
 *
 * @return dynamically allocated nfs_fsloc_set_t object
 *
 * If return value is non-NULL, caller must free it with
 * nfs_jp_put_locations().
 */
__attribute_malloc__
static nfs_fsloc_set_t
nfs_jp_alloc_locations(void)
{
	return calloc(1, sizeof(struct nfs_fsloc_set));
}

/**
 * Internal function to rewind a set of locations
 *
 * @param locset set of NFS locations to rewind
 */
static void
nfs_jp_do_rewind_locations(nfs_fsloc_set_t locset)
{
	locset->ns_current = locset->ns_list;
}

/**
 * Resolve NFS basic junction information into a set of NFS locations
 *
 * @param junct_path NUL-terminated C string containing POSIX path of junction
 * @param locset OUT set of NFS locations
 * @return a junction status code
 *
 * If this entry point returns JP_OK, the caller must free the returned
 * set of locations by calling the jp_put_locations entry point.
 */
static enum jp_status
nfs_jp_get_basic(const char *junct_path, nfs_fsloc_set_t *locset)
{
	nfs_fsloc_set_t new;
	FedFsStatus retval;

	new = nfs_jp_alloc_locations();
	if (new == NULL) {
		nfs_jp_debug("%s: No memory\n", __func__);
		return JP_MEMORY;
	}

	retval = nfs_get_locations(junct_path, &new->ns_list);
	if (retval != FEDFS_OK) {
		nfs_jp_debug("%s: Failed to get locations: %s\n",
			__func__, nsdb_display_fedfsstatus(retval));
		nfs_jp_put_locations(new);
		return JP_PARSE;
	}

	nfs_jp_debug("%s: Returning location set %p\n", __func__, new);
	nfs_jp_do_rewind_locations(new);
	new->ns_ttl = FEDFS_NFS_BASIC_TTL;
	*locset = new;
	return JP_OK;
}

/**
 * Convert one FedFS fileset location into one NFS location
 *
 * @param fsl a FedFS fileset location
 * @param fsloc OUT an NFS location
 * @return a junction status code
 *
 * If nfs_jp_convert_fedfs_fsl() returns JP_OK, the caller must free the
 * returned location by calling nfs_free_location().
 */
static enum jp_status
nfs_jp_convert_fedfs_fsl(struct fedfs_fsl *fsl, struct nfs_fsloc **fsloc)
{
	struct fedfs_nfs_fsl *nfs_fsl = &fsl->fl_u.fl_nfsfsl;
	struct nfs_fsloc *new;

	new = nfs_new_location();
	if (new == NULL) {
		nfs_jp_debug("%s: No memory\n", __func__);
		return JP_MEMORY;
	}

	new->nfl_hostname = strdup(nfs_fsl->fn_fslhost);
	new->nfl_hostport = nfs_fsl->fn_fslport;
	new->nfl_rootpath = nfs_dup_string_array(nfs_fsl->fn_nfspath);
	if (new->nfl_hostname == NULL || new->nfl_rootpath == NULL) {
		nfs_free_location(new);
		nfs_jp_debug("%s: No memory\n", __func__);
		return JP_MEMORY;
	}

	new->nfl_flags.nfl_varsub = nfs_fsl->fn_varsub;
	new->nfl_currency = nfs_fsl->fn_currency;
	new->nfl_validfor = nfs_fsl->fn_validfor;
	new->nfl_genflags.nfl_writable = nfs_fsl->fn_gen_writable;
	new->nfl_genflags.nfl_going = nfs_fsl->fn_gen_going;
	new->nfl_genflags.nfl_split = nfs_fsl->fn_gen_split;
	new->nfl_transflags.nfl_rdma = nfs_fsl->fn_trans_rdma;
	new->nfl_info.nfl_simul = nfs_fsl->fn_class_simul;
	new->nfl_info.nfl_handle = nfs_fsl->fn_class_handle;
	new->nfl_info.nfl_fileid = nfs_fsl->fn_class_fileid;
	new->nfl_info.nfl_writever = nfs_fsl->fn_class_writever;
	new->nfl_info.nfl_change = nfs_fsl->fn_class_change;
	new->nfl_info.nfl_readdir = nfs_fsl->fn_class_readdir;
	new->nfl_info.nfl_readrank = nfs_fsl->fn_readrank;
	new->nfl_info.nfl_writerank = nfs_fsl->fn_writerank;
	new->nfl_info.nfl_readorder = nfs_fsl->fn_readorder;
	new->nfl_info.nfl_writeorder = nfs_fsl->fn_writeorder;

	*fsloc = new;
	return JP_OK;
}

/**
 * Convert FedFS fileset locations into a set of NFS locations
 *
 * @param fsls a list of FedFS fileset locations
 * @param new empty set of NFS locations to fill in
 * @return a junction status code
 *
 * If nfs_jp_convert_fedfs_fsls() returns JP_OK, the caller must free the returned
 * set of locations by calling nfs_jp_put_locations().
 */
static enum jp_status
nfs_jp_convert_fedfs_fsls(struct fedfs_fsl *fsls, nfs_fsloc_set_t new)
{
	struct fedfs_fsl *fsl;

	if (fsls == NULL) {
		nfs_jp_debug("%s: No locations\n", __func__);
		return JP_EMPTY;
	}

	for (fsl = fsls; fsl != NULL; fsl = fsl->fl_next) {
		struct nfs_fsloc *fsloc;
		enum jp_status status;

		status = nfs_jp_convert_fedfs_fsl(fsl, &fsloc);
		if (status != JP_OK) {
			nfs_jp_put_locations(new);
			return status;
		}

		if (new->ns_list == NULL)
			new->ns_list = fsloc;
		else {
			fsloc->nfl_next = new->ns_list;
			new->ns_list = fsloc;
		}
	}

	nfs_jp_do_rewind_locations(new);
	return JP_OK;
}

/**
 * Attempt to follow an LDAP referral to another NSDB
 *
 * @param host OUT: pointer to an initialized nsdb_t that may be replaced
 * @return a FedFsStatus code
 */
static FedFsStatus
nfs_jp_follow_ldap_referral(nsdb_t *host)
{
	static unsigned int nest = 0;
	FedFsStatus retval;
	nsdb_t old, refer;

	old = *host;
	if (!nsdb_follow_referrals(old)) {
		nfs_jp_debug("LDAP referrals for NSDB %s:%u disallowed\n",
			nsdb_hostname(old), nsdb_port(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	}

	if (nest++ > 10) {
		nfs_jp_debug("Possible referral loop for NSDB %s:%u\n",
			nsdb_hostname(old), nsdb_port(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	}

	retval = nsdb_lookup_nsdb_by_uri(nsdb_referred_to(old), &refer);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_PARAMS:
		nfs_jp_debug("Encountered referral to unrecognized NSDB %s\n",
			nsdb_referred_to(old));
		return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
	default:
		nfs_jp_debug("Problem following referral: %s\n",
			nsdb_display_fedfsstatus(retval));
		return retval;
	}

	nsdb_close_nsdb(old);
	nsdb_free_nsdb(old);
	*host = refer;
	return FEDFS_OK;
}

/**
 * Resolve a FedFS fileset name into a set of NFS locations
 *
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to resolve
 * @param host an initialized NSDB host object
 * @param new empty set of NFS locations
 * @return a junction status code
 *
 * If nfs_jp_resolve_fsn() returns JP_OK, the caller must free the returned
 * set of locations by calling nfs_jp_put_locations().
 */
static enum jp_status
nfs_jp_resolve_fsn(const char *fsn_uuid, nsdb_t host,
		nfs_fsloc_set_t new)
{
	enum jp_status status = JP_NSDBREMOTE;
	struct fedfs_fsl *fsls;
	struct fedfs_fsn *fsn;
	unsigned int ldap_err;
	FedFsStatus retval;
	int fsn_ttl;

again:
	retval = nsdb_open_nsdb(host, NULL, NULL, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		break;
	case FEDFS_ERR_NSDB_CONN:
		nfs_jp_debug("%s: Failed to connect to NSDB %s:%u\n",
			nsdb_hostname(host), nsdb_port(host));
		return JP_NSDBREMOTE;
	case FEDFS_ERR_NSDB_AUTH:
		nfs_jp_debug("%s: Failed to establish secure connection to "
			"NSDB %s:%u\n", nsdb_hostname(host), nsdb_port(host));
		return JP_NSDBLOCAL;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		nfs_jp_debug("%s: Failed to bind to NSDB %s:%u: %s\n",
			nsdb_hostname(host), nsdb_port(host),
			ldap_err2string(ldap_err));
		return JP_NSDBLOCAL;
	default:
		nfs_jp_debug("%s: Failed to open NSDB %s:%u: %s\n",
			nsdb_hostname(host), nsdb_port(host),
			nsdb_display_fedfsstatus(retval));
		return JP_NSDBLOCAL;
	}

	retval = nsdb_get_fsn_s(host, NULL, fsn_uuid, &fsn, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		fsn_ttl = fsn->fn_fsnttl;
		nsdb_free_fedfs_fsn(fsn);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		nfs_jp_debug("%s: No FSL entries for FSN %s\n",
			__func__, fsn_uuid);
		goto out_close;
	case FEDFS_ERR_NSDB_NOFSN:
		nfs_jp_debug("%s: No FSN %s found\n",
			__func__, fsn_uuid);
		goto out_close;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		switch (ldap_err) {
		case LDAP_REFERRAL:
			retval = nfs_jp_follow_ldap_referral(&host);
			if (retval == FEDFS_OK)
				goto again;
			break;
		case LDAP_CONFIDENTIALITY_REQUIRED:
			nfs_jp_debug("TLS security required for %s:%u\n",
				nsdb_hostname(host), nsdb_port(host));
			break;
		default:
			nfs_jp_debug("%s: NSDB operation failed with %s\n",
				__func__, ldap_err2string(ldap_err));
		}
		goto out_close;
	default:
		nfs_jp_debug("%s: Failed to resolve FSN %s: %s\n",
			__func__, fsn_uuid, nsdb_display_fedfsstatus(retval));
		goto out_close;
	}

	retval = nsdb_resolve_fsn_s(host, NULL, fsn_uuid, &fsls, &ldap_err);
	switch (retval) {
	case FEDFS_OK:
		status = nfs_jp_convert_fedfs_fsls(fsls, new);
		if (status == JP_OK)
			new->ns_ttl = fsn_ttl;
		nfs_jp_debug("%s: Returning %p, ns_list=%p\n",
			__func__, new, new->ns_list);
		nsdb_free_fedfs_fsls(fsls);
		break;
	case FEDFS_ERR_NSDB_NOFSL:
		nfs_jp_debug("%s: No FSL entries for FSN %s\n",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_NOFSN:
		nfs_jp_debug("%s: No FSN %s found\n",
			__func__, fsn_uuid);
		break;
	case FEDFS_ERR_NSDB_LDAP_VAL:
		nfs_jp_debug("%s: NSDB operation failed with %s\n",
			__func__, ldap_err2string(ldap_err));
		break;
	default:
		nfs_jp_debug("%s: Failed to resolve FSN %s: %s\n",
			__func__, fsn_uuid, nsdb_display_fedfsstatus(retval));
	}

out_close:
	nsdb_close_nsdb(host);
	return status;
}

/**
 * Resolve FedFS junction information into a set of NFS locations
 *
 * @param junct_path NUL-terminated C string containing POSIX path of junction
 * @param new empty set of NFS locations
 * @return a junction status code
 *
 * If nfs_jp_resolve_fedfs_junction() returns JP_OK, the caller must free
 * the returned set of locations by calling nfs_jp_put_locations().
 */
static enum jp_status
nfs_jp_resolve_fedfs_junction(const char *junct_path, nfs_fsloc_set_t new)
{
	enum jp_status status;
	FedFsStatus retval;
	char *fsn_uuid;
	nsdb_t host;

	retval = fedfs_get_fsn(junct_path, &fsn_uuid, &host);
	/* XXX: Needs expansion */
	if (retval != FEDFS_OK) {
		nfs_jp_debug("%s: Failed to get FSN: %s\n",
			__func__, nsdb_display_fedfsstatus(retval));
		return JP_NSDBREMOTE;
	}

	status = nfs_jp_resolve_fsn(fsn_uuid, host, new);

	nsdb_free_nsdb(host);
	free(fsn_uuid);
	return status;
}

/**
 * Resolve FedFS junction into a set of NFS locations
 *
 * @param junct_path NUL-terminated C string containing POSIX path of junction
 * @param locset OUT set of NFS locations
 * @return a junction status code
 *
 * If nfs_jp_get_fedfs() returns JP_OK, the caller must free the returned
 * set of locations by calling nfs_jp_put_locations().
 */
static enum jp_status
nfs_jp_get_fedfs(const char *junct_path, nfs_fsloc_set_t *locset)
{
	enum jp_status status;
	nfs_fsloc_set_t new;

	new = nfs_jp_alloc_locations();
	if (new == NULL) {
		nfs_jp_debug("%s: No memory\n", __func__);
		return JP_MEMORY;
	}

	status = nfs_jp_resolve_fedfs_junction(junct_path, new);
	if (status != JP_OK) {
		nfs_jp_put_locations(new);
		return status;
	}

	*locset = new;
	nfs_jp_debug("%s: Returning location set %p\n", __func__, new);
	return JP_OK;
}

/**
 * Resolve junction information into a set of NFS locations
 *
 * @param junct_path NUL-terminated C string containing POSIX path of junction
 * @param locset OUT set of NFS locations
 * @return a junction status code
 *
 * If this entry point returns JP_OK, the caller must free the returned
 * set of locations by calling the jp_put_locations entry point.
 */
static enum jp_status
nfs_jp_get_locations(const char *junct_path, nfs_fsloc_set_t *locset)
{
	FedFsStatus retval;

	if (junct_path == NULL || locset == NULL) {
		nfs_jp_debug("%s: Invalid parameters\n", __func__);
		return JP_INVAL;
	}
	nfs_jp_debug("%s: %s\n", __func__, junct_path);

	retval = nfs_is_junction(junct_path);
	if (retval == FEDFS_OK)
		return nfs_jp_get_basic(junct_path, locset);
	if (retval != FEDFS_ERR_NOTJUNCT)
		return JP_NOTJUNCTION;
	retval = fedfs_is_junction(junct_path);
	if (retval == FEDFS_OK)
		return nfs_jp_get_fedfs(junct_path, locset);

	nfs_jp_debug("%s: Not a junction\n", __func__);
	return JP_NOTJUNCTION;
}

/**
 * Reset the current location to the first location in the list
 *
 * @param locset set of NFS locations
 */
static void
nfs_jp_rewind_locations(nfs_fsloc_set_t locset)
{
	if (locset == NULL) {
		nfs_jp_debug("%s: Invalid parameters\n", __func__);
		return;
	}

	nfs_jp_debug("%s: Rewinding %p\n", __func__, locset);
	nfs_jp_do_rewind_locations(locset);
}

/**
 * Get the fileserver hostname and export path from the next location in the set
 *
 * @param locset set of NFS locations
 * @param hostname OUT NUL-terminated C string containing hostname of fileserver
 * @param export_path OUT NUL-terminated C string containing export path
 * @param ttl OUT cache time-to-live, in seconds
 * @return a junction status code
 *
 * If this entry point returns JP_OK, the caller must free the hostname
 * and export_path strings with free(3).
 */
static enum jp_status
nfs_jp_get_next_location(nfs_fsloc_set_t locset,
		char **hostname, char **export_path, int *ttl)
{
	char *hostname_tmp, *export_path_tmp;
	struct nfs_fsloc *fsloc;

	if (locset == NULL || hostname == NULL ||
	    export_path == NULL || ttl == NULL) {
		nfs_jp_debug("%s: Invalid parameters\n", __func__);
		return JP_INVAL;
	}
	nfs_jp_debug("%s: locset=%p, ns_current=%p, ns_list=%p\n",
		__func__, locset, locset->ns_current, locset->ns_list);

	if (locset->ns_current == NULL) {
		nfs_jp_debug("%s: No locations\n", __func__);
		return JP_EMPTY;
	}
	fsloc = locset->ns_current;

	hostname_tmp = strdup(fsloc->nfl_hostname);
	if (hostname_tmp == NULL) {
		nfs_jp_debug("%s: No memory\n", __func__);
		return JP_MEMORY;
	}

	if (nsdb_path_array_to_posix(fsloc->nfl_rootpath,
					&export_path_tmp) != FEDFS_OK) {
		free(hostname_tmp);
		nfs_jp_debug("%s: Failed to parse\n", __func__);
		return JP_PARSE;
	}

	nfs_jp_debug("%s: Success; hostname=%s path=%s\n",
		__func__, hostname_tmp, export_path_tmp);
	*hostname = hostname_tmp;
	*export_path = export_path_tmp;
	*ttl = locset->ns_ttl;
	locset->ns_current = locset->ns_current->nfl_next;
	return JP_OK;
}

/**
 * Vector of methods provided by this plug-in
 */
struct jp_ops nfs_junction_ops = {
	.jp_api_version		= JP_API_VERSION,
	.jp_init		= nfs_jp_init,
	.jp_done		= nfs_jp_done,
	.jp_error		= nfs_jp_error,
	.jp_put_locations	= nfs_jp_put_locations,
	.jp_get_locations	= nfs_jp_get_locations,
	.jp_rewind_locations	= nfs_jp_rewind_locations,
	.jp_get_next_location	= nfs_jp_get_next_location,
};
