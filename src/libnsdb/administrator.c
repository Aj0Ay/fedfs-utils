/**
 * @file src/libnsdb/administrator.c
 * @brief NSDB administrator operations (Chapter 5, section 1)
 *
 * @todo
 *	Implement asynchronous LDAP calls so LDAP replies can be
 *	handled from the RPC svc loop or in GUI clients
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
#include <sys/socket.h>

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>

#include <rpcsvc/nfs_prot.h>

#include "nsdb.h"
#include "junction.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Invoke ldap_search_ext_s(3), requesting no attributes
 *
 * @param func NUL-terminated C string containing name of calling function
 * @param ld an initialized LDAP server descriptor
 * @param base NUL-terminated C string containing search base
 * @param scope LDAP scope
 * @param filter NUL-terminated C string containing search filter
 * @param response OUT: list of LDAP responses
 * @return an LDAP result code
 *
 */
static int
__nsdb_search_nsdb_none_s(const char *func, LDAP *ld, const char *base,
		int scope, char *filter, LDAPMessage **response)
{
	static char *attrs[] = { LDAP_NO_ATTRS, NULL };
	char *uri;

	if (ldap_get_option(ld, LDAP_OPT_URI, &uri) == LDAP_OPT_SUCCESS) {
		xlog(D_CALL, "%s:\n  ldapsearch -H %s -b \"%s\" -s %s '%s'",
			func, uri, base, nsdb_printable_scope(scope), filter);
		ldap_memfree(uri);
	} else {
		xlog(D_CALL, "%s:\n  ldapsearch -b \"%s\" -s %s '%s'",
			func, base, nsdb_printable_scope(scope), filter);
	}

	return ldap_search_ext_s(ld, (char *)base, scope, filter, attrs,
					0, NULL, NULL, NULL,
					LDAP_NO_LIMIT, response);
}

/**
 * Hide the __func__ argument at call sites
 */
#define nsdb_search_nsdb_none_s(ld, base, scope, filter, response) \
	__nsdb_search_nsdb_none_s(__func__, ld, base, scope, filter, response)

/**
 * Invoke ldap_search_ext_s(3), requesting no attributes, no filter
 *
 * @param func NUL-terminated C string containing name of calling function
 * @param ld an initialized LDAP server descriptor
 * @param base NUL-terminated C string containing search base
 * @param response OUT: list of LDAP responses
 * @return an LDAP result code
 *
 */
static int
__nsdb_search_nsdb_nofilter_s(const char *func, LDAP *ld, const char *base,
		LDAPMessage **response)
{
	static char *attrs[] = { LDAP_NO_ATTRS, NULL };
	char *uri;

	if (ldap_get_option(ld, LDAP_OPT_URI, &uri) == LDAP_OPT_SUCCESS) {
		xlog(D_CALL, "%s:\n  ldapsearch -H %s -b \"%s\" -s one",
			func, uri, base);
		ldap_memfree(uri);
	} else {
		xlog(D_CALL, "%s:\n  ldapsearch -b \"%s\" -s one",
			func, base);
	}

	return ldap_search_ext_s(ld, (char *)base, LDAP_SCOPE_ONELEVEL, NULL,
					attrs, 0, NULL, NULL, NULL,
					LDAP_NO_LIMIT, response);
}

/**
 * Hide the __func__ argument at call sites
 */
#define nsdb_search_nsdb_nofilter_s(ld, base, response) \
	__nsdb_search_nsdb_nofilter_s(__func__, ld, base, response)

/**
 * Modify a FedFS-related record on an NSDB
 *
 * @param func NUL-terminated C string containing a function name
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param mods filled-in LDAP modification array
 * @param ldap_err OUT: possibly an LDAP error code
 * @return an LDAP result code
 */
static int
__nsdb_modify_nsdb_s(const char *func, LDAP *ld, const char *dn, LDAPMod **mods,
		unsigned int *ldap_err)
{
	char *uri;
	int rc;

	if (ldap_get_option(ld, LDAP_OPT_URI, &uri) == LDAP_OPT_SUCCESS) {
		xlog(D_CALL, "%s: modifying %s on %s", func, dn, uri);
		ldap_memfree(uri);
	} else
		xlog(D_CALL, "%s: modifying %s", func, dn);

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to update %s: %s",
			func, dn, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully updated %s", func, dn);
	return FEDFS_OK;
}

/**
 * Hide the __func__ argument at call sites
 */
#define nsdb_modify_nsdb_s(ld, dn, mods, ldaperr) \
	__nsdb_modify_nsdb_s(__func__, ld, dn, mods, ldaperr)

/**
 * Construct the DN of an FSN entry
 *
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID
 * @return NUL-terminated C string containing DN of an FSN entry
 *
 * Caller must free returned dn with ber_memfree(3)
 */
static char *
nsdb_construct_fsn_dn(const char *nce, const char *fsn_uuid)
{
	size_t dn_len;
	char *dn;
	int len;

	dn_len = strlen("fedfsFsnUuid=") + strlen(fsn_uuid) +
				strlen(",") + strlen(nce) + 1;
	dn = ber_memalloc(dn_len);
	if (dn == NULL) {
		xlog(D_GENERAL, "%s: No memory for DN", __func__);
		return NULL;
	}
	len = snprintf(dn, dn_len, "fedfsFsnUuid=%s,%s", fsn_uuid, nce);
	if (len < 0 || (size_t)len > dn_len) {
		xlog(D_GENERAL, "%s: DN is too long", __func__);
		return NULL;
	}

	xlog(D_CALL, "%s: Constructed dn %s", __func__, dn);
	return dn;
}

/**
 * Add a new FSN entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param ttl number of seconds fileservers may cache this FSN
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: fedfsFsnUuid="fsn_uuid","nce"
   changeType: add
   objectClass: fedfsFsn
   fedfsFsnUuid: "fsn_uuid"
   fedfsFsnTTL: "ttl"
   @endverbatim
 */
static FedFsStatus
nsdb_create_fsn_add_entry(LDAP *ld, const char *nce,
		const char *fsn_uuid, const unsigned int ttl,
		unsigned int *ldap_err)
{
	char *ocvals[2], *uuidvals[2], *ttlvals[2];
	LDAPMod *attrs[5];
	LDAPMod attr[4];
	char ttlbuf[16];
	int i, rc;
	char *dn;

	for (i = 0; i < 4; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "fedfsFsn");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFsnUuid", uuidvals, fsn_uuid);
	sprintf(ttlbuf, "%u", ttl);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFsnTTL", ttlvals, ttlbuf);

	attrs[i] = NULL;

	dn = nsdb_construct_fsn_dn(nce, fsn_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	rc = ldap_add_ext_s(ld, dn, attrs, NULL, NULL);
	ber_memfree(dn);
	if (rc != LDAP_SUCCESS) {
		xlog(L_ERROR, "Failed to add new FSN entry: %s",
				ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully added new FSN entry", __func__);
	return FEDFS_OK;
}

/**
 * Create a new FSN entry under "nce" (Chapter 5 Section 1.1)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param ttl number of seconds fileservers may cache this FSN
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_create_fsn_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		const unsigned int ttl, unsigned int *ldap_err)
{
	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || fsn_uuid == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	return nsdb_create_fsn_add_entry(host->fn_ldap, nce, fsn_uuid,
							ttl, ldap_err);
}

/**
 * Discover the DN for an FSN record
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSL UUID
 * @param dn OUT: a NUL-terminated C string containing DN of FSL record
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with ber_memfree(3).
 */
static FedFsStatus
nsdb_search_fsn_dn_s(LDAP *ld, const char *nce, const char *fsn_uuid,
		char **dn, unsigned int *ldap_err)
{
	LDAPMessage *response;
	FedFsStatus retval;
	char filter[128];
	int len, rc;

	/* watch out for buffer overflow */
	len = snprintf(filter, sizeof(filter),
			"(&(objectClass=fedfsFsn)(fedfsFsnUuid=%s))", fsn_uuid);
	if (len < 0 || (size_t)len > sizeof(filter)) {
		xlog(D_GENERAL, "%s: filter is too long", __func__);
		return FEDFS_ERR_INVAL;
	}

	rc = nsdb_search_nsdb_none_s(ld, nce, LDAP_SCOPE_ONELEVEL,
					filter, &response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: No entry for FSN UUID %s exists",
			__func__, fsn_uuid);
		return FEDFS_ERR_NSDB_NOFSN;
	default:
		xlog(D_GENERAL, "%s: LDAP search failed: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		return FEDFS_ERR_NSDB_FAULT;
	}

	rc = ldap_count_messages(ld, response);
	switch (rc) {
	case -1:
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out;
	case 1:
		xlog(D_GENERAL, "%s: No entry for FSN UUID %s exists",
			__func__, fsn_uuid);
		retval = FEDFS_ERR_NSDB_NOFSN;
		goto out;
	default:
		xlog(D_CALL, "%s: received %d messages", __func__, rc);
	}

	*dn = ldap_get_dn(ld, response);
	if (*dn == NULL) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
		xlog(D_GENERAL, "%s: Failed to parse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}
	retval = FEDFS_OK;
	xlog(D_CALL, "%s: Found '%s'", __func__, *dn);

out:
	ldap_msgfree(response);
	return retval;
}

/**
 * Delete one FSL child
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_delete_fsn_fsls_entry_s(LDAP *ld, LDAPMessage *entry,
		unsigned int *ldap_err)
{
	char *dn;
	int rc;

	dn = ldap_get_dn(ld, entry);
	if (dn == NULL) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
		xlog(D_GENERAL, "%s: Failed to parse entry: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: deleting %s", __func__, dn);
	rc = ldap_delete_ext_s(ld, dn, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete FSL entry %s: %s",
			__func__, dn, ldap_err2string(rc));
		ber_memfree(dn);
		switch (rc) {
		case LDAP_NO_SUCH_OBJECT:
			return FEDFS_ERR_NSDB_NOFSL;
		default:
			*ldap_err = rc;
			return FEDFS_ERR_NSDB_LDAP_VAL;
		}
	}

	xlog(D_GENERAL, "%s: Successfully deleted FSL entry %s",
		__func__, dn);
	ber_memfree(dn);
	return FEDFS_OK;
}

/**
 * Delete all existing FSL entries under "fsn_uuid"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of FSN entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_delete_fsn_fsls_s(LDAP *ld, const char *dn, unsigned int *ldap_err)
{
	LDAPMessage *message, *response;
	FedFsStatus retval;
	int entries, rc;

	xlog(D_CALL, "%s: searching for children of %s", __func__, dn);

again:
	rc = nsdb_search_nsdb_nofilter_s(ld, dn, &response);
	switch (rc) {
	case LDAP_SUCCESS:
	case LDAP_SIZELIMIT_EXCEEDED:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: FSL %s has no children",
			__func__, dn);
		return FEDFS_OK;
	default:
		xlog(D_GENERAL, "%s: Failed to retrieve entries for %s: %s",
			__func__, dn, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	entries = ldap_count_messages(ld, response);
	if (entries == -1) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out;
	}

	xlog(D_CALL, "%s: received %d messages", __func__, entries);

	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_parse_delete_fsn_fsls_entry_s(ld, message,
								ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, NULL, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_RESPONSE;
		}
	}

out:
	ldap_msgfree(response);
	if (rc == LDAP_SIZELIMIT_EXCEEDED && retval == FEDFS_OK)
		goto again;
	return retval;
}

/**
 * Delete an existing FSN entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of entry to remove
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: delete
   @endverbatim
 */
static FedFsStatus
nsdb_delete_fsn_entry_s(LDAP *ld, const char *dn, unsigned int *ldap_err)
{
	int rc;

	rc = ldap_delete_ext_s(ld, dn, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete FSN entry %s: %s",
			__func__, dn, ldap_err2string(rc));
		switch (rc) {
		case LDAP_NO_SUCH_OBJECT:
			return FEDFS_ERR_NSDB_NOFSN;
		case LDAP_NOT_ALLOWED_ON_NONLEAF:
			/* FSN still has children */
			/* XXX: spec provides no error code for this case */
			return FEDFS_ERR_NSDB_NOFSL;
		default:
			*ldap_err = rc;
			return FEDFS_ERR_NSDB_LDAP_VAL;
		}
	}

	xlog(D_GENERAL, "%s: Successfully deleted FSN entry %s",
		__func__, dn);
	return FEDFS_OK;
}

/**
 * Delete an existing FSN entry under "nce" (Chapter 5, section 1.2)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param leave_fsn if true, delete FSL children only
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_fsn_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		_Bool leave_fsn, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || fsn_uuid == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_search_fsn_dn_s(host->fn_ldap, nce, fsn_uuid,
						&dn, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_delete_fsn_fsls_s(host->fn_ldap, dn, ldap_err);
	if (retval != FEDFS_OK)
		goto out;

	if (!leave_fsn)
		retval = nsdb_delete_fsn_entry_s(host->fn_ldap, dn, ldap_err);

out:
	ber_memfree(dn);
	return retval;
}

/**
 * Construct the DN of an FSL entry
 *
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID
 * @param fsl_uuid NUL-terminated C string containing FSL UUID
 * @return NUL-terminated C string containing DN of an FSL entry
 *
 * Caller must free returned dn with ber_memfree(3)
 */
static char *
nsdb_construct_fsl_dn(const char *nce, const char *fsn_uuid, const char *fsl_uuid)
{
	size_t dn_len;
	char *dn;
	int len;
	dn_len = strlen("fedfsFslUuid=") + strlen(fsl_uuid) + strlen(",") +
		strlen("fedfsFsnUuid=") + strlen(fsn_uuid) + strlen(",") +
		strlen(nce) + 1;
	dn = ber_memalloc(dn_len);
	if (dn == NULL) {
		xlog(D_GENERAL, "%s: No memory for FSL DN", __func__);
		return NULL;
	}
	len = snprintf(dn, dn_len, "fedfsFslUuid=%s,fedfsFsnUuid=%s,%s",
				fsl_uuid, fsn_uuid, nce);
	if (len < 0 || (size_t)len > dn_len) {
		xlog(D_GENERAL, "%s: DN is too long", __func__);
		ber_memfree(dn);
		return NULL;
	}

	xlog(D_CALL, "%s: Constructed dn %s", __func__, dn);
	return dn;
}

/**
 * Build a UriUriA for the location information in "nfsfsl"
 *
 * @param nfsfsl an initialized struct fedfs_nfs_fsl
 * @param uri OUT: a filled-in UriUriA object
 * @return a FedFsStatus code
 *
 * Caller must free the members of the UriUriA object with
 * uriFreeUriMembersA().
 */
static FedFsStatus
nsdb_nfsfsl_to_uri(const struct fedfs_nfs_fsl *nfsfsl, UriUriA *uri)
{
	memset(uri, 0, sizeof(*uri));

	nsdb_assign_textrange(&uri->scheme, "nfs");
	nsdb_assign_textrange(&uri->hostText, nfsfsl->fn_fslhost);
	if (nfsfsl->fn_fslport != NFS_PORT && nfsfsl->fn_fslport != 0) {
		char portbuf[8];
		sprintf(portbuf, "%u", nfsfsl->fn_fslport);
		nsdb_assign_textrange(&uri->portText, portbuf);
	}

	return nsdb_path_array_to_uri_pathname(nfsfsl->fn_nfspath, uri);
}

/**
 * Construct an NFS URI for this location
 *
 * @param nfsfsl an initialized struct fedfs_nfs_fsl
 * @param nfsuri OUT: a NUL-terminated C string containing an NFS URI
 * @return a FedFsStatus code
 *
 * Caller must free "nfsuri" with free(3).
 */
static FedFsStatus
nsdb_construct_nfsuri(const struct fedfs_nfs_fsl *nfsfsl, char **nfsuri)
{
	FedFsStatus retval;
	char *result;
	int len, err;
	UriUriA uri;

	retval = nsdb_nfsfsl_to_uri(nfsfsl, &uri);
	if (retval != FEDFS_OK)
		return retval;

	retval = FEDFS_ERR_SVRFAULT;
	err = uriToStringCharsRequiredA(&uri, &len);
	if (err != URI_SUCCESS) {
		xlog(D_GENERAL, "%s: uriToStringCharsRequired failed: %d",
			__func__, err);
		goto out;
	}
	len++;

	result = (char *)calloc(len, sizeof(char));
	if (result == NULL) {
		xlog(D_GENERAL, "%s calloc failed", __func__);
		goto out;
	}

	err = uriToStringA(result, &uri, len, NULL);
	if (err != URI_SUCCESS) {
		xlog(D_GENERAL, "%s uriToStringA failed: %d",
			__func__, err);
		free(result);
		goto out;
	}

	xlog(D_CALL, "%s: NFS URI: %s", __func__, result);
	*nfsuri = result;
	retval = FEDFS_OK;

out:
	uriFreeUriMembersA(&uri);
	return retval;
}

static const char *nsdb_ldap_true	= "TRUE";
static const char *nsdb_ldap_false	= "FALSE";

/**
 * Add a new NFS FSN entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsl an initialized struct fedfs_fsl of type FEDFS_NFS_FSL
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The new entry is set up as an NFSv4.0 FSL, and can be subsequently modified
 * using the nsdb-update-fsl tool.
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: fedfsFslUuid="fsl_uuid",fedfsFsnUuid="fsn_uuid","nce"
   changeType: add
   objectClass: fedfsFsl
   objectClass: fedfsNfsFsl
   fedfsFslUuid: "fsl_uuid"
   fedfsFsnUuid: "fsn_uuid"
   fedfsNsdbName: "nsdbname"
   fedfsNsdbPort: "nsdbport"
   fedfsFslHost: "serverhost"
   fedfsFslPort: "serverport"
   fedfsFslTTL: 300
   fedfsNfsPath: "xdrpath"
   fedfsNfsMajorVer: 4
   fedfsNfsMinorVer: 0
   fedfsNfsCurrency: 0
   fedfsNfsGenFlagWritable: FALSE
   fedfsNfsGenFlagGoing: FALSE
   fedfsNfsGenFlagSplit: FALSE
   fedfsNfsTransFlagRdma: FALSE
   fedfsNfsClassSimul: 0
   fedfsNfsClassHandle: 0
   fedfsNfsClassFileid: 0
   fedfsNfsClassWritever: 0
   fedfsNfsClassChange: 0
   fedfsNfsClassReaddir: 0
   fedfsNfsReadRank: 0
   fedfsNfsReadOrder: 0
   fedfsNfsWriteRank: 0
   fedfsNfsWriteOrder: 0
   fedfsNfsVarSub: FALSE
   fedfsNfsValidFor: 300
   @endverbatim
 */
static FedFsStatus
nsdb_create_nfs_fsl_entry_s(LDAP *ld, const char *nce, struct fedfs_fsl *fsl,
		unsigned int *ldap_err)
{
	struct fedfs_nfs_fsl *nfsfsl = &fsl->fl_u.fl_nfsfsl;
	char *ocvals[3], *fsluuidvals[2], *fsnuuidvals[2];

	/* XXX: variables for encoding annotations and description
	 *	attributes would go here */

	char *nfsurivals[2], *nfsuri = NULL;
	char *currvals[2], currbuf[12];
	char *flagwvals[2], *flaggvals[2], *flagsvals[2],
		*flagrvals[2], *varsubvals[2];
	char *csvals[2], csbuf[4];
	char *chvals[2], chbuf[4];
	char *cfvals[2], cfbuf[4];
	char *cwvals[2], cwbuf[4];
	char *ccvals[2], ccbuf[4];
	char *crvals[2], crbuf[4];
	char *rrankvals[2], rrankbuf[4];
	char *rordvals[2], rordbuf[4];
	char *wrankvals[2], wrankbuf[4];
	char *wordvals[2], wordbuf[4];
	char *valforvals[2], valforbuf[12];

	FedFsStatus retval;
	LDAPMod *attrs[30];
	LDAPMod attr[29];
	int i, rc;
	char *dn;

	for (i = 0; i < 30; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++], "objectClass", ocvals, "fedfsFsl");
	ocvals[1] = "fedfsNfsFsl";
	ocvals[2] = NULL;

	nsdb_init_add_attribute(attrs[i++], "fedfsFslUuid",
				fsluuidvals, fsl->fl_fsluuid);
	nsdb_init_add_attribute(attrs[i++], "fedfsFsnUuid",
				fsnuuidvals, fsl->fl_fsnuuid);
	retval = nsdb_construct_nfsuri(nfsfsl, &nfsuri);
	if (retval != FEDFS_OK)
		goto out;
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsURI",
				 nfsurivals, nfsuri);

	sprintf(currbuf, "%d", nfsfsl->fn_currency);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsCurrency",
				currvals, currbuf);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsGenFlagWritable",
				flagwvals, nfsfsl->fn_gen_writable ?
					nsdb_ldap_true : nsdb_ldap_false);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsGenFlagGoing",
				flaggvals, nfsfsl->fn_gen_going ?
					nsdb_ldap_true : nsdb_ldap_false);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsGenFlagSplit",
				flagsvals, nfsfsl->fn_gen_split ?
					nsdb_ldap_true : nsdb_ldap_false);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsTransFlagRdma",
				flagrvals, nfsfsl->fn_trans_rdma ?
					nsdb_ldap_true : nsdb_ldap_false);
	sprintf(csbuf, "%u", nfsfsl->fn_class_simul);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassSimul",
				csvals, csbuf);
	sprintf(chbuf, "%u", nfsfsl->fn_class_handle);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassHandle",
				chvals, chbuf);
	sprintf(cfbuf, "%u", nfsfsl->fn_class_fileid);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassFileid",
				cfvals, cfbuf);
	sprintf(cwbuf, "%u", nfsfsl->fn_class_writever);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassWritever",
				cwvals, cwbuf);
	sprintf(ccbuf, "%u", nfsfsl->fn_class_change);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassChange",
				ccvals, ccbuf);
	sprintf(crbuf, "%u", nfsfsl->fn_class_readdir);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsClassReaddir",
				crvals, crbuf);
	sprintf(rrankbuf, "%u", nfsfsl->fn_readrank);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsReadRank",
				rrankvals, rrankbuf);
	sprintf(rordbuf, "%u", nfsfsl->fn_readorder);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsReadOrder",
				rordvals, rordbuf);
	sprintf(wrankbuf, "%u", nfsfsl->fn_writerank);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsWriteRank",
				wrankvals, wrankbuf);
	sprintf(wordbuf, "%u", nfsfsl->fn_writeorder);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsWriteOrder",
				wordvals, wordbuf);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsVarSub",
				varsubvals, nfsfsl->fn_varsub ?
					nsdb_ldap_true : nsdb_ldap_false);
	sprintf(valforbuf, "%u", nfsfsl->fn_validfor);
	nsdb_init_add_attribute(attrs[i++], "fedfsNfsValidFor",
				valforvals, valforbuf);

	attrs[i] = NULL;

	dn = nsdb_construct_fsl_dn(nce, fsl->fl_fsnuuid, fsl->fl_fsluuid);
	if (dn == NULL) {
		retval = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	rc = ldap_add_ext_s(ld, dn, attrs, NULL, NULL);
	ber_memfree(dn);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to add new FSL entry: %s\n",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}

	xlog(D_CALL, "%s: Successfully added new FSL entry",
		__func__);
	retval = FEDFS_OK;

out:
	free(nfsuri);
	return retval;
}

/**
 * Create new FSN records under "nce" (Chapter 5, section 1.3)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsls a list of one or more initialized struct fedfs_fsls
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If creating one of the FSLs fails, we attempt to clean up by
 * deleting the FSLs that have already been created.
 */
FedFsStatus
nsdb_create_fsls_s(nsdb_t host, const char *nce, struct fedfs_fsl *fsls,
		unsigned int *ldap_err)
{
	struct fedfs_fsl *fsl, *progress;
	FedFsStatus retval;

	if (host->fn_ldap == NULL) {
		xlog(D_GENERAL, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || fsls == NULL) {
		xlog(D_GENERAL, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	for (fsl = fsls, progress = NULL;
	     fsl != NULL;
	     progress = fsl, fsl = fsl->fl_next) {
		switch (fsl->fl_type) {
		case FEDFS_NFS_FSL:
			retval = nsdb_create_nfs_fsl_entry_s(host->fn_ldap, nce,
								fsl, ldap_err);
			break;
		default:
			xlog(D_GENERAL, "%s: Unrecognized FSL type", __func__);
			retval = FEDFS_ERR_INVAL;
		}
		if (retval != FEDFS_OK)
			goto out_delete;
	}

	return retval;

out_delete:
	if (progress != NULL) {
		for (fsl = fsls; fsl != NULL; fsl = fsl->fl_next) {
			unsigned int dummy_ldap_err;
			FedFsStatus status;
			status = nsdb_delete_fsl_s(host, nce, fsl->fl_fsluuid,
							&dummy_ldap_err);
			if (status != FEDFS_OK)
				xlog(D_GENERAL, "%s: Recovery deletion of %s failed",
					__func__, fsl->fl_fsluuid);
			if (fsl == progress)
				break;
		}
	}
	return retval;
}

/**
 * Discover the DN for an FSL record
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param dn OUT: a NUL-terminated C string containing DN of FSL record
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with ber_memfree(3).
 */
static FedFsStatus
nsdb_search_fsl_dn_s(LDAP *ld, const char *nce, const char *fsl_uuid,
		char **dn, unsigned int *ldap_err)
{
	LDAPMessage *response;
	FedFsStatus retval;
	char filter[128];
	int len, rc;

	/* watch out for buffer overflow */
	len = snprintf(filter, sizeof(filter),
			"(&(objectClass=fedfsFsl)(fedfsFslUuid=%s))", fsl_uuid);
	if (len < 0 || (size_t)len > sizeof(filter)) {
		xlog(D_GENERAL, "%s: filter is too long", __func__);
		return FEDFS_ERR_INVAL;
	}

	rc = nsdb_search_nsdb_none_s(ld, nce, LDAP_SCOPE_SUBTREE,
					filter, &response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: No entry for FSL UUID %s exists",
			__func__, fsl_uuid);
		return FEDFS_ERR_NSDB_NOFSL;
	default:
		xlog(D_GENERAL, "%s: LDAP search failed: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		return FEDFS_ERR_NSDB_FAULT;
	}

	rc = ldap_count_messages(ld, response);
	switch (rc) {
	case -1:
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out;
	case 1:
		xlog(D_GENERAL, "%s: No entry for FSN UUID %s exists",
			__func__, fsl_uuid);
		retval = FEDFS_ERR_NSDB_NOFSL;
		goto out;
	default:
		xlog(D_CALL, "%s: received %d messages", __func__, rc);
	}

	*dn = ldap_get_dn(ld, response);
	if (*dn == NULL) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
		xlog(D_GENERAL, "%s: Failed to parse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}
	xlog(D_CALL, "%s: Found %s", __func__, *dn);
	retval = FEDFS_OK;

out:
	ldap_msgfree(response);
	return retval;
}

/**
 * Delete an existing FSL entry
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of FSL record to delete
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: delete
   @endverbatim
 */
static FedFsStatus
nsdb_delete_fsl_entry_s(LDAP *ld, const char *dn, unsigned int *ldap_err)
{
	int rc;

	rc = ldap_delete_ext_s(ld, dn, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete FSL entry %s: %s",
			__func__, dn, ldap_err2string(rc));
		switch (rc) {
		case LDAP_NO_SUCH_OBJECT:
			return FEDFS_ERR_NSDB_NOFSL;
		default:
			*ldap_err = rc;
			return FEDFS_ERR_NSDB_LDAP_VAL;
		}
	}

	xlog(D_GENERAL, "%s: Successfully deleted FSL entry %s",
		__func__, dn);
	return FEDFS_OK;
}

/**
 * Delete an existing FSL entry under "nce" (Chapter 5, section 1.4)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_fsl_s(nsdb_t host, const char *nce, const char *fsl_uuid,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || fsl_uuid == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_search_fsl_dn_s(host->fn_ldap, nce, fsl_uuid,
							&dn, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_delete_fsl_entry_s(host->fn_ldap, dn, ldap_err);
	ber_memfree(dn);
	return retval;
}

/**
 * Delete an attribute from entry "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to remove
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The LDAP server will prevent removing required attributes.
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: modify
   delete: "attribute"
   @endverbatim
 */
static FedFsStatus
nsdb_update_fsl_remove_attribute_s(LDAP *ld, const char *dn,
		const char *attribute, unsigned int *ldap_err)
{
	FedFsStatus retval;

	retval = nsdb_delete_attribute_all_s(ld, dn, attribute, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	xlog(D_CALL, "%s: Successfully deleted attribute %s from entry %s",
		__func__, attribute, dn);
	return FEDFS_OK;
}

/**
 * Add a new or replace an existing attribute in "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to modify
 * @param value a NUL-terminated C string containing the new value
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The LDAP server will prevent schema violations (invalid values or
 * attribute names).  Special care is taken to handle the binary-valued
 * attribute "fedfsNfsPath".
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: modify
   replace: "attribute"
   "attribute": "value"
   @endverbatim
 */
static FedFsStatus
nsdb_update_fsl_update_attribute_s(LDAP *ld, const char *dn,
		const char *attribute, const void *value,
		unsigned int *ldap_err)
{
	struct berval newval;
	FedFsStatus retval;

	newval.bv_val = (char *)value;
	newval.bv_len = 0;
	if (value != NULL)
		newval.bv_len = (ber_len_t)strlen(value);

	retval = nsdb_modify_attribute_s(ld, dn, attribute,
						&newval, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	xlog(D_CALL, "%s: Successfully updated attribute %s for entry %s",
		__func__, attribute, dn);
	return FEDFS_OK;
}

/**
 * Update an FSL entry under "nce" (Chapter 5, section 1.5)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param attribute a NUL-terminated C string containing the name of an attribute to modify
 * @param value a NUL-terminated C string containing the new value
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If caller did not provide an NCE, discover one by querying the NSDB.
 *
 * This operation works only with single-value attributes.  If "value"
 * is NULL, the attribute is removed.
 */
FedFsStatus
nsdb_update_fsl_s(nsdb_t host, const char *nce, const char *fsl_uuid,
		const char *attribute, const void *value,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || fsl_uuid == NULL ||
	    attribute == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_search_fsl_dn_s(host->fn_ldap, nce, fsl_uuid,
							&dn, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	if (value == NULL)
		retval = nsdb_update_fsl_remove_attribute_s(host->fn_ldap,
							dn, attribute, ldap_err);
	else
		retval = nsdb_update_fsl_update_attribute_s(host->fn_ldap,
							dn, attribute,
							value, ldap_err);
	ber_memfree(dn);
	return retval;
}

/**
 * Add a new top-level o=fedfs entry
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn OUT: a NUL-terminated C string containing DN of new NCE
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with ber_memfree(3).
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: o=fedfs
   changeType: add
   objectClass: organization
   o: fedfs
   @endverbatim
 */
static FedFsStatus
nsdb_create_nce_add_top_entry(LDAP *ld, char **dn,
		unsigned int *ldap_err)
{
	char *ocvals[2], *ouvals[2];
	LDAPMod *attrs[3];
	LDAPMod attr[2];
	size_t len;
	int i, rc;
	char *nce;

	for (i = 0; i < 3; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "organization");
	nsdb_init_add_attribute(attrs[i++],
				"o", ouvals, "fedfs");
	attrs[i] = NULL;

	len = strlen("o=fedfs");
	nce = ber_memalloc(len);
	if (nce == NULL) {
		xlog(D_GENERAL, "%s: No memory for NCE DN", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	(void)sprintf(nce, "o=fedfs");

	xlog(D_CALL, "%s: Using DN '%s'", __func__, nce);
	rc = ldap_add_ext_s(ld, nce, attrs, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		ber_memfree(nce);
		xlog(D_GENERAL, "Failed to add new blank NCE: %s",
				ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	*dn = nce;
	xlog(D_CALL, "%s: Successfully added blank NCE", __func__);
	return FEDFS_OK;
}

/**
 * Add a new ou=fedfs entry under "parent"
 *
 * @param ld an initialized LDAP server descriptor
 * @param parent a NUL-terminated C string containing DN of parent
 * @param dn OUT: a NUL-terminated C string containing DN of new NCE
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with ber_memfree(3).
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: ou=fedfs,"parent"
   changeType: add
   objectClass: organizationalUnit
   ou: fedfs
   @endverbatim
 */
static FedFsStatus
nsdb_create_nce_add_entry(LDAP *ld, const char *parent, char **dn,
		unsigned int *ldap_err)
{
	char *ocvals[2], *ouvals[2];
	LDAPMod *attrs[3];
	LDAPMod attr[2];
	size_t len;
	int i, rc;
	char *nce;

	for (i = 0; i < 3; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "organizationalUnit");
	nsdb_init_add_attribute(attrs[i++],
				"ou", ouvals, "fedfs");
	attrs[i] = NULL;

	len = strlen("ou=fedfs,") + strlen(parent) + 1;
	nce = ber_memalloc(len);
	if (nce == NULL) {
		xlog(D_GENERAL, "%s: No memory for NCE DN", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	(void)sprintf(nce, "ou=fedfs,%s", parent);

	xlog(D_CALL, "%s: Using DN '%s'", __func__, nce);
	rc = ldap_add_ext_s(ld, nce, attrs, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		ber_memfree(nce);
		xlog(D_GENERAL, "%s: Failed to add new blank NCE: %s",
				__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	*dn = nce;
	xlog(D_CALL, "%s: Successfully added blank NCE", __func__);
	return FEDFS_OK;
}

/**
 * Create a blank NSDB container entry on a target NSDB server
 *
 * @param host an initialized and bound nsdb_t object
 * @param parent a NUL-terminated C string containing DN of parent
 * @param dn OUT: a NUL-terminated C string containing DN of new NCE
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with free(3).
 *
 * Note: an NCE can be any entry in an LDAP DIT.  This function creates
 * the simple case of an "ou=fedfs" entry under some other entry.
 */
FedFsStatus
nsdb_create_simple_nce_s(nsdb_t host, const char *parent,
		char **dn, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *nce;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (parent == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (parent[0] == '\0')
		retval = nsdb_create_nce_add_top_entry(host->fn_ldap,
							&nce, ldap_err);
	else
		retval = nsdb_create_nce_add_entry(host->fn_ldap, parent,
							&nce, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = FEDFS_OK;
	if (dn != NULL) {
		*dn = strdup(nce);
		if (*dn == NULL) {
			xlog(D_GENERAL, "%s: No memory for DN",
				__func__);
			retval = FEDFS_ERR_SVRFAULT;
		}
	}
	ber_memfree(nce);
	return retval;
}

/**
 * Update NSDB Container Info in a namingContext entry
 *
 * @param ld an initialized LDAP server descriptor
 * @param context a NUL-terminated C string containing DN of namingContext
 * @param nce a NUL-terminated C string containing value of new FedFsNceDN attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "context"
   changeType: modify
   add: objectClass
   objectClass: fedfsNsdbContainerInfo
   -
   add: fedfsNceDN
   fedfsNceDN: "nce"
   @endverbatim
 */
static FedFsStatus
nsdb_add_nci_attributes_s(LDAP *ld, const char *context,
		const char *nce, unsigned int *ldap_err)
{
	char *ocvals[2], *ncevals[2];
	LDAPMod *mods[3];
	LDAPMod mod[2];
	int i;

	for (i = 0; i < 2; i++)
		mods[i] = &mod[i];
	i = 0;

	nsdb_init_mod_attribute(mods[i++],
				"objectClass", ocvals, "fedfsNsdbContainerInfo");
	nsdb_init_mod_attribute(mods[i++],
				"fedfsNceDN", ncevals, nce);
	mods[i] = NULL;

	return nsdb_modify_nsdb_s(ld, context, mods, ldap_err);
}

/**
 * Update NSDB container information
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_update_nci_s(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *context;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_find_naming_context_s(host, nce, &context, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_add_nci_attributes_s(host->fn_ldap, context, nce,
						ldap_err);
	free(context);
	return retval;
}

/**
 * Remove NSDB Container Info from a namingContext object
 *
 * @param ld an initialized LDAP server descriptor
 * @param context a NUL-terminated C string containing DN of namingContext
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "context"
   changeType: modify
   delete: objectClass
   objectClass: fedfsNsdbContainerInfo
   -
   delete: fedfsNceDN
   @endverbatim
 */
static FedFsStatus
nsdb_remove_nci_attributes_s(LDAP *ld, const char *context,
		unsigned int *ldap_err)
{
	LDAPMod *mods[3];
	char *ocvals[2];
	LDAPMod mod[2];
	int i;

	for (i = 0; i < 2; i++)
		mods[i] = &mod[i];
	i = 0;

	nsdb_init_del_attribute(mods[i++],
				"objectClass", ocvals, "fedfsNsdbContainerInfo");
	nsdb_init_del_attribute(mods[i++],
				"fedfsNceDN", NULL, NULL);
	mods[i] = NULL;

	return nsdb_modify_nsdb_s(ld, context, mods, ldap_err);
}

/**
 * Remove NSDB container information
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_remove_nci_s(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *context;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_find_naming_context_s(host, nce, &context, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_remove_nci_attributes_s(host->fn_ldap, context, ldap_err);

	free(context);
	return retval;
}

/**
 * Delete one FSN child
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_delete_nsdb_fsns_entry_s(LDAP *ld, LDAPMessage *entry,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;
	int rc;

	dn = ldap_get_dn(ld, entry);
	if (dn == NULL) {
		ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &rc);
		xlog(D_GENERAL, "%s: Failed to parse entry: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	retval = nsdb_delete_fsn_fsls_s(ld, dn, ldap_err);
	if (retval != FEDFS_OK)
		goto out;

	retval = nsdb_delete_fsn_entry_s(ld, dn, ldap_err);

out:
	ber_memfree(dn);
	return retval;
}

/**
 * Remove all FSN records from an NSDB
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_delete_nsdb_fsns_s(LDAP *ld, const char *nce, unsigned int *ldap_err)
{
	LDAPMessage *message, *response;
	FedFsStatus retval;
	int entries, rc;

	xlog(D_CALL, "%s: searching for children of %s", __func__, nce);

again:
	rc = nsdb_search_nsdb_nofilter_s(ld, nce, &response);
	switch (rc) {
	case LDAP_SUCCESS:
	case LDAP_SIZELIMIT_EXCEEDED:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: NCE %s has no children",
			__func__, nce);
		return FEDFS_OK;
	default:
		xlog(D_GENERAL, "%s: Failed to retrieve entries for %s: %s",
			__func__, nce, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	entries = ldap_count_messages(ld, response);
	if (entries == -1) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out;
	}

	xlog(D_CALL, "%s: received %d messages", __func__, entries);

	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_parse_delete_nsdb_fsns_entry_s(ld, message,
								ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, NULL, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_RESPONSE;
		}
	}

out:
	ldap_msgfree(response);
	if (rc == LDAP_SIZELIMIT_EXCEEDED && retval == FEDFS_OK)
		goto again;
	return retval;
}

/**
 * Remove all FedFS records from an NSDB
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_nsdb_s(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	FedFsStatus retval;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (nce == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	retval = nsdb_remove_nci_s(host, nce, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	return nsdb_delete_nsdb_fsns_s(host->fn_ldap, nce, ldap_err);
}

/**
 * Add or replace an value from an attribute
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param attr a NUL-terminated C string containing attribute to modify
 * @param value a NUL-terminated UTF-8 C string containing new value of attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: modify
   replace: "attr"
   fedfsAnnotation: "annotation"
   @endverbatim
 */
static FedFsStatus
nsdb_attr_add_s(nsdb_t host, const char *dn, const char *attr,
		const char *value, unsigned int *ldap_err)
{
	struct berval bval;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (value == NULL)
		return FEDFS_ERR_INVAL;

	bval.bv_val = (char *)value;
	bval.bv_len = (ber_len_t)strlen(value);
	return nsdb_add_attribute_s(host->fn_ldap, dn, attr, &bval, ldap_err);
}

/**
 * Remove a value from an attribute
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param attr a NUL-terminated C string containing attribute to modify
 * @param value a NUL-terminated UTF-8 C string containing existing value of attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * "value" must exactly match a value contained by the target attribute.
 *
 * Setting "value" to NULL will remove all values of a multi-valued
 * attribute.
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: modify
   delete: "attr"
   @endverbatim
 */
static FedFsStatus
nsdb_attr_delete_s(nsdb_t host, const char *dn, const char *attr,
		const char *value, unsigned int *ldap_err)
{
	struct berval bval;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (value == NULL)
		return nsdb_delete_attribute_all_s(host->fn_ldap, dn,
							attr, ldap_err);

	bval.bv_val = (char *)value;
	bval.bv_len = (ber_len_t)strlen(value);
	return nsdb_delete_attribute_s(host->fn_ldap, dn, attr, &bval, ldap_err);
}

/**
 * Add or replace an annotation value on a fedfsAnnotation attribute
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param annotation a NUL-terminated UTF-8 C string containing new value of fedfsAnnotation attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_annotation_add_s(nsdb_t host, const char *dn,
		const char *annotation, unsigned int *ldap_err)
{
	return nsdb_attr_add_s(host, dn, "fedfsAnnotation",
				annotation, ldap_err);
}

/**
 * Remove an annotation value from a fedfsAnnotation attribute
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param annotation a NUL-terminated UTF-8 C string containing existing value of fedfsAnnotation attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The annotation must exactly match a value contained by the fedfsAnnotation
 * attribute in the target DN.
 *
 * Setting "annotation" to NULL will remove all values of the multi-valued
 * fedfsAnnotation attribute.
 */
FedFsStatus
nsdb_annotation_delete_s(nsdb_t host, const char *dn,
		const char *annotation, unsigned int *ldap_err)
{
	return nsdb_attr_delete_s(host, dn, "fedfsAnnotation",
					annotation, ldap_err);
}

/**
 * Add a value to the fedfsDescr attribute of a FedFs entry
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param description a NUL-terminated UTF-8 C string containing new value of fedfsDescr attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_description_add_s(nsdb_t host, const char *dn, const char *description,
		unsigned int *ldap_err)
{
	return nsdb_attr_add_s(host, dn, "fedfsDescr", description, ldap_err);
}

/**
 * Remove a value from the fedfsDescr attribute of a FedFs entry
 *
 * @param host an initialized and bound nsdb_t object
 * @param dn a NUL-terminated C string containing DN of entry to modify
 * @param description a NUL-terminated UTF-8 C string containing existing value of fedfsDescr attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * "description" must exactly match a value contained by the fedfsDescr
 * attribute in the target DN.
 *
 * Setting "description" to NULL will remove all values of the multi-valued
 * fedfsDescr attribute.
 */
FedFsStatus
nsdb_description_delete_s(nsdb_t host, const char *dn, const char *description,
		unsigned int *ldap_err)
{
	return nsdb_attr_delete_s(host, dn, "fedfsDescr", description, ldap_err);
}
