/**
 * @file src/libnsdb/fileserver.c
 * @brief NSDB fileserver operations (Chapter 5, section 2)
 *
 * @todo
 *	Implement asynchronous LDAP calls so LDAP replies can be handled from the RPC svc loop
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

#include "nsdb.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Default 5 second time out for LDAP requests
 */
static struct timeval nsdb_ldap_timeout = { 5, 0 };

/**
 * Free a single struct fedfs_fsl
 *
 * @param fsl pointer to fsl to free
 */
static void
nsdb_free_fsl(struct fedfs_fsl *fsl)
{
	free(fsl->fl_u.fl_nfsfsl.fn_path);
	nsdb_free_string_array(fsl->fl_description);
	nsdb_free_string_array(fsl->fl_annotations);
	free(fsl->fl_dn);
	free(fsl);
}

/**
 * Free a list of fedfs_fsl structures
 * @param fsls pointer to first element of a list of struct fedfs_fsl
 */
void
nsdb_free_fsls(struct fedfs_fsl *fsls)
{
	struct fedfs_fsl *fsl;

	while (fsls != NULL) {
		fsl = fsls;
		fsls = fsl->fl_next;
		nsdb_free_fsl(fsl);
	}
}

/**
 * Handle an LDAP referral message
 *
 * @param ld an initialized LDAP server descriptor
 * @param reference an LDAP_RES_SEARCH_REFERENCE message
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * @todo
 *	Implement LDAP referral handling
 */
static FedFsStatus
nsdb_parse_reference(LDAP *ld, LDAPMessage *reference,
		unsigned int *ldap_err)
{
	char **referrals = NULL;
	int i, rc;

	xlog(L_ERROR, "%s: Received referral while retrieving "
				"an NCE prefix", __func__);

	rc = ldap_parse_reference(ld, reference, &referrals, NULL, 0);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse result: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	if (referrals != NULL) {
		for (i = 0; referrals[i] != NULL; i++)
			xlog(L_ERROR, "%s: Search reference: %s\n",
				__func__, referrals[i]);
		ber_memvfree((void **)referrals);
	}

	/* Haven't implemented LDAP referral support yet */
	return FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED;
}

/**
 * Handle an LDAP search result message
 *
 * @param ld an initialized LDAP server descriptor
 * @param result an LDAP_RES_SEARCH_RESULT message
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_result(LDAP *ld, LDAPMessage *result, unsigned int *ldap_err)
{
	char *matched_msg, *error_msg;
	int rc, result_code;

	matched_msg = error_msg = NULL;
	rc = ldap_parse_result(ld, result, &result_code,
					&matched_msg, &error_msg, NULL, NULL, 0);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse result: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	if (result_code != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Search result: %s",
			__func__, ldap_err2string(result_code));
		if ((error_msg != NULL) && (*error_msg != '\0'))
			xlog(D_GENERAL, "%s: Extended error: %s",
				__func__, error_msg);
		if ((matched_msg != NULL) && (*matched_msg != '\0'))
			xlog(D_GENERAL, "%s: Matched DN: %s",
				__func__, matched_msg);
		*ldap_err = result_code;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_GENERAL, "%s: Search completed successfully", __func__);
	return FEDFS_OK;
}

/**
 * Construct DN for an LDAP server's NSDB container
 *
 * @param ld an initialized LDAP descriptor
 * @param message an LDAP_RES_SEARCH_ENTRY message
 * @param nceprefix a NUL-terminated C string containing an NCE prefix received from server
 * @param tmp OUT: pointer to a NUL-terminated C string containing resulting DN; caller must free with free(3)
 * @return true if successful
 */
static _Bool
nsdb_construct_nce_dn(LDAP *ld, LDAPMessage *message,
		const char *nceprefix, char **tmp)
{
	char *dn, *result;
	size_t size;
	int len;

	dn = ldap_get_dn(ld, message);
	if (dn == NULL)
		return false;

	/* If the fedfsNcePrefix value is empty,
	 * just return the entry's DN */
	if (*nceprefix == '\0') {
		*tmp = dn;
		return true;
	}

	size = strlen(nceprefix) + strlen(",") + strlen(dn) + 1;
	result = malloc(size);
	if (result == NULL) {
		free(dn);
		return false;
	}

	len = snprintf(result, size, "%s,%s", nceprefix, dn);
	if (len < 0 || (size_t)len > size) {
		free(dn);
		free(result);
		return false;
	}

	free(dn);
	*tmp = result;
	return true;
}

/**
 * Parse NCE prefix attribute
 *
 * @param ld an initialized LDAP descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param dn OUT: pointer to a NUL-terminated C string containing resulting DN
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_nceprefix_attribute(LDAP *ld, LDAPMessage *entry, char *attr,
		char **dn)
{
	struct berval **values;
	FedFsStatus retval;
	char *tmp;

	xlog(D_CALL, "%s: parsing attribute %s", __func__, attr);
	if (strcasecmp(attr, "fedfsNcePrefix") != 0)
		return FEDFS_OK;

	values = ldap_get_values_len(ld, entry, attr);
	if (values == NULL) {
		xlog(D_GENERAL, "%s: No values found for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}
	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out_free;
	}

	if (!nsdb_construct_nce_dn(ld, entry, values[0]->bv_val, &tmp)) {
		retval = FEDFS_ERR_SVRFAULT;
		goto out_free;
	}

	retval = FEDFS_OK;
	*dn = tmp;

out_free:
	ldap_value_free_len(values);
	return FEDFS_OK;
}

/**
 * Construct DN for an LDAP server's NSDB container
 *
 * @param ld an initialized LDAP descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param dn OUT: pointer to a NUL-terminated C string containing resulting DN
 * @return a FedFsStatus code
 *
 * Caller must free "dn" with free(3)
 */
static FedFsStatus
nsdb_parse_nceprefix_entry(LDAP *ld, LDAPMessage *entry, char **dn)
{
	BerElement *field = NULL;
	FedFsStatus retval;
	char *attr;

	for (attr = ldap_first_attribute(ld, entry, &field), retval = FEDFS_OK;
	     attr != NULL && retval == FEDFS_OK;
	     attr = ldap_next_attribute(ld, entry, field)) {
		retval = nsdb_parse_nceprefix_attribute(ld, entry,
							attr, dn);
		ldap_memfree(attr);
	}

	if (field != NULL)
		ber_free(field, 0);
	return retval;
}

/**
 * Get the naming context's NSDB DN, if it has one
 *
 * @param host an initialized and bound nsdb_t object
 * @param naming_context NUL-terminated C string containing one naming context
 * @param dn OUT: pointer to a NUL-terminated C string containing full DN of NSDB container; caller must free with free(3)
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * ldapsearch equivalent:
 *
 * @verbatim

   ldapsearch -b "naming_context" -s base objectClass=* fedfsNcePrefix
   @endverbatim
 *
 * The full DN for the NSDB container is constructed and returned in "dn."
 * That is, if the requested naming context is "dc=example,dc=com" and
 * the fedfsNcePrefix attribute in the server's "dc=example,dc=com"
 * entry contains "o=fedfs", then the string that is returned in "dn"
 * is "dc=example,dc=com,o=fedfs".
 */
FedFsStatus
nsdb_get_nceprefix_s(nsdb_t host, const char *naming_context, char **dn,
		unsigned int *ldap_err)
{
	LDAPMessage *response, *message;
	char *attrs[2], *tmp = NULL;
	LDAP *ld = host->fn_ldap;
	FedFsStatus retval;
	int rc;

	attrs[0] = "fedfsNcePrefix";
	attrs[1] = NULL;
	rc = ldap_search_ext_s(ld, naming_context, LDAP_SCOPE_BASE,
				"objectClass=*", attrs, 0, NULL,
				NULL, &nsdb_ldap_timeout,
				LDAP_NO_LIMIT, &response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: %s is not an NSDB container entry",
			__func__, naming_context);
		return FEDFS_ERR_NSDB_NONCE;
	default:
		xlog(D_GENERAL, "%s: Failed to retrieve naming_context "
			"entry %s: %s", __func__, naming_context,
			ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response\n", __func__);
		return FEDFS_ERR_NSDB_FAULT;
	}

	rc = ldap_count_messages(ld, response);
	switch (rc) {
	case -1:
		xlog(D_GENERAL, "%s: Empty LDAP response\n", __func__);
		retval = FEDFS_ERR_NSDB_FAULT;
		goto out;
	case 1:
		xlog(L_ERROR, "Naming context entry %s is inaccessible",
			naming_context);
		retval = FEDFS_ERR_NSDB_NONCE;
		goto out;
	default:
		xlog(D_CALL, "%s: received %d messages", __func__, rc);
		break;
	}

	tmp = NULL;
	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_parse_nceprefix_entry(ld, message, &tmp);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			retval = nsdb_parse_reference(ld, message, ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_FAULT;
		}
	}

	if (retval == FEDFS_OK) {
		if (tmp == NULL) {
			xlog(D_GENERAL, "%s: %s is not an NCE",
				__func__, naming_context);
			retval = FEDFS_ERR_NSDB_NONCE;
		} else {
			xlog(D_CALL, "%s: %s contains NCE prefix %s",
				__func__, naming_context, tmp);
			*dn = tmp;
		}
	} else
		free(tmp);

out:
	ldap_msgfree(response);
	return retval;
}

/**
 * Parse namingContext attribute
 *
 * @param ld an initialized LDAP descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param contexts OUT: pointer to an array of NUL-terminated C strings
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_naming_contexts_attribute(LDAP *ld, LDAPMessage *entry, char *attr,
		char ***contexts)
{
	struct berval **values;
	FedFsStatus retval;

	values = ldap_get_values_len(ld, entry, attr);
	if (values == NULL) {
		xlog(D_GENERAL, "%s: No values found for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	/* XXX: why check the attr name again? */
	if (strcasecmp(attr, "namingContexts") == 0)
		retval = nsdb_parse_multivalue_str(attr, values,
				contexts);
	else {
		xlog(L_ERROR, "%s: Unrecognized attribute: %s",
			__func__, attr);
		retval = FEDFS_ERR_NSDB_RESPONSE;
	}

	ldap_value_free_len(values);
	return retval;
}

/**
 * Extract list of LDAP server's naming contexts from search results
 *
 * @param ld an initialized LDAP descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param contexts OUT: pointer to an array of NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * Caller must free "contexts" with nsdb_free_string_array()
 */
static FedFsStatus
nsdb_parse_naming_contexts_entry(LDAP *ld, LDAPMessage *entry,
		char ***contexts)
{
	BerElement *field = NULL;
	FedFsStatus retval;
	char *attr;

	for (attr = ldap_first_attribute(ld, entry, &field), retval = FEDFS_OK;
	     attr != NULL && retval == FEDFS_OK;
	     attr = ldap_next_attribute(ld, entry, field)) {
		if (strcasecmp(attr, "namingContexts") == 0) {
			retval = nsdb_parse_naming_contexts_attribute(ld, entry,
								attr, contexts);
			ldap_memfree(attr);
			break;
		}
		ldap_memfree(attr);
	}

	if (field != NULL)
		ber_free(field, 0);
	return retval;
}

/**
 * Retrieve namingContexts from an LDAP server's root DSE
 *
 * @param host an initialized and bound nsdb_t object
 * @param contexts OUT: pointer to an array of NUL-terminated C strings
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free "contexts" with nsdb_free_string_array()
 *
 * ldapsearch equivalent:
 *
 * @verbatim

   ldapsearch -b "" -s base objectClass=* namingContexts
   @endverbatim
 */
FedFsStatus
nsdb_get_naming_contexts_s(nsdb_t host, char ***contexts,
		unsigned int *ldap_err)
{
	LDAPMessage *response, *message;
	LDAP *ld = host->fn_ldap;
	char *attrs[2], **tmp;
	FedFsStatus retval;
	int rc;

	attrs[0] = "namingContexts";
	attrs[1] = NULL;
	rc = ldap_search_ext_s(ld, "", LDAP_SCOPE_BASE,
				"objectClass=*", attrs, 0, NULL,
				NULL, &nsdb_ldap_timeout,
				LDAP_NO_LIMIT, &response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(L_ERROR, "No root DSE entry found");
		return FEDFS_ERR_NSDB_FAULT;
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
		retval = FEDFS_ERR_NSDB_FAULT;
		goto out;
	case 1:
		xlog(L_ERROR, "Root DSE entry is inaccessible");
		retval = FEDFS_ERR_NSDB_FAULT;
		goto out;
	default:
		xlog(D_CALL, "%s: received %d messages", __func__, rc);
		break;
	}

	tmp = NULL;
	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_parse_naming_contexts_entry(ld,
							message, &tmp);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			retval = nsdb_parse_reference(ld,
							message, ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_FAULT;
		}
	}

	if (retval == FEDFS_OK) {
		xlog(D_CALL, "%s: returning context list",
			__func__);
		*contexts = tmp;
	} else
		nsdb_free_string_array(tmp);

out:
	ldap_msgfree(response);
	return retval;
}

/**
 * Parse objectClass attribute of a fedfsFsl
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values array of values for this attribute
 * @param fsl OUT: fedfs_fsl structure to fill in
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_resolve_fsn_parse_objectclass(char *attr, struct berval **values,
		struct fedfs_fsl *fsl)
{
	char **objectclass;
	FedFsStatus retval;
	int i;

	retval = nsdb_parse_multivalue_str(attr, values, &objectclass);
	if (retval != FEDFS_OK)
		return retval;

	for (i = 0; objectclass[i] != NULL; i++)
		if (strcasecmp(objectclass[i], "fedfsNfsFsl") == 0)
			fsl->fl_type = FEDFS_NFS_FSL;

	nsdb_free_string_array(objectclass);

	return FEDFS_OK;
}

/**
 * Parse fedfsAnnotation attribute of a fedfsFsl
 *
 * @param values array of values for this attribute
 * @param fsl OUT: fedfs_fsl structure to fill in
 * @return a FedFsStatus code
 *
 * Place the keywords in fsl->fl_anno_keys and the values in
 * fsl->fl_anno_vals.
 */
static FedFsStatus
nsdb_parse_annotations(struct berval **values, struct fedfs_fsl *fsl)
{
	char **tmp_annos;
	int i, count;

	count = ldap_count_values_len(values);
	tmp_annos = calloc(count + 1, sizeof(char *));
	if (tmp_annos == NULL) {
		xlog(D_GENERAL, "%s: no memory for annotations array",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; i < count; i++) {
		tmp_annos[i] = strndup(values[i]->bv_val, values[i]->bv_len);
		if (tmp_annos[i] == NULL) {
			xlog(D_GENERAL, "%s: no memory for annotation",
				__func__);
			nsdb_free_string_array(tmp_annos);
			return FEDFS_ERR_SVRFAULT;
		}

		xlog(D_GENERAL, "%s: fedfsAnnotation[%d]: %s",
			__func__, i, tmp_annos[i]);
	}
	tmp_annos[i] = NULL;

	fsl->fl_annotations = tmp_annos;
	return FEDFS_OK;
}

/**
 * Parse the values of each attribute in a fedfsFsl object
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry an LDAP search result message
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param fsl OUT: fedfs_fsl structure to fill in
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_resolve_fsn_parse_attribute(LDAP *ld, LDAPMessage *entry, char *attr,
		struct fedfs_fsl *fsl)
{
	struct fedfs_nfs_fsl *nfsl = &fsl->fl_u.fl_nfsfsl;
	struct berval **values;
	FedFsStatus retval;

	values = ldap_get_values_len(ld, entry, attr);
	if (values == NULL) {
		xlog(D_GENERAL, "%s: No values found for attribute %s",
			__func__, attr);
		return FEDFS_OK;
	}

	if (strcasecmp(attr, "objectClass") == 0)
		retval = nsdb_resolve_fsn_parse_objectclass(attr, values, fsl);
	else if (strcasecmp(attr, "fedfsFslUuid") == 0)
		retval = nsdb_parse_singlevalue_str(attr, values,
				fsl->fl_fsluuid, sizeof(fsl->fl_fsluuid));
	else if (strcasecmp(attr, "fedfsFsnUuid") == 0)
		retval = nsdb_parse_singlevalue_str(attr, values,
				fsl->fl_fsnuuid, sizeof(fsl->fl_fsnuuid));
	else if (strcasecmp(attr, "fedfsNsdbName") == 0)
		retval = nsdb_parse_singlevalue_str(attr, values,
				fsl->fl_nsdbname, sizeof(fsl->fl_nsdbname));
	else if (strcasecmp(attr, "fedfsNsdbPort") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&fsl->fl_nsdbport);
	else if (strcasecmp(attr, "fedfsFslHost") == 0)
		retval = nsdb_parse_singlevalue_str(attr, values,
				fsl->fl_fslhost, sizeof(fsl->fl_nsdbname));
	else if (strcasecmp(attr, "fedfsFslPort") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&fsl->fl_fslport);
	else if (strcasecmp(attr, "fedfsFslTTL") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&fsl->fl_fslttl);
	else if (strcasecmp(attr, "fedfsAnnotation") == 0)
		retval = nsdb_parse_annotations(values, fsl);
	else if (strcasecmp(attr, "fedfsDescr") == 0)
		retval = nsdb_parse_multivalue_str(attr, values,
				&fsl->fl_description);

	/* fedfsNfsFsl attributes */

	else if (strcasecmp(attr, "fedfsNfsPath") == 0)
		retval = nsdb_parse_singlevalue_xdrpath(attr, values,
					&nfsl->fn_path);
	else if (strcasecmp(attr, "fedfsNfsMajorVer") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_majorver);
	else if (strcasecmp(attr, "fedfsNfsMinorVer") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_minorver);
	else if (strcasecmp(attr, "fedfsNfsCurrency") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_currency);
	else if (strcasecmp(attr, "fedfsNfsGenFlagWritable") == 0)
		retval = nsdb_parse_singlevalue_bool(attr, values,
				&nfsl->fn_gen_writable);
	else if (strcasecmp(attr, "fedfsNfsGenFlagGoing") == 0)
		retval = nsdb_parse_singlevalue_bool(attr, values,
				&nfsl->fn_gen_going);
	else if (strcasecmp(attr, "fedfsNfsGenFlagSplit") == 0)
		retval = nsdb_parse_singlevalue_bool(attr, values,
				&nfsl->fn_gen_split);
	else if (strcasecmp(attr, "fedfsNfsTransFlagRdma") == 0)
		retval = nsdb_parse_singlevalue_bool(attr, values,
				&nfsl->fn_trans_rdma);
	else if (strcasecmp(attr, "fedfsNfsClassSimul") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_simul);
	else if (strcasecmp(attr, "fedfsNfsClassHandle") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_handle);
	else if (strcasecmp(attr, "fedfsNfsClassFileid") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_fileid);
	else if (strcasecmp(attr, "fedfsNfsClassWritever") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_writever);
	else if (strcasecmp(attr, "fedfsNfsClassChange") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_change);
	else if (strcasecmp(attr, "fedfsNfsClassReaddir") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_class_readdir);
	else if (strcasecmp(attr, "fedfsNfsReadRank") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_readrank);
	else if (strcasecmp(attr, "fedfsNfsReadOrder") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_readorder);
	else if (strcasecmp(attr, "fedfsNfsWriteRank") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_readrank);
	else if (strcasecmp(attr, "fedfsNfsWriteOrder") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_readorder);
	else if (strcasecmp(attr, "fedfsNfsVarSub") == 0)
		retval = nsdb_parse_singlevalue_bool(attr, values,
				&nfsl->fn_varsub);
	else if (strcasecmp(attr, "fedfsNfsValidFor") == 0)
		retval = nsdb_parse_singlevalue_int(attr, values,
				&nfsl->fn_validfor);

	else {
		/* Ignore anything we don't recognize */
		xlog(D_GENERAL, "%s: Unrecognized attribute: %s",
			__func__, attr);
		retval = FEDFS_OK;
	}

	ldap_value_free_len(values);
	return retval;
}

/**
 * Construct a struct fedfs_fsl based on the returned "entry"
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param fsls OUT: a list of fedfs_fsl structures
 * @return a FedFsStatus code
 *
 * On success, the new fsl is inserted at the head of the "fsls" list.
 */
static FedFsStatus
nsdb_resolve_fsn_parse_entry(LDAP *ld, LDAPMessage *entry,
		struct fedfs_fsl **fsls)
{
	BerElement *field = NULL;
	struct fedfs_fsl *new;
	FedFsStatus retval;
	char *attr, *dn;

	xlog(D_CALL, "%s: parsing entry", __func__);

	new = calloc(1, sizeof(struct fedfs_fsl));
	if (new == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate new fsl", __func__);
		return FEDFS_ERR_SVRFAULT;
	}
	new->fl_type = (FedFsFslType) -1;

	dn = ldap_get_dn(ld, entry);
	if (dn != NULL ) {
		new->fl_dn = strdup(dn);
		ldap_memfree(dn);
	}

	for (attr = ldap_first_attribute(ld, entry, &field), retval = FEDFS_OK;
	     attr != NULL && retval == FEDFS_OK;
	     attr = ldap_next_attribute(ld, entry, field)) {
		retval = nsdb_resolve_fsn_parse_attribute(ld, entry, attr, new);
		ldap_memfree(attr);
	}

	if (field != NULL)
		ber_free(field, 0);

	if (retval != FEDFS_OK) {
		xlog(D_CALL, "%s: parsing failed: %s",
			__func__, nsdb_display_fedfsstatus(retval));
		return retval;
	}

	new->fl_next = *fsls;
	*fsls = new;
	xlog(D_CALL, "%s: parsing complete", __func__);
	return FEDFS_OK;
}

/**
 * Retrieve and display the FSL entries associated with an FSN UUID
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsls OUT: a list of fedfs_fsl structures
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * ldapsearch equivalent:
 *
 * @verbatim

   ldapsearch -b fedfsFsnUuid="fsn_uuid","nce" -s one objectClass=fedfsFsl
   @endverbatim
 */
static FedFsStatus
nsdb_resolve_fsn_find_entry_s(LDAP *ld, const char *nce, const char *fsn_uuid,
		struct fedfs_fsl **fsls, unsigned int *ldap_err)
{
	LDAPMessage *response, *message;
	FedFsStatus retval;
	struct fedfs_fsl *tmp;
	char *dn;
	int rc;

	dn = nsdb_construct_fsn_dn(nce, fsn_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	rc = ldap_search_ext_s(ld, dn, LDAP_SCOPE_ONELEVEL,
				"objectClass=fedfsFsl", NULL, 0, NULL, NULL,
				NULL, LDAP_NO_LIMIT, &response);
	free(dn);
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
		ldap_msgfree(response);
		return FEDFS_ERR_NSDB_FAULT;
	case 1:
		xlog(D_CALL, "%s: No FSL entries for FSN UUID %s",
			__func__, fsn_uuid);
		ldap_msgfree(response);
		return FEDFS_ERR_NSDB_NOFSL;
	default:
		xlog(D_CALL, "%s: Received %d messages", __func__, rc);
		break;
	}

	tmp = NULL;
	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_resolve_fsn_parse_entry(ld,
							message, &tmp);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			retval = nsdb_parse_reference(ld, message, ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_FAULT;
		}
	}
	ldap_msgfree(response);

	if (retval == FEDFS_OK) {
		xlog(D_CALL, "%s: returning fsls", __func__);
		*fsls = tmp;
	} else
		nsdb_free_fsls(tmp);
	return retval;
}

/**
 * Resolve an FSN UUID under "nce" (Chapter 5, section 2.2)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsls OUT: a list of fedfs_fsl structures
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If caller did not provide an NCE, discover one by querying the NSDB.
 *
 * Caller must free the list returned in "fsls" using nsdb_free_fsls().
 */
FedFsStatus
nsdb_resolve_fsn_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		struct fedfs_fsl **fsls, unsigned int *ldap_err)
{
	char **contexts, **nce_list;
	FedFsStatus retval;
	int i, j;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce != NULL)
		return nsdb_resolve_fsn_find_entry_s(host->fn_ldap, nce,
						fsn_uuid, fsls, ldap_err);

	/*
	 * Caller did not provide an nce.  Generate a list
	 * of the server's NSDB container entries.
	 */
	retval = nsdb_get_naming_contexts_s(host, &contexts, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	for (i = 0; contexts[i] != NULL; i++);
	nce_list = calloc(i + 1, sizeof(char *));
	if (nce_list == NULL) {
		retval = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	/*
	 * Query only naming contexts that have an NCE prefix
	 */
	for (i = 0, j = 0; contexts[i] != NULL; i++) {
		retval = nsdb_get_nceprefix_s(host, contexts[i],
						&nce_list[j], ldap_err);
		if (retval == FEDFS_OK)
			j++;
	}
	if (j == 0)
		goto out;

	for (j = 0; nce_list[j] != NULL; j++) {
		retval = nsdb_resolve_fsn_find_entry_s(host->fn_ldap,
							nce_list[j], fsn_uuid,
							fsls, ldap_err);
		if (retval == FEDFS_OK)
			break;
	}

out:
	nsdb_free_string_array(nce_list);
	nsdb_free_string_array(contexts);
	return retval;
}

/**
 * Parse fedfsFsn attributes
 *
 * @param ld an initialized LDAP descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param fsns OUT: pointer to an array of NUL-terminated C strings containing FSN UUIDs
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_parse_fsn_attribute(LDAP *ld, LDAPMessage *entry, char *attr, char ***fsns)
{
	char fsn_uuid[FEDFS_UUID_STRLEN];
	struct berval **values;
	char **tmp = *fsns;
	FedFsStatus retval;
	int i;

	xlog(D_CALL, "%s: parsing attribute %s", __func__, attr);

	if (strcasecmp(attr, "fedfsFsnUuid") != 0)
		return FEDFS_OK;

	values = ldap_get_values_len(ld, entry, attr);
	if (values == NULL) {
		xlog(D_GENERAL, "%s: No values found for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}
	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		retval = FEDFS_ERR_NSDB_RESPONSE;
		goto out_free;
	}

	retval = nsdb_parse_singlevalue_str(attr, values,
						fsn_uuid, sizeof(fsn_uuid));
	if (retval != FEDFS_OK)
		goto out_free;

	retval = FEDFS_OK;
	for (i = 0; tmp[i] != NULL; i++) ;
	tmp[i] = strdup(fsn_uuid);
	if (tmp[i] == NULL)
		retval = FEDFS_ERR_SVRFAULT;

out_free:
	ldap_value_free_len(values);
	return retval;
}

/**
 * Populate the fsns array with the FSN UUID in given LDAP message
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry an LDAP_RES_SEARCH_ENTRY message
 * @param fsns OUT: pointer to an array of NUL-terminated C strings containing FSN UUIDs
 * @return a FedFsStatus code
 *
 * Each LDAP message contains one FSN entry.  Mine the entry
 * for the FSN UUID, and plant it at the end of the fsns array.
 */
static FedFsStatus
nsdb_parse_fsn_entry(LDAP *ld, LDAPMessage *entry, char ***fsns)
{
	BerElement *field = NULL;
	FedFsStatus retval;
	char *attr;

	for (attr = ldap_first_attribute(ld, entry, &field), retval = FEDFS_OK;
	     attr != NULL && retval == FEDFS_OK;
	     attr = ldap_next_attribute(ld, entry, field)) {
		retval = nsdb_parse_fsn_attribute(ld, entry, attr, fsns);
		ldap_memfree(attr);
	}

	if (field != NULL)
		ber_free(field, 0);
	return retval;
}

/**
 * Retrieve and display the FSN entries associated with an NSDB container
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing the DN of the NSDB container
 * @param fsns OUT: pointer to an array of NUL-terminated C strings containing FSN UUIDs
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * ldapsearch equivalent:
 *
 * @verbatim

   ldapsearch -b "nce" objectClass=fedfsFsn
   @endverbatim
 */
static FedFsStatus
nsdb_list_find_entries_s(LDAP *ld, const char *nce, char ***fsns,
		unsigned int *ldap_err)
{
	LDAPMessage *response, *message;
	FedFsStatus retval;
	char **tmp;
	int rc;

	rc = ldap_search_ext_s(ld, nce, LDAP_SCOPE_SUBTREE,
				"objectClass=fedfsFsn", NULL, 0, NULL,
				NULL, NULL, LDAP_NO_LIMIT, &response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: No entry for %s exists",
			__func__, nce);
		return FEDFS_ERR_NSDB_NOFSN;
	default:
		xlog(D_GENERAL, "%s: LDAP search failed: %s\n",
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
		ldap_msgfree(response);
		return FEDFS_ERR_NSDB_FAULT;
	case 1:
		xlog(D_CALL, "%s: No FSN entries under %s",
			__func__, nce);
		ldap_msgfree(response);
		return FEDFS_ERR_NSDB_NOFSN;
	default:
		xlog(D_CALL, "%s: Received %d messages",
			__func__, rc);
		break;
	}

	/* Assume one FSN per LDAP message, minus the RESULT message,
	 * plus the NULL pointer on the end of the array */
	retval = FEDFS_ERR_SVRFAULT;
	tmp = calloc(rc, sizeof(char *));
	if (tmp == NULL)
		goto out;
	tmp[0] = NULL;

	retval = FEDFS_OK;
	for (message = ldap_first_message(ld, response);
	     message != NULL && retval == FEDFS_OK;
	     message = ldap_next_message(ld, message)) {
		switch (ldap_msgtype(message)) {
		case LDAP_RES_SEARCH_ENTRY:
			retval = nsdb_parse_fsn_entry(ld, message, &tmp);
			break;
		case LDAP_RES_SEARCH_REFERENCE:
			retval = nsdb_parse_reference(ld, message, ldap_err);
			break;
		case LDAP_RES_SEARCH_RESULT:
			retval = nsdb_parse_result(ld, message, ldap_err);
			break;
		default:
			xlog(L_ERROR, "%s: Unrecognized LDAP message type",
				__func__);
			retval = FEDFS_ERR_NSDB_FAULT;
		}
	}

	if (retval == FEDFS_OK) {
		xlog(D_CALL, "%s: returning fsn list", __func__);
		*fsns = tmp;
	} else
		nsdb_free_string_array(tmp);

out:
	ldap_msgfree(response);
	return retval;
}

/**
 * Enumerate all FSN entries under "nce"
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsns OUT: pointer to an array of NUL-terminated C strings containing FSN UUIDs
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If caller did not provide an NCE, discover one by querying the NSDB.
 */
FedFsStatus
nsdb_list_s(nsdb_t host, const char *nce, char ***fsns, unsigned int *ldap_err)
{
	char **contexts, **nce_list;
	FedFsStatus retval;
	int i, j;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce != NULL)
		return nsdb_list_find_entries_s(host->fn_ldap, nce,
							fsns, ldap_err);

	/*
	 * Caller did not provide an nce.  Discover the server's NSDB
	 * container entry.  List entries in all discovered NSDB
	 * containers.
	 */
	retval = nsdb_get_naming_contexts_s(host, &contexts, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	for (i = 0; contexts[i] != NULL; i++);
	nce_list = calloc(i + 1, sizeof(char *));
	if (nce_list == NULL) {
		retval = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	/*
	 * List only naming contexts that have an NCE prefix
	 */
	for (i = 0, j = 0; contexts[i] != NULL; i++) {
		retval = nsdb_get_nceprefix_s(host, contexts[i],
						&nce_list[j], ldap_err);
		if (retval == FEDFS_OK)
			j++;
	}
	if (j == 0)
		goto out;

	for (j = 0; nce_list[j] != NULL; j++)
		nsdb_list_find_entries_s(host->fn_ldap, nce_list[j],
						fsns, ldap_err);
	retval = FEDFS_OK;

out:
	nsdb_free_string_array(nce_list);
	nsdb_free_string_array(contexts);
	return retval;
}
