/**
 * @file src/libnsdb/ldap.c
 * @brief Contact a remote LDAP service.
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
#include <termios.h>
#include <unistd.h>
#include <netdb.h>

#include "nsdb.h"
#include "junction.h"
#include "nsdb-internal.h"
#include "path.h"
#include "xlog.h"

/**
 * Read a password from stdin, disabling character echo
 *
 * @return a NUL-terminated C string containing the typed-in password.  Caller must free the string with free(3)
 */
static char *
nsdb_get_pw(void)
{
	struct termios saved, tmp;
	static char buf[ /* XXX: arbitrary */ 128];
	size_t i;
	int c;

	fprintf(stdout, "Enter NSDB password: ");
	fflush(stdout);
	setvbuf(stdout, NULL, _IONBF ,0);

	tcgetattr(0, &saved);
	tmp = saved;
	tmp.c_lflag &= ~(ISIG|ICANON|ECHO);
	tmp.c_cc[VMIN] = 1;
	tmp.c_cc[VTIME] = 2;
	tcsetattr(0, TCSANOW, &tmp);

	i = 0;
	while (true) {
		c = getchar();
		if (c == EOF || c == '\n' || c == '\r')
			break;
		if (i < (sizeof(buf) - 1))
			buf[i++] = c;
	}
	buf[i] = '\0';

	tcsetattr(0, TCSANOW, &saved);
	fprintf(stdout, "\n");
	fflush(stdout);

	if (c == EOF)
		return NULL;
	return buf;
}

/**
 * Set up LDAPMod structure for an LDAP ADD operation
 *
 * @param mod pointer to struct to initialize
 * @param attribute NUL-terminated C string containing attribute name
 * @param bv pointer to array of C strings used for BER value
 * @param value NUL-terminated C string containing attribute value
 */
void
nsdb_init_add_attribute(LDAPMod *mod, const char *attribute,
		char **bv, const char *value)
{
	bv[0] = (char *)value;
	bv[1] = NULL;

	mod->mod_op = 0;
	mod->mod_type = (char *)attribute;
	mod->mod_values = bv;
}

/**
 * Set up LDAPMod structure for an LDAP MODIFY operation
 *
 * @param mod pointer to struct to initialize
 * @param attribute NUL-terminated C string containing attribute name
 * @param bv pointer to array of C strings used for BER value
 * @param value NUL-terminated C string containing attribute value
 */
void
nsdb_init_mod_attribute(LDAPMod *mod, const char *attribute,
		char **bv, const char *value)
{
	bv[0] = (char *)value;
	bv[1] = NULL;

	mod->mod_op = LDAP_MOD_ADD;
	mod->mod_type = (char *)attribute;
	mod->mod_values = bv;
}

/**
 * Free array of NUL-terminated C strings
 *
 * @param strings array of char * to be released
 *
 * @note
 *	With OpenLDAP, could use ber_memvfree() instead
 */
void
nsdb_free_string_array(char **strings)
{
	int i;

	if (strings == NULL)
		return;
	for (i = 0; strings[i] != NULL; i++)
		free(strings[i]);
	free(strings);
}

/**
 * Parse the value of a single-value boolean attribute
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values a NULL-terminated array of pointers to bervals
 * @param result OUT: boolean into which to copy the value
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_parse_singlevalue_bool(char *attr, struct berval **values, _Bool *result)
{
	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	/* XXX: Better value type checking, please */
	if (atoi(values[0]->bv_val)) {
		xlog(D_CALL, "%s: Attribute %s contains TRUE", __func__, attr);
		*result = true;
	} else {
		xlog(D_CALL, "%s: Attribute %s contains FALSE", __func__, attr);
		*result = false;
	}
	return FEDFS_OK;
}

/**
 * Parse the value of a single-value integer attribute
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values a NULL-terminated array of pointers to bervals
 * @param result OUT: integer into which to copy the value
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_parse_singlevalue_int(char *attr, struct berval **values, int *result)
{
	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	/* XXX: Better value type checking, please */
	*result = atoi(values[0]->bv_val);
	xlog(D_CALL, "%s: Attribute %s contains value %d",
		__func__, attr, *result);
	return FEDFS_OK;
}

/**
 * Parse the value of a single-value string attribute
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values a NULL-terminated array of pointers to bervals
 * @param result OUT: buffer into which to copy the attribute
 * @param len size, in bytes, of "result"
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_parse_singlevalue_str(char *attr, struct berval **values,
		char *result, const size_t len)
{
	if (len < strlen(values[0]->bv_val)) {
		xlog(L_ERROR, "%s: Value of attribute %s is too large",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}
	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	strncpy(result, values[0]->bv_val, len);
	xlog(D_CALL, "%s: Attribute %s contains value \'%s\'",
		__func__, attr, result);
	return FEDFS_OK;
}

/**
 * Parse the value of an attribute containing an XDR-encoded FedFsPathname
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values pointer to a berval containing value of fedfsNfsPath attribute
 * @param result OUT: dynamically allocated buffer containing XDR-decoded path
 * @return a FedFsStatus code
 *
 * Caller must free "result" with free(3)
 */
FedFsStatus
nsdb_parse_singlevalue_xdrpath(char *attr, struct berval **values, char **result)
{
	FedFsStatus retval;

	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	retval = nsdb_xdr_to_posix_path(values[0], result);
	if (retval != FEDFS_OK) {
		xlog(L_ERROR, "%s: Bad %s value",
			__func__, attr);
		return retval;
	}

	xlog(D_CALL, "%s: Attribute %s contains value \'%s\'",
		__func__, attr, *result);
	return FEDFS_OK;
}

/**
 * Parse the values of a multi-value string attribute
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values pointer to a berval containing value of fedfsNfsPath attribute
 * @param result OUT: dynamically allocated array of NUL-terminated strings
 * @return a FedFsStatus code
 *
 * Caller must free "result" with nsdb_free_string_array()
 */
FedFsStatus
nsdb_parse_multivalue_str(char *attr, struct berval **values, char ***result)
{
	int i, count;
	char **tmp;

	count = ldap_count_values_len(values);
	tmp = calloc(count + 1, sizeof(char *));
	if (tmp == NULL) {
		xlog(D_GENERAL, "%s: no memory for array", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; i < count; i++) {
		tmp[i] = strdup(values[i]->bv_val);
		if (tmp[i] == NULL) {
			xlog(D_GENERAL, "%s: no memory for string", __func__);
			nsdb_free_string_array(tmp);
			return FEDFS_ERR_SVRFAULT;
		}
		xlog(D_CALL, "%s: %s[%d]: %s", __func__, attr, i, tmp[i]);
	}
	tmp[i] = NULL;

	*result = tmp;
	return FEDFS_OK;
}

/**
 * Allocate an LDAP * control block
 *
 * @param hostname NUL-terminated C string containing DNS name of LDAP server
 * @param port numeric port number of LDAP server
 * @param ld OUT: allocated LDAP control block
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Connection to the LDAP server may occur at a later time.
 */
FedFsStatus
nsdb_open(const char *hostname, const unsigned short port, LDAP **ld,
		unsigned int *ldap_err)
{
	int ldap_version, rc;
	LDAPURLDesc url;
	char *ldap_url;
	LDAP *tmp;

	memset(&url, 0, sizeof(url));
	url.lud_scheme = "ldap";
	url.lud_host = (char *)hostname;
	url.lud_port = port;
	url.lud_scope = LDAP_SCOPE_DEFAULT;
	ldap_url = ldap_url_desc2str(&url);
	if (ldap_url == NULL) {
		xlog(D_GENERAL, "%s: Failed to construct LDAP URL",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	rc = ldap_initialize(&tmp, ldap_url);
	free(ldap_url);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to initialize connection "
				"to NSDB '%s': %s",
				__func__, hostname,
				ldap_err2string(rc));
		return FEDFS_ERR_NSDB_CONN;
	}

	rc = ldap_get_option(tmp, LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to get connection version "
				" for NSDB '%s': %s",
				__func__, hostname,
				ldap_err2string(rc));
		goto out_ldap_err;
	}
	if (ldap_version < LDAP_VERSION3) {
		ldap_version = LDAP_VERSION3;
		rc = ldap_set_option(tmp,
				LDAP_OPT_PROTOCOL_VERSION, &ldap_version);
		if (rc != LDAP_OPT_SUCCESS) {
			xlog(D_GENERAL, "%s: Failed to get connection version "
					" for NSDB '%s': %s",
					__func__, hostname,
					ldap_err2string(rc));
			goto out_ldap_err;
		}
	}

	/*
	 * The FedFS protocol drafts do not specify how to handle LDAP
	 * referrals.  We probably don't want them, since our x.509 certs
	 * will probably not be usable with a referred to LDAP server.
	 */
	rc = ldap_set_option(tmp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to disable referrals: %s", 
						__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	*ld = tmp;
	return FEDFS_OK;

out_ldap_err:
	*ldap_err = rc;
	(void)ldap_unbind_ext_s(tmp, NULL, NULL);
	return FEDFS_ERR_NSDB_LDAP_VAL;
}

/**
 * Bind to an LDAP server
 *
 * @param ld an initialized LDAP descriptor
 * @param binddn NUL-terminated C string containing bind DN
 * @param passwd NUL-terminated C string containing bind password
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * This function may ask for a password on stdin if "binddn" is
 * not NULL but "passwd" is NULL.
 */
FedFsStatus
nsdb_bind(LDAP *ld, const char *binddn, const char *passwd,
		unsigned int *ldap_err)
{
	char *secret = (char *)passwd;
	struct berval cred;
	int rc;

	/* Anonymous bind? */
	if (binddn == NULL)
		return FEDFS_OK;

	if (secret == NULL || strcmp(secret , "-") == 0) {
		secret = nsdb_get_pw();
		if (secret == NULL) {
			xlog(D_GENERAL, "No password provided");
			return FEDFS_ERR_NSDB_AUTH;
		}
	}

	cred.bv_val = secret;
	cred.bv_len = strlen(secret);
	rc = ldap_sasl_bind_s(ld, binddn, NULL, &cred, NULL, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to bind with LDAP server: (%d) %s",
			__func__, rc, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	return FEDFS_OK;
}

/**
 * Start a TLS session
 *
 * @param ld an initialized LDAP descriptor
 * @param certfile NUL-terminated C string containing pathname of X.509 cert file
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If "certfile" is not NULL, then the certfile contents are used to
 * authenticate the server, and TLS must be started and operating
 * before this function returns true.
 */
FedFsStatus
nsdb_start_tls(LDAP *ld, const char *certfile, unsigned int *ldap_err)
{
	int value, rc;

	/* Nothing to do if no certfile was provided */
	if (certfile == NULL)
		return FEDFS_OK;

	rc = ldap_set_option(ld, LDAP_OPT_X_TLS_CERTFILE, certfile);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to set NSDB certificate: %s",
				__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	value = LDAP_OPT_X_TLS_HARD;
	rc = ldap_set_option(ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &value);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to set "
				"LDAP_OPT_X_TLS_REQUIRE_CERT: %s",
				__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to start TLS: %s",
				__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	return FEDFS_OK;

out_ldap_err:
	*ldap_err = rc;
	return FEDFS_ERR_NSDB_LDAP_VAL;
}

/**
 * Construct the DN of an FSN entry
 *
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID
 * @return NUL-terminated C string containing DN of an FSN entry
 *
 * Caller must free returned dn with free(3)
 */
char *
nsdb_construct_fsn_dn(const char *nce, const char *fsn_uuid)
{
	size_t dn_len;
	char *dn;
	int len;

	dn_len = strlen("fedfsFsnUuid=") + strlen(fsn_uuid) +
				strlen(",") + strlen(nce) + 1;
	dn = malloc(dn_len);
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
 * Construct the DN of an FSL entry
 *
 * @param nce NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid NUL-terminated C string containing FSN UUID
 * @param fsl_uuid NUL-terminated C string containing FSL UUID
 * @return NUL-terminated C string containing DN of an FSL entry
 *
 * Caller must free returned dn with free(3)
 */
char *
nsdb_construct_fsl_dn(const char *nce, const char *fsn_uuid, const char *fsl_uuid)
{
	size_t dn_len;
	char *dn;
	int len;

	dn_len = strlen("fedfsFslUuid=") + strlen(fsl_uuid) + strlen(",") +
		 strlen("fedfsFsnUuid=") + strlen(fsn_uuid) + strlen(",") +
		 strlen(nce) + 1;
	dn = malloc(dn_len);
	if (dn == NULL) {
		xlog(D_GENERAL, "%s: No memory for FSL DN", __func__);
		return NULL;
	}
	len = snprintf(dn, dn_len, "fedfsFslUuid=%s,fedfsFsnUuid=%s,%s",
				fsl_uuid, fsn_uuid, nce);
	if (len < 0 || (size_t)len > dn_len) {
		xlog(D_GENERAL, "%s: DN is too long", __func__);
		free(dn);
		return NULL;
	}

	xlog(D_CALL, "%s: Constructed dn %s", __func__, dn);
	return dn;
}

/**
 * Add a new FedFS-related attribute to "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to modify
 * @param value berval containing the value to add
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * This function is appropriate for modifying multi-valued attributes.
 * To modify single-valued attributes, use nsdb_update_attribute_s().
 *
 * The LDAP server will prevent schema violations (invalid values or
 * attribute names).
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "dn"
   changeType: add
   replace: "attribute"
   "attribute": "value"
   @endverbatim
 */
FedFsStatus
nsdb_add_attribute_s(LDAP *ld, const char *dn,
		const char *attribute, struct berval *value,
		unsigned int *ldap_err)
{
	struct berval *attrvals[2];
	LDAPMod mod[1], *mods[2];
	int rc;

	attrvals[0] = value;
	attrvals[1] = NULL;

	mod[0].mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
	mod[0].mod_type = (char *)attribute;
	mod[0].mod_bvalues = attrvals;

	mods[0] = &mod[0];
	mods[1] = NULL;

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "Failed to add attribute %s: %s",
				attribute, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return FEDFS_OK;
}

/**
 * Add a new or replace an existing FedFS-related attribute in "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to modify
 * @param value a berval containing the new value
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The LDAP server will prevent schema violations (invalid values or
 * attribute names).
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
FedFsStatus
nsdb_modify_attribute_s(LDAP *ld, const char *dn, const char *attribute,
		struct berval *value, unsigned int *ldap_err)
{
	struct berval *attrvals[2];
	LDAPMod mod[1], *mods[2];
	int rc;

	attrvals[0] = value;
	attrvals[1] = NULL;

	mod[0].mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES;
	mod[0].mod_type = (char *)attribute;
	mod[0].mod_bvalues = attrvals;

	mods[0] = &mod[0];
	mods[1] = NULL;

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "Failed to replace attribute %s: %s",
				attribute, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return FEDFS_OK;
}

/**
 * Delete a specific attribute value from entry "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to remove
 * @param value berval containing the value to remove
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * To delete the value of a single-valued attribute, or remove all
 * values from a multi-valued attribute, use nsdb_delete_attribute_all_s.
 * To delete a specific value from a multi-valued attribute, use
 * this function.
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
FedFsStatus
nsdb_delete_attribute_s(LDAP *ld, const char *dn, const char *attribute,
		struct berval *value, unsigned int *ldap_err)
{
	struct berval *attrvals[2];
	LDAPMod mod[1], *mods[2];
	int rc;

	attrvals[0] = value;
	attrvals[1] = NULL;

	mod[0].mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
	mod[0].mod_type = (char *)attribute;
	mod[0].mod_bvalues = attrvals;

	mods[0] = &mod[0];
	mods[1] = NULL;

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete attribute %s: %s",
				__func__, attribute, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return FEDFS_OK;
}

/**
 * Delete all values of an attribute in entry "dn"
 *
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of entry
 * @param attribute a NUL-terminated C string containing the name of an attribute to remove
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * To delete the value of a single-valued attribute, or remove all
 * values from a multi-valued attribute, use this function.  To
 * delete a specific value from a multi-valued attribute, use
 * nsdb_delete_attribute_s().
 *
 * This function is appropriate for modifying multi-valued attributes.
 * To modify single-valued attributes, use nsdb_update_attribute_s().
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
FedFsStatus
nsdb_delete_attribute_all_s(LDAP *ld, const char *dn,
		const char *attribute, unsigned int *ldap_err)
{
	LDAPMod mod[1], *mods[2];
	int rc;

	mod[0].mod_op = LDAP_MOD_DELETE;
	mod[0].mod_type = (char *)attribute;
	mod[0].mod_values = NULL;

	mods[0] = &mod[0];
	mods[1] = NULL;

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete attribute %s: %s",
				__func__, attribute, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return FEDFS_OK;
}
