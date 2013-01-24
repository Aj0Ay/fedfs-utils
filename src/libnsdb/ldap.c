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
#include <errno.h>
#include <memory.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <netdb.h>

#include "nsdb.h"
#include "junction.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Map scope to a printable string
 *
 * @param scope LDAP scope
 * @return static NUL-terminated C string containing scope name
 */
const char *
nsdb_printable_scope(int scope)
{
	switch (scope) {
	case LDAP_SCOPE_BASE:
		return "base";
	case LDAP_SCOPE_ONE:
		return "one";
	case LDAP_SCOPE_SUB:
		return "sub";
	case LDAP_SCOPE_CHILDREN:
		return "children";
	}
	return "default";
}

/**
 * Map LDAPMod operation to a printable string
 *
 * @param op LDAPMod operation
 * @return static NUL-terminated C string containing operation name
 */
static const char *
nsdb_printable_ldap_mod_op(int op)
{
	switch (op & LDAP_MOD_OP) {
	case LDAP_MOD_ADD:
		return "add";
	case LDAP_MOD_DELETE:
		return "delete";
	case LDAP_MOD_REPLACE:
		return "replace";
	}
	return "modify";
}

/**
 * Modify a FedFS-related record on an NSDB
 *
 * @param func NUL-terminated C string containing a function name
 * @param ld an initialized LDAP server descriptor
 * @param dn a NUL-terminated C string containing DN of NSDB container entry
 * @param mod filled-in LDAP modification argument
 * @param ldap_err OUT: possibly an LDAP error code
 * @return an LDAP result code
 */
static int
__nsdb_modify_nsdb_s(const char *func, LDAP *ld, const char *dn, LDAPMod *mod,
		unsigned int *ldap_err)
{
	char *uri, *attribute = mod->mod_type;
	LDAPMod *mods[] = { mod, NULL };
	int rc;

	if (ldap_get_option(ld, LDAP_OPT_URI, &uri) == LDAP_OPT_SUCCESS) {
		xlog(D_CALL, "%s: modifying %s (%s) at %s",
			func, dn, attribute, uri);
		ldap_memfree(uri);
	} else
		xlog(D_CALL, "%s: modifying %s (%s)",
			func, dn, attribute);

	rc = ldap_modify_ext_s(ld, dn, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: failed to %s attribute %s: %s",
				func, nsdb_printable_ldap_mod_op(mod->mod_op),
				attribute, ldap_err2string(rc));
		*ldap_err = (unsigned int)rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return FEDFS_OK;
}

/**
 * Hide the __func__ argument at call sites
 */
#define nsdb_modify_nsdb_s(ld, dn, mod, ldaperr) \
	__nsdb_modify_nsdb_s(__func__, ld, dn, mod, ldaperr)

/**
 * Enable LDAP debugging when contacting an NSDB
 *
 */
void
nsdb_enable_ldap_debugging(void)
{
	int rc, debug;

	debug = 0xffff;		/* LDAP_DEBUG_ANY */

#if 0
	rc = ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &debug);
	if (rc != LBER_OPT_SUCCESS)
		xlog(L_ERROR, "Failed to set LBER_OPT_DEBUG_LEVEL");
#endif

	rc = ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &debug);
	if (rc != LDAP_OPT_SUCCESS )
		xlog(L_ERROR, "Failed to set LDAP_OPT_DEBUG_LEVEL");
}

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
 * Set up LDAPMod structure for an LDAP MODIFY (add) operation
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
 * Set up LDAPMod structure for an LDAP MODIFY (del) operation
 *
 * @param mod pointer to struct to initialize
 * @param attribute NUL-terminated C string containing attribute name
 * @param bv pointer to array of C strings used for BER value
 * @param value NUL-terminated C string containing attribute value
 */
void
nsdb_init_del_attribute(LDAPMod *mod, const char *attribute,
		char **bv, const char *value)
{
	if (value != NULL) {
		bv[0] = (char *)value;
		bv[1] = NULL;
	}

	mod->mod_op = LDAP_MOD_DELETE;
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
	struct berval *value;

	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}
	value = values[0];
	
	if (strncmp(value->bv_val, "TRUE", value->bv_len) == 0) {
		xlog(D_CALL, "%s: Attribute %s contains TRUE",
			__func__, attr);
		*result = true;
		return FEDFS_OK;
	} else if (strncmp(value->bv_val, "FALSE", value->bv_len) == 0) {
		xlog(D_CALL, "%s: Attribute %s contains FALSE",
			__func__, attr);
		*result = false;
		return FEDFS_OK;
	}

	xlog(D_CALL, "%s: Attribute %s contains out-of-range value: %.*s",
		__func__, attr, value->bv_len, value->bv_val);
	return FEDFS_ERR_NSDB_RESPONSE;
}

/**
 * Parse the value of a single-value unsigned char attribute
 *
 * @param attr a NUL-terminated C string containing the name of an attribute
 * @param values a NULL-terminated array of pointers to bervals
 * @param result OUT: unsigned char into which to copy the value
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_parse_singlevalue_uchar(char *attr, struct berval **values,
		unsigned char *result)
{
	char *endptr;
	long tmp;

	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	errno = 0;
	tmp = strtol(values[0]->bv_val, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || tmp < 0 || tmp > 255) {
		xlog(D_CALL, "%s: Attribute %s contains out-of-range value %.*s",
			__func__, attr, values[0]->bv_len, values[0]->bv_val);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	*result = (unsigned char)tmp;
	xlog(D_CALL, "%s: Attribute %s contains value %d",
		__func__, attr, *result);
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
	char *endptr;
	long tmp;

	if (values[1] != NULL) {
		xlog(L_ERROR, "%s: Expecting only one value for attribute %s",
			__func__, attr);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	errno = 0;
	tmp = strtol(values[0]->bv_val, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || tmp < INT_MIN || tmp > INT_MAX) {
		xlog(D_CALL, "%s: Attribute %s contains out-of-range value %.*s",
			__func__, attr, values[0]->bv_len, values[0]->bv_val);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	*result = (int)tmp;
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
			xlog(D_GENERAL, "%s: Failed to set connection version "
					" for NSDB '%s': %s",
					__func__, hostname,
					ldap_err2string(rc));
			goto out_ldap_err;
		}
	}

	/*
	 * To authenticate a referred-to NSDB node and handle our
	 * per-NSDB "follow referrals" setting, libnsdb wants
	 * to handle LDAP referrals explicitly.
	 */
	rc = ldap_set_option(tmp, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to disable referrals "
			"for NSDB '%s': %s", __func__,
			hostname, ldap_err2string(rc));
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
			return FEDFS_ERR_INVAL;
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
 */
FedFsStatus
nsdb_start_tls(LDAP *ld, const char *certfile, unsigned int *ldap_err)
{
	int value, rc;
	char *uri;

	if (certfile == NULL)
		return FEDFS_ERR_INVAL;
	xlog(D_CALL, "%s: Using certfile %s", __func__, certfile);

	rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_CACERTFILE, certfile);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to set NSDB certificate: %s",
				__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	value = LDAP_OPT_X_TLS_HARD;
	rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &value);
	if (rc != LDAP_OPT_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to set "
				"LDAP_OPT_X_TLS_REQUIRE_CERT: %s",
				__func__, ldap_err2string(rc));
		goto out_ldap_err;
	}

	rc = ldap_start_tls_s(ld, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		char *msg = NULL;

		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void *)&msg);
		xlog(D_GENERAL, "%s: %s", __func__, msg);
		ldap_memfree(msg);

		if (rc == LDAP_CONNECT_ERROR)
			return FEDFS_ERR_NSDB_AUTH;
		goto out_ldap_err;
	}

	if (ldap_get_option(ld, LDAP_OPT_URI, &uri) == LDAP_OPT_SUCCESS) {
		xlog(D_CALL, "%s: START_TLS succeeded for %s",
			__func__, uri);
		ldap_memfree(uri);
	} else
		xlog(D_CALL, "%s: START_TLS succeeded", __func__);
	return FEDFS_OK;

out_ldap_err:
	*ldap_err = rc;
	return FEDFS_ERR_NSDB_LDAP_VAL;
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
	struct berval *attrvals[] = { value, NULL };
	LDAPMod mod = {
		.mod_op		= LDAP_MOD_ADD | LDAP_MOD_BVALUES,
		.mod_type	= (char *)attribute,
		.mod_bvalues	= attrvals,
	};

	return nsdb_modify_nsdb_s(ld, dn, &mod, ldap_err);
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
	struct berval *attrvals[] = { value, NULL };
	LDAPMod mod = {
		.mod_op		= LDAP_MOD_REPLACE | LDAP_MOD_BVALUES,
		.mod_type	= (char *)attribute,
		.mod_bvalues	= attrvals,
	};

	return nsdb_modify_nsdb_s(ld, dn, &mod, ldap_err);
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
	struct berval *attrvals[] = { value, NULL };
	LDAPMod mod = {
		.mod_op		= LDAP_MOD_DELETE | LDAP_MOD_BVALUES,
		.mod_type	= (char *)attribute,
		.mod_bvalues	= attrvals,
	};

	return nsdb_modify_nsdb_s(ld, dn, &mod, ldap_err);
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
	LDAPMod mod = {
		.mod_op		= LDAP_MOD_DELETE,
		.mod_type	= (char *)attribute,
	};

	return nsdb_modify_nsdb_s(ld, dn, &mod, ldap_err);
}

/**
 * Duplicate an array of referral URIs
 *
 * @param refs an array of NUL-terminated C strings containing LDAP URIs
 * @param referrals OUT: pointer to an array of NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * Caller must free "referrals" with nsdb_free_string_array().
 */
static FedFsStatus
nsdb_copy_referrals_array(char **refs, char ***referrals)
{
	int i, count;
	char **tmp;

	for (i = 0; refs[i] != NULL; i++)
		xlog(D_GENERAL, "%s: Referral: %s", __func__, refs[i]);
	if (referrals == NULL)
		return FEDFS_OK;
	count = i;

	tmp = calloc(count, sizeof(char *));
	if (tmp == NULL) {
		xlog(D_GENERAL, "%s: no memory for array", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; i < count; i++) {
		tmp[i] = strdup(refs[i]);
		if (tmp[i] == NULL) {
			xlog(D_GENERAL, "%s: no memory for string", __func__);
			nsdb_free_string_array(tmp);
			return FEDFS_ERR_SVRFAULT;
		}
	}
	tmp[i] = NULL;

	nsdb_free_string_array(*referrals);
	*referrals = tmp;
	return FEDFS_OK;
}

/**
 * Handle an LDAP search result message
 *
 * @param ld an initialized LDAP server descriptor
 * @param result an LDAP_RES_SEARCH_RESULT message
 * @param referrals OUT: pointer to an array of NUL-terminated C strings
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If "ldap_err" contains LDAP_REFERRAL, caller must free "referrals"
 * with nsdb_free_string_array().
 */
FedFsStatus
nsdb_parse_result(LDAP *ld, LDAPMessage *result, char ***referrals,
		unsigned int *ldap_err)
{
	char *matched_dn = NULL, *error_msg = NULL;
	int rc, result_code;
	char **refs = NULL;
	FedFsStatus retval;

	if (ld == NULL || result == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	rc = ldap_parse_result(ld, result, &result_code,
				&matched_dn, &error_msg, &refs, NULL, 0);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse result: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	if (result_code != LDAP_SUCCESS)
		xlog(D_CALL, "%s: Search result: %s",
			__func__, ldap_err2string(result_code));
	else
		xlog(D_CALL, "%s: Search completed successfully", __func__);

	if (matched_dn != NULL) {
		if (*matched_dn != '\0')
			xlog(D_GENERAL, "%s: Matched DN: %s",
				__func__, matched_dn);
		ber_memfree(matched_dn);
	}

	if (error_msg != NULL) {
		if (*error_msg != '\0')
			xlog(D_GENERAL, "%s: Extended error: %s",
				__func__, error_msg);
		ber_memfree(error_msg);
	}

	retval = FEDFS_OK;
	if (refs != NULL) {
		retval = nsdb_copy_referrals_array(refs, referrals);
		ber_memvfree((void **)refs);
	}

	if (result_code != LDAP_SUCCESS) {
		*ldap_err = result_code;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	return retval;
}

/**
 * Compare two BER values
 *
 * @param bv1 an LDAP berval structure
 * @param bv2 an LDAP berval structure
 * @return if true, input BER values match
 */
static _Bool
nsdb_compare_bval(struct berval *bv1, struct berval *bv2)
{
	if (bv1->bv_len != bv2->bv_len)
		return false;
	if (memcmp(bv1->bv_val, bv2->bv_val, bv1->bv_len) != 0)
		return false;
	return true;
}

/**
 * Compare two LDAP AVAs
 *
 * @param ava1
 * @param ava2
 * @return if true, input AVAs match
 */
static _Bool
nsdb_compare_avas(LDAPAVA *ava1, LDAPAVA *ava2)
{
	if (!nsdb_compare_bval(&ava1->la_attr, &ava2->la_attr))
		return false;
	if (!nsdb_compare_bval(&ava1->la_value, &ava2->la_value))
		return false;
	return true;
}

/**
 * Compare two LDAP relative distinguished names
 *
 * @param rdn1 a structured LDAP relative distinguished name
 * @param rdn2 a structured LDAP relative distinguished name
 * @return if true, input RDNs match
 */
static _Bool
nsdb_compare_rdns(LDAPRDN rdn1, LDAPRDN rdn2)
{
	int i;

	for (i = 0; rdn1[i] != NULL && rdn2[i] != NULL; i++)
		if (!nsdb_compare_avas(rdn1[i], rdn2[i]))
			return false;
	return true;
}

/**
 * Compare two LDAP distinguished names
 *
 * @param dn1 a structured LDAP distinguished name
 * @param dn2 a structured LDAP distinguished name
 * @return if true, the DNs match
 */
_Bool
nsdb_compare_dns(LDAPDN dn1, LDAPDN dn2)
{
	int count1, count2;

	if (dn1 == NULL || dn2 == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return false;
	}

	for (count1 = 0; dn1[count1] != NULL; count1++);
	for (count2 = 0; dn2[count2] != NULL; count2++);

	if (count1 != count2)
		return false;

	for (count1 = 0; count1 != count2; count1++)
		if (!nsdb_compare_rdns(dn1[count1], dn2[count1]))
			return false;

	return true;
}

/**
 * Compare a structured LDAP distinguished name with a DN string
 *
 * @param dn1 a structured LDAP distinguished name
 * @param dn2_in a NUL-terminated C string containing a distinguished name
 * @param ldap_err OUT: possibly an LDAP error code
 * @return if true, the DNs match
 *
 * On return, the return value is valid only if "ldap_err" is
 * LDAP_SUCCESS.
 */
_Bool
nsdb_compare_dn_string(LDAPDN dn1, const char *dn2_in,
		unsigned int *ldap_err)
{
	LDAPDN dn2 = NULL;
	_Bool result;
	int rc;

	result = false;

	if (dn1 == NULL || dn2_in == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		goto out;
	}

	rc = ldap_str2dn(dn2_in, &dn2, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		*ldap_err = rc;
		goto out;
	}

	*ldap_err = LDAP_SUCCESS;
	result = nsdb_compare_dns(dn1, dn2);

out:
	ldap_dnfree(dn2);
	return result;
}

/**
 * Compare two LDAP distinguished name strings
 *
 * @param dn1_in a NUL-terminated C string containing a distinguished name
 * @param dn2_in a NUL-terminated C string containing a distinguished name
 * @param ldap_err OUT: possibly an LDAP error code
 * @return if true, the DNs match
 *
 * On return, the return value is valid only if "ldap_err" is
 * LDAP_SUCCESS.
 */
_Bool
nsdb_compare_dn_strings(const char *dn1_in, const char *dn2_in,
		unsigned int *ldap_err)
{
	LDAPDN dn1 = NULL;
	LDAPDN dn2 = NULL;
	_Bool result;
	int rc;

	result = false;

	if (dn1_in == NULL || dn2_in == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		goto out;
	}

	rc = ldap_str2dn(dn1_in, &dn1, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		*ldap_err = rc;
		goto out;
	}

	rc = ldap_str2dn(dn2_in, &dn2, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		*ldap_err = rc;
		goto out;
	}

	*ldap_err = LDAP_SUCCESS;
	result = nsdb_compare_dns(dn1, dn2);

out:
	ldap_dnfree(dn2);
	ldap_dnfree(dn1);
	return result;
}

/**
 * Strip an RDN from the left end of a DN
 *
 * @param dn IN/OUT: a structured LDAP distinguished name
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free returned "*dn" with ldap_dnfree(3).
 *
 * Convert "dn" to a string starting after the first RDN, then
 * convert the resulting string back to an LDAPDN.
 */
FedFsStatus
nsdb_left_remove_rdn(LDAPDN *dn, unsigned int *ldap_err)
{
	LDAPDN new, dn_in;
	char *tmp = NULL;
	int rc;

	if (dn == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_INVAL;
	}

	dn_in = *dn;
	dn_in++;

	rc = ldap_dn2str(dn_in, &tmp, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	rc = ldap_str2dn(tmp, &new, LDAP_DN_FORMAT_LDAPV3);
	free(tmp);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to unparse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	ldap_dnfree(*dn);
	*dn = new;
	return FEDFS_OK;
}

/**
 * Append an RDN to the right end of a DN
 *
 * @param dn IN/OUT: a structured LDAP distinguished name
 * @param rdn a structured LDAP relative distinguished name
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * Caller must free returned "*dn" with ldap_dnfree(3).
 *
 * Convert both structured DNs to strings, concatenate them, then
 * convert the resulting string back to an LDAPDN.
 */
FedFsStatus
nsdb_right_append_rdn(LDAPDN *dn, LDAPRDN rdn, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *rstr = NULL;
	char *tmp = NULL;
	char *buf = NULL;
	LDAPDN new;
	size_t len;
	int rc;

	if (dn == NULL || rdn == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		retval = FEDFS_ERR_INVAL;
		goto out;
	}

	rc = ldap_rdn2str(rdn, &rstr, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse RDN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}

	if (*dn == NULL) {
		rc = ldap_str2dn(rstr, &new, LDAP_DN_FORMAT_LDAPV3);
		if (rc != LDAP_SUCCESS) {
			xlog(D_GENERAL, "%s: Failed to unparse DN: %s",
				__func__, ldap_err2string(rc));
			*ldap_err = rc;
			retval = FEDFS_ERR_NSDB_LDAP_VAL;
			goto out;
		}
		goto out_success;
	}

	rc = ldap_dn2str(*dn, &tmp, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to parse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}

	len = strlen(tmp) + strlen(",") + strlen(rstr) + 1;
	buf = malloc(len);
	if (buf == NULL) {
		xlog(D_GENERAL, "%s: no memory", __func__);
		retval = FEDFS_ERR_SVRFAULT;
		goto out;
	}

	strcpy(buf, tmp);
	strcat(buf, ",");
	strcat(buf, rstr);

	rc = ldap_str2dn(buf, &new, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to unparse DN: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		retval = FEDFS_ERR_NSDB_LDAP_VAL;
		goto out;
	}

out_success:
	ldap_dnfree(*dn);
	*dn = new;
	retval = FEDFS_OK;

out:
	free(buf);
	ldap_memfree(tmp);
	free(rstr);
	return retval;
}

/**
 * Compare two LDAP distinguished names
 *
 * @param dn a structured LDAP distinguished name
 * @param suffix a structured LDAP distinguished name
 * @return if true, the DNs match
 */
static _Bool
nsdb_ends_with(LDAPDN dn, LDAPDN suffix)
{
	unsigned int count_d, count_s;

	for (count_d = 0; dn[count_d] != NULL; count_d++);
	for (count_s = 0; suffix[count_s] != NULL; count_s++);

	if (count_d < count_s || count_s == 0)
		return false;

	for (; count_s != 0; count_d--, count_s--)
		if (!nsdb_compare_rdns(dn[count_d - 1], suffix[count_s - 1]))
			return false;
	return true;
}

/**
 * Predicate: See if "dn" ends with "suffix"
 *
 * @param dn_in a NUL-terminated C string containing a distinguished name
 * @param suffix_in a NUL-terminated C string containing a distinguished name
 * @param ldap_err OUT: possibly an LDAP error code
 * @return if true, "dn" ends with "suffix"
 *
 * On return, the return value is valid only if "ldap_err" is
 * LDAP_SUCCESS.
 */
_Bool
nsdb_dn_ends_with(const char *dn_in, const char *suffix_in,
		unsigned int *ldap_err)
{
	LDAPDN dn = NULL;
	LDAPDN suffix = NULL;
	_Bool result;
	int rc;

	result = false;

	if (dn_in == NULL || suffix_in == NULL || ldap_err == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		goto out;
	}

	rc = ldap_str2dn(dn_in, &dn, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		*ldap_err = rc;
		goto out;
	}

	rc = ldap_str2dn(suffix_in, &suffix, LDAP_DN_FORMAT_LDAPV3);
	if (rc != LDAP_SUCCESS) {
		*ldap_err = rc;
		goto out;
	}

	*ldap_err = LDAP_SUCCESS;
	result = nsdb_ends_with(dn, suffix);

	if (result)
		xlog(D_CALL, "%s: dn '%s' ends with '%s'",
			__func__, dn_in, suffix_in);
	else
		xlog(D_CALL, "%s: dn '%s' does not end with '%s'",
			__func__, dn_in, suffix_in);

out:
	ldap_dnfree(suffix);
	ldap_dnfree(dn);
	return result;
}
