/*
 * @file src/libnsdb/nsdb-internal.h
 * @brief Common public declarations for the NSDB API
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

#ifndef _FEDFS_NSDB_INTERNAL_H_
#define _FEDFS_NSDB_INTERNAL_H_

#include <time.h>
#include <ldap.h>
#include <sqlite3.h>

#include "fedfs_admin.h"

/**
 * object that internally represents an NSDB
 */
struct fedfs_nsdb {
	char *			fn_hostname;
	unsigned short		fn_port;
	unsigned int		fn_sectype;
	char *			fn_certfile;
	LDAP *			fn_ldap;
	char **			fn_naming_contexts;
	char *			fn_default_binddn;
	char *			fn_default_nce;
	_Bool			fn_follow_referrals;
	char **			fn_referrals;
};

/**
 ** Private LDAP-related APIs (ldap.c)
 **/

const char *	 nsdb_printable_scope(int scope);

void		 nsdb_init_add_attribute(LDAPMod *mod,
				const char *attribute, char **bv,
				const char *value);
void		 nsdb_init_mod_attribute(LDAPMod *mod,
				const char *attribute, char **bv,
				const char *value);
void		 nsdb_init_del_attribute(LDAPMod *mod,
				const char *attribute, char **bv,
				const char *value);

FedFsStatus	 nsdb_parse_singlevalue_bool(char *attr,
				struct berval **values, _Bool *result);
FedFsStatus	 nsdb_parse_singlevalue_uchar(char *attr,
				struct berval **values, unsigned char *result);
FedFsStatus	 nsdb_parse_singlevalue_int(char *attr,
				struct berval **values, int *result);
FedFsStatus	 nsdb_parse_singlevalue_str(char *attr,
				struct berval **values, char *result,
				const size_t len);
FedFsStatus	 nsdb_parse_multivalue_str(char *attr,
				struct berval **values, char ***result);

FedFsStatus	 nsdb_open(const char *hostname,
				const unsigned short port, LDAP **ld,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_bind(LDAP *ld, const char *binddn,
				const char *passwd,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_start_tls(LDAP *ld, const char *certfile,
				unsigned int *ldap_err);

FedFsStatus	 nsdb_add_attribute_s(LDAP *ld, const char *dn,
				const char *attribute,
				struct berval *value,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_modify_attribute_s(LDAP *ld, const char *dn,
				const char *attribute,
				struct berval *value,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_delete_attribute_s(LDAP *ld, const char *dn,
				const char *attribute,
				struct berval *value,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_delete_attribute_all_s(LDAP *ld, const char *dn,
				const char *attribute,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_parse_result(LDAP *ld, LDAPMessage *result,
				char ***referrals, unsigned int *ldap_err);
_Bool		 nsdb_compare_dns(LDAPDN dn1, LDAPDN dn2);
_Bool		 nsdb_compare_dn_string(LDAPDN dn1, const char *dn2_in,
				unsigned int *ldap_err);
_Bool		 nsdb_compare_dn_strings(const char *dn1_in,
				const char *dn2_in,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_left_remove_rdn(LDAPDN *dn, unsigned int *ldap_err);
FedFsStatus	 nsdb_right_append_rdn(LDAPDN *dn, LDAPRDN rdn,
				unsigned int *ldap_err);
_Bool		 nsdb_dn_ends_with(const char *dn_in, const char *suffix_in,
				unsigned int *ldap_err);


/**
 ** Private sqlite-related APIs (sqlite.c)
 **/
sqlite3		*nsdb_open_db(const char *db_filename, int flags);
void		 nsdb_close_db(sqlite3 *db);
_Bool		 nsdb_prepare_stmt(sqlite3 *db, sqlite3_stmt **stmt,
				const char *sql);
void		 nsdb_finalize_stmt(sqlite3_stmt *stmt);
_Bool		 nsdb_begin_transaction(sqlite3 *db);
void		 nsdb_end_transaction(sqlite3 *db);
void		 nsdb_rollback_transaction(sqlite3 *db);
_Bool		 nsdb_create_table(sqlite3 *db, const char *table_name,
				const char *table_def);

/**
 ** Private security-related APIs (nsdb.c)
 **/
FedFsStatus	 nsdb_create_private_certfile(char **pathbuf);
FedFsStatus	 nsdb_update_security_nsdbparams(struct fedfs_nsdb *host,
				FedFsConnectionSec type,
				const char *certfile);

/**
 ** Private security-related APIs (connsec.c)
 **/
void		 nsdb_connsec_remove_certfile(const char *certfile);

#endif	/* !_FEDFS_NSDB_INTERNAL_H_ */
