/*
 * @file src/include/nsdb.h
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

#ifndef _FEDFS_NSDB_H_
#define _FEDFS_NSDB_H_

#include <netdb.h>
#include <ldap.h>
#include <uriparser/Uri.h>

#include "fedfs_admin.h"
#include "fedfs.h"

/**
 * Object that internally represents an NSDB
 */
struct fedfs_nsdb;
typedef struct fedfs_nsdb *nsdb_t;

/**
 * Object that contains FedFS Fileset Name data
 *
 * Derived from the fedfsFsn object class, defined in
 * the NSDB protocol draft, chapter 4, section 2.2.2
 */
struct fedfs_fsn {
	char			 *fn_dn;

	char			  fn_fsnuuid[FEDFS_UUID_STRLEN];
	int			  fn_fsnttl;
	char			**fn_annotations;
	char			**fn_description;
};

/**
 ** API to manage struct fedfs_fsn objects
 **/

/**
 * Release a struct fedfs_fsn
 */
void		 nsdb_free_fedfs_fsn(struct fedfs_fsn *fsn);


/**
 * Object that contains FedFS NFS fileset Location data
 *
 * Derived from the fedfsNfsFsl object class, defined in
 * the NSDB protocol draft, chapter 4, section 2.2.4
 */
struct fedfs_nfs_fsl {
	char			  fn_fslhost[NI_MAXHOST + 1];
	int			  fn_fslport;
	char			**fn_nfspath;
	int			  fn_currency;
	_Bool			  fn_gen_writable;
	_Bool			  fn_gen_going;
	_Bool			  fn_gen_split;
	_Bool			  fn_trans_rdma;
	unsigned char		  fn_class_simul;
	unsigned char		  fn_class_handle;
	unsigned char		  fn_class_fileid;
	unsigned char		  fn_class_writever;
	unsigned char		  fn_class_change;
	unsigned char		  fn_class_readdir;
	unsigned char		  fn_readrank;
	unsigned char		  fn_readorder;
	unsigned char		  fn_writerank;
	unsigned char		  fn_writeorder;
	_Bool			  fn_varsub;
	int			  fn_validfor;
};

/**
 * Object that contains FedFS Fileset Location data
 *
 * Derived from the fedfsFsl object class, defined in
 * the NSDB protocol draft, chapter 4, section 2.2.3
 */
struct fedfs_fsl {
	struct fedfs_fsl	 *fl_next; 
	char			 *fl_dn;

	char			  fl_fsluuid[FEDFS_UUID_STRLEN];
	char			  fl_fsnuuid[FEDFS_UUID_STRLEN];
	char			**fl_annotations;
	char			**fl_description;

	FedFsFslType		  fl_type;
	union {
		struct fedfs_nfs_fsl	  fl_nfsfsl;
	} fl_u;
};

/**
 ** API to manage struct fedfs_fsl objects
 **/

/**
 * Allocate a fresh struct fedfs_fsl and init its fields to standard defaults
 */
__attribute_malloc__
struct fedfs_fsl *
		 nsdb_new_fedfs_fsl(FedFsFslType type);

/**
 * Release a struct fedfs_fsl
 */
void		 nsdb_free_fedfs_fsl(struct fedfs_fsl *fsl);

/**
 * Release a list of struct fedfs_fsls
 */
void		 nsdb_free_fedfs_fsls(struct fedfs_fsl *fsls);


/**
 ** API to manage NSDB objects and the associated X.509 cert store
 **/

/**
 * Locate the cert store
 */
_Bool		 nsdb_set_parentdir(const char *parentdir);
_Bool		 nsdb_is_default_parentdir(void);
_Bool		 nsdb_init_database(void);

/**
 * Generate list of NSDB names we know about
 */
FedFsStatus	 nsdb_enumerate_nsdbs(char ***nsdblist);

/**
 * Construct a new nsdb_t object
 */
FedFsStatus	 nsdb_new_nsdb(const char *hostname, const unsigned long port,
				nsdb_t *host);

/**
 * Instantiate an nsdb_t object based on stored connection parameters
 */
FedFsStatus	 nsdb_lookup_nsdb(const char *hostname,
				const unsigned short port, nsdb_t *host);

/**
 * Instantiate an nsdb_t object based on stored connection parameters
 */
FedFsStatus	 nsdb_lookup_nsdb_by_uri(const char *uri, nsdb_t *host);

/**
 * Create connection parameters entry for an NSDB
 */
FedFsStatus	 nsdb_create_nsdb(const char *hostname,
				const unsigned short port);

/**
 * Initialize libcrypto
 */
void		 nsdb_connsec_crypto_startup(void);

/**
 * Shut down libcrypto
 */
void		 nsdb_connsec_crypto_shutdown(void);

/**
 * Retrieve NSDB certificate data for "host"
 */
FedFsStatus	 nsdb_connsec_get_cert_data(nsdb_t host,
				char **data, unsigned int *len);

/**
 * Set connection security parameters for an NSDB to "NONE"
 */
FedFsStatus	 nsdb_connsec_set_none(const char *hostname,
				const unsigned short port);

/**
 * Set connection security parameters for an NSDB to "TLS"
 * Certificate material provided in a buffer
 */
FedFsStatus	 nsdb_connsec_set_tls_buf(const char *hostname,
				const unsigned short port, char *data,
				unsigned int len);

/**
 * Set connection security parameters for an NSDB to "TLS"
 * Certificate material provided in a local file
 */
FedFsStatus	 nsdb_connsec_set_tls_file(const char *hostname,
				const unsigned short port,
				const char *certfile);

/**
 * Update stored default bind DN for an NSDB
 */
FedFsStatus	 nsdb_update_default_binddn(const char *hostname,
				const unsigned short port,
				const char *binddn);

/**
 * Update stored default NCE for an NSDB
 */
FedFsStatus	 nsdb_update_default_nce(const char *hostname,
				const unsigned short port,
				const char *nce);

/**
 * Update stored followReferrals flag for an NSDB
 */
FedFsStatus	 nsdb_update_follow_referrals(const char *hostname,
				const unsigned short port,
				const _Bool follow_referrals);

/**
 * Remove stored connection parameters for an NSDB
 */
FedFsStatus	 nsdb_delete_nsdb(const char *hostname,
				const unsigned short port);

/**
 * Connect an nsdb_t object to the server it represents
 */
FedFsStatus	 nsdb_open_nsdb(nsdb_t host, const char *binddn,
				const char *passwd,
				unsigned int *ldap_err);

/**
 * Finish a previously opened connection
 */
void		 nsdb_close_nsdb(nsdb_t host);

/**
 * Release all resources associated with an nsdb_t object
 */
void		 nsdb_free_nsdb(nsdb_t host);

/**
 * Access various data fields in an nsdb_t
 */
const char	*nsdb_hostname(const nsdb_t host);
size_t		 nsdb_hostname_len(const nsdb_t host);
unsigned short	 nsdb_port(const nsdb_t host);
FedFsConnectionSec
		 nsdb_sectype(const nsdb_t host);
const char	*nsdb_certfile(const nsdb_t host);
const char	*nsdb_default_binddn(const nsdb_t host);
const char	*nsdb_default_nce(const nsdb_t host);
_Bool		 nsdb_follow_referrals(const nsdb_t host);
const char	*nsdb_referred_to(const nsdb_t host);

/**
 * Data type helpers for nsdb_t objects
 */
_Bool		 nsdb_parse_port_string(const char *string,
				unsigned short *port);
_Bool		 nsdb_is_hostname_utf8(const char *hostname);

/**
 * Look for "default" values in environment variables
 */
void		 nsdb_env(char **nsdbname, unsigned short *nsdbport,
				char **binddn, char **nce);


/**
 ** NSDB administrative operations defined in the
 ** NSDB protocol draft, Chapter 5, section 1)
 **/

/**
 * Create an FSN (5.1.1)
 */
FedFsStatus	 nsdb_create_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid,
				const unsigned int ttl,
				unsigned int *ldap_err);

/**
 * Delete an FSN (5.1.2)
 */
FedFsStatus	 nsdb_delete_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid, _Bool leave_fsn,
				unsigned int *ldap_err);

/**
 * Create one or more FSLs (5.1.3)
 */
FedFsStatus	 nsdb_create_fsls_s(nsdb_t host, const char *nce,
				struct fedfs_fsl *fsls,
				unsigned int *ldap_err);

/**
 * Delete an FSL (5.1.4)
 */
FedFsStatus	 nsdb_delete_fsl_s(nsdb_t host, const char *nce,
				const char *fsl_uuid,
				unsigned int *ldap_err);

/**
 * Update an FSL (5.1.5)
 */
FedFsStatus	 nsdb_update_fsl_s(nsdb_t host, const char *nce,
				const char *fsl_uuid,
				const char *attribute,
				const void *value,
				unsigned int *ldap_err);

/**
 ** NSDB administrative operations defined by this implementation
 **/

/**
 * Create a simple "ou=fedfs" entry
 */
FedFsStatus	 nsdb_create_simple_nce_s(nsdb_t host, const char *parent,
				char **dn, unsigned int *ldap_err);

/**
 * Update or remove NSDB container information
 */
FedFsStatus	 nsdb_update_nci_s(nsdb_t host, const char *nce,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_remove_nci_s(nsdb_t host, const char *nce,
				unsigned int *ldap_err);

/**
 * Remove all FedFS entries on an NSDB
 */
FedFsStatus	 nsdb_delete_nsdb_s(nsdb_t host, const char *nce,
				unsigned int *ldap_err);

/**
 * Display or alter an object's fedfsDescription attribute
 */
FedFsStatus	 nsdb_description_add_s(nsdb_t host, const char *dn,
				const char *description, unsigned int *ldap_err);
FedFsStatus	 nsdb_description_delete_s(nsdb_t host, const char *dn,
				const char *description, unsigned int *ldap_err);

/**
 * Display or alter an object's fedfsAnnotation attribute
 */
FedFsStatus	 nsdb_annotation_add_s(nsdb_t host, const char *dn,
				const char *annotation, unsigned int *ldap_err);
FedFsStatus	 nsdb_annotation_delete_s(nsdb_t host, const char *dn,
				const char *annotation, unsigned int *ldap_err);

/**
 ** NSDB file server operations defined in the
 ** NSDB protocol draft, Chapter 5, section 2)
 **/

/**
 * NSDB Container Entry enumeration (5.2.1)
 */
FedFsStatus	 nsdb_get_ncedn_s(nsdb_t host, const char *naming_context,
				char **dn, unsigned int *ldap_err);
FedFsStatus	 nsdb_get_naming_contexts_s(nsdb_t host, char ***contexts,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_find_naming_context_s(nsdb_t host, const char *entry,
				char **context, unsigned int *ldap_err);

/**
 * Resolve an FSN (5.2.2)
 */
FedFsStatus	 nsdb_resolve_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid, struct fedfs_fsl **fsls,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_get_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid, struct fedfs_fsn **fsn,
				unsigned int *ldap_err);

/**
 ** NSDB fileserver operations defined by this implementation
 **/

/**
 * Enumerate FSNs
 */
FedFsStatus	 nsdb_list_s(nsdb_t host, const char *nce, char ***fsns,
				unsigned int *ldap_err);

/**
 * Ping an NSDB host
 */
FedFsStatus	 nsdb_ping_nsdb_s(nsdb_t host, unsigned int *ldap_err);

/**
 * Ping an LDAP server
 */
FedFsStatus	 nsdb_ping_s(const char *hostname, const unsigned short port,
				unsigned int *ldap_err);

/**
 * Enable LDAP debugging when contacting an NSDB
 */
void		 nsdb_enable_ldap_debugging(void);

/**
 ** Readability helpers
 **/
const char	*nsdb_display_fedfsconnectionsec(const FedFsConnectionSec sectype);
const char	*nsdb_display_fedfsstatus(const FedFsStatus status);
void		 nsdb_print_fedfsstatus(const FedFsStatus status);

void		 nsdb_free_string_array(char **strings);

/**
 ** fedfsAnnotation parsing
 **/
FedFsStatus	 nsdb_construct_annotation(const char *keyword,
				const char *value, char **annotation);
FedFsStatus	 nsdb_parse_annotation(const char *annotation, size_t len,
				char **keyword, char **value);

/**
 ** Pathname parsing utilities
 **/
__attribute_malloc__
char		*nsdb_normalize_path(const char *pathname);
_Bool		 nsdb_pathname_is_utf8(const char *pathname);
void		 nsdb_free_fedfspathname(FedFsPathName *fpath);

FedFsStatus	 nsdb_path_array_to_posix(char * const *path_array,
				char **pathname);
FedFsStatus	 nsdb_posix_to_path_array(const char *pathname,
				char ***path_array);
FedFsStatus	 nsdb_path_array_to_fedfspathname(char * const *path_array,
				FedFsPathName *fpath);
FedFsStatus	 nsdb_fedfspathname_to_path_array(FedFsPathName fpath,
				char ***path_array);
void		 nsdb_assign_textrange(UriTextRangeA *text,
				const char *string);
FedFsStatus	 nsdb_path_array_to_uri_pathname(char * const *path_array,
				UriUriA *uri);
FedFsStatus	 nsdb_uri_pathname_to_path_array(const UriUriA *uri,
				char ***path_array);

/**
 ** x.509 certificate utilities
 **/
FedFsStatus	 nsdb_connsec_read_pem_file(const char *certfile,
				char **data, unsigned int *len);
FedFsStatus	 nsdb_connsec_write_pem_file(const char *certfile,
				const char *data, const unsigned int len);

#endif	/* !_FEDFS_NSDB_H_ */
