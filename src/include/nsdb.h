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

#include "fedfs_admin.h"
#include "fedfs.h"

/**
 * Default DN of FedFS NSDB containers
 */
#define NSDB_DEFAULT_NCE	"o=fedfs"

/**
 * Object that internally represents an NSDB
 */
struct fedfs_nsdb;
typedef struct fedfs_nsdb *nsdb_t;

/**
 * Stored connection parameters
 */
struct fedfs_secdata {
	FedFsConnectionSec	 type;
	char			*data;
	unsigned int		 len;
};

/**
 * Object that contains FedFS NFS fileset Location data
 *
 * Derived from the fedfsNfsFsl object class, defined in
 * the NSDB protocol draft, chapter 4, section 2.2.4
 */
struct fedfs_nfs_fsl {
	char			 *fn_path;
	int			  fn_majorver;
	int			  fn_minorver;
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
	char			  fl_nsdbname[NI_MAXHOST + 1];
	int			  fl_nsdbport;
	char			  fl_fslhost[NI_MAXHOST + 1];
	int			  fl_fslport;
	int			  fl_fslttl;
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
 * Extract contents of a certificate file
 */
FedFsStatus	 nsdb_read_certfile(const char *pathname,
				char **certdata, unsigned int *certlen);

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
				const unsigned short port, nsdb_t *host,
				struct fedfs_secdata *sec);

/**
 * Update stored connection parameters for an NSDB
 */
FedFsStatus	 nsdb_update_nsdb(const char *hostname,
				const unsigned short port,
				const struct fedfs_secdata *sec);

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
const char	*nsdb_default_binddn(const nsdb_t host);
const char	*nsdb_default_nce(const nsdb_t host);
_Bool		 nsdb_follow_referrals(const nsdb_t host);

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
				char **binddn, char **nce, char **passwd);


/**
 ** NSDB administrative operations defined in the
 ** NSDB protocol draft, Chapter 5, section 1)
 **/

/**
 * Create an FSN (5.1.1)
 */
FedFsStatus	 nsdb_create_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid, const char *nsdbname,
				const unsigned short nsdbport,
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
				const char *value,
				unsigned int *ldap_err);

/**
 ** NSDB administrative operations defined by this implementation
 **/

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
FedFsStatus	 nsdb_get_nceprefix_s(nsdb_t host, const char *naming_context,
				char **dn, unsigned int *ldap_err);
FedFsStatus	 nsdb_get_naming_contexts_s(nsdb_t host, char ***contexts,
				unsigned int *ldap_err);
FedFsStatus	 nsdb_split_nce_dn_s(nsdb_t host, const char *nce,
				char **context, char **prefix,
				unsigned int *ldap_err);

/**
 * Resolve an FSN (5.2.2)
 */
FedFsStatus	 nsdb_resolve_fsn_s(nsdb_t host, const char *nce,
				const char *fsn_uuid, struct fedfs_fsl **fsls,
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

FedFsStatus	 nsdb_fedfspathname_to_posix(const FedFsPathName fpath,
				char **pathname);
FedFsStatus	 nsdb_posix_to_fedfspathname(const char *pathname,
				FedFsPathName *fpath);
void		 nsdb_free_fedfspathname(FedFsPathName *fpath);

FedFsStatus	 nsdb_posix_path_to_xdr(const char *pathname,
				struct berval *xdr_path);
FedFsStatus	 nsdb_xdr_to_posix_path(struct berval *xdr_path,
				char **pathname);

#endif	/* !_FEDFS_NSDB_H_ */
