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

#include "nsdb.h"
#include "junction.h"
#include "path.h"
#include "nsdb-internal.h"
#include "xlog.h"

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
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
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
   fedfsNsdbName: "nsdbname"
   @endverbatim
 */
static FedFsStatus
nsdb_create_fsn_add_entry(LDAP *ld, const char *nce,
		const char *fsn_uuid, const char *nsdbname,
		const unsigned short nsdbport, unsigned int *ldap_err)
{
	char *ocvals[2], *uuidvals[2], *namevals[2], *portvals[2];
	LDAPMod *attrs[5];
	LDAPMod attr[4];
	char portbuf[8];
	int i, rc;
	char *dn;

	for (i = 0; i < 4; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "fedfsFsn");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFsnUuid", uuidvals, fsn_uuid);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbName", namevals, nsdbname);
	sprintf(portbuf, "%u", nsdbport);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbPort", portvals, portbuf);

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
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_create_fsn_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		const char *nsdbname, const unsigned short nsdbport,
		unsigned int *ldap_err)
{
	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce == NULL || fsn_uuid == NULL || nsdbname == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	return nsdb_create_fsn_add_entry(host->fn_ldap, nce, fsn_uuid,
						nsdbname, nsdbport, ldap_err);
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
	static char *attrs[] = { LDAP_NO_ATTRS, NULL };
	LDAPMessage *response;
	FedFsStatus retval;
	char filter[128];
	int len, rc;

	/* watch out for buffer overflow */
	len = snprintf(filter, sizeof(filter),
			"(&(objectClass=fedfsFsn)(fedfsFsnUuid=%s))", fsn_uuid);
	if (len < 0 || (size_t)len > sizeof(filter)) {
		xlog(D_GENERAL, "%s: filter is too long", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	rc = ldap_search_ext_s(ld, nce, LDAP_SCOPE_ONELEVEL,
				filter, attrs, 0, NULL, NULL,
				NULL, LDAP_NO_LIMIT, &response);
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
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_fsn_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce == NULL || fsn_uuid == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = nsdb_search_fsn_dn_s(host->fn_ldap, nce, fsn_uuid,
						&dn, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_delete_fsn_entry_s(host->fn_ldap, dn, ldap_err);
	ber_memfree(dn);
	return retval;
}

/**
 * Add a new FSL entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
 * @param servername a NUL-terminated C string containing DNS hostname of file server
 * @param serverport port number of file server
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: fedfsFslUuid="fsl_uuid",fedfsFsnUuid="fsn_uuid","nce"
   changeType: add
   objectClass: fedfsFsl
   fedfsFslUuid: "fsl_uuid"
   fedfsFsnUuid: "fsn_uuid"
   fedfsNsdbName: "nsdbname"
   fedfsNsdbPort: "nsdbport"
   fedfsFslHost: "serverhost"
   fedfsFslPort: "serverport"
   fedfsFslTTL: 300
   @endverbatim
 */
static FedFsStatus
nsdb_create_fsl_add_entry_s(LDAP *ld, const char *nce,
		const char *fsn_uuid, const char *fsl_uuid,
		const char *nsdbname, const unsigned short nsdbport,
		const char *servername, const unsigned short serverport,
		unsigned int *ldap_err)
{
	char *servernamevals[2], *serverportvals[2], *ttyvals[2];
	char *ocvals[2], *fsnuuidvals[2], *fsluuidvals[2];
	char *nsdbnamevals[2], *nsdbportvals[2];
	char nsdbportbuf[8], serverportbuf[8];
	LDAPMod *attrs[10];
	LDAPMod attr[9];
	int i, rc;
	char *dn;

	for (i = 0; i < 9; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "fedfsFsl");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslUuid", fsluuidvals, fsl_uuid);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFsnUuid", fsnuuidvals, fsn_uuid);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbName", nsdbnamevals, nsdbname);
	if (nsdbport != LDAP_PORT) {
		sprintf(nsdbportbuf, "%u", nsdbport);
		nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbPort", nsdbportvals, nsdbportbuf);
	}
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslHost", servernamevals, servername);
	if (serverport != 0) {
		sprintf(serverportbuf, "%u", serverport);
		nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbPort", serverportvals, serverportbuf);
	}
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslTTL", ttyvals, "300");

	attrs[i] = NULL;

	dn = nsdb_construct_fsl_dn(nce, fsn_uuid, fsl_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	rc = ldap_add_ext_s(ld, dn, attrs, NULL, NULL);
	free(dn);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to add new FSL entry: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully added new FSL entry",
		__func__);
	return FEDFS_OK;
}

/**
 * Add a new NFS FSL entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
 * @param servername a NUL-terminated C string containing DNS hostname of file server
 * @param serverport port number of file server
 * @param xdr_path a berval containing an XDR-encoded pathname
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * The new entry is set up as an NFSv4.0 FSL, and can be subsequently modified
 * using the nsdb-modify-fsl tool.
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
nsdb_create_fsl_add_nfs_entry_s(LDAP *ld, const char *nce,
		const char *fsn_uuid, const char *fsl_uuid,
		const char *nsdbname, const unsigned short nsdbport,
		const char *servername, const unsigned short serverport,
		struct berval *xdr_path, unsigned int *ldap_err)
{
	char *servernamevals[2], *serverportvals[2], *ttyvals[2];
	char *ocvals[3], *fsnuuidvals[2], *fsluuidvals[2];
	char *nsdbnamevals[2], *nsdbportvals[2];
	char *majversvals[2], *minversvals[2], *currvals[2];
	char *flagwvals[2], *flaggvals[2], *flagsvals[2], *flagrvals[2];
	char *csvals[2], *chvals[2], *cfvals[2], *cwvals[2], *ccvals[2], *crvals[2];
	char *rrankvals[2], *rordvals[2], *wrankvals[2], *wordvals[2];
	char *varsubvals[2], *valforvals[2];
	char nsdbportbuf[8], serverportbuf[8];
	struct berval *xdrpathvals[2];
	LDAPMod *attrs[30];
	LDAPMod attr[29];
	int i, rc;
	char *dn;

	for (i = 0; i < 30; i++)
		attrs[i] = &attr[i];
	i = 0;

	nsdb_init_add_attribute(attrs[i++],
				"objectClass", ocvals, "fedfsFsl");
	ocvals[1] = "fedfsNfsFsl";
	ocvals[2] = NULL;

	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslUuid", fsluuidvals, fsl_uuid);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFsnUuid", fsnuuidvals, fsn_uuid);
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbName", nsdbnamevals, nsdbname);
	if (nsdbport != LDAP_PORT) {
		sprintf(nsdbportbuf, "%u", nsdbport);
		nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbPort", nsdbportvals, nsdbportbuf);
	}
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslHost", servernamevals, servername);
	if (serverport != 0) {
		sprintf(serverportbuf, "%u", serverport);
		nsdb_init_add_attribute(attrs[i++],
				"fedfsNsdbPort", serverportvals, serverportbuf);
	}
	nsdb_init_add_attribute(attrs[i++],
				"fedfsFslTTL", ttyvals, "300");

	xdrpathvals[0] = xdr_path;
	xdrpathvals[1] = NULL;
	attr[i].mod_op = LDAP_MOD_BVALUES;
	attr[i].mod_type = "fedfsNfsPath";
	attr[i++].mod_bvalues = xdrpathvals;

	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsMajorVer", majversvals, "4");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsMinorVer", minversvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsCurrency", currvals, "-1");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsGenFlagWritable", flagwvals, "FALSE");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsGenFlagGoing", flaggvals, "FALSE");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsGenFlagSplit", flagsvals, "TRUE");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsTransFlagRdma", flagrvals, "TRUE");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassSimul", csvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassHandle", chvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassFileid", cfvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassWritever", cwvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassChange", ccvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsClassReaddir", crvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsReadRank", rrankvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsReadOrder", rordvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsWriteRank", wrankvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsWriteOrder", wordvals, "0");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsVarSub", varsubvals, "FALSE");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNfsValidFor", valforvals, "0");

	attrs[i] = NULL;

	dn = nsdb_construct_fsl_dn(nce, fsn_uuid, fsl_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	rc = ldap_add_ext_s(ld, dn, attrs, NULL, NULL);
	free(dn);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to add new FSL entry: %s\n",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully added new FSL entry",
		__func__);
	return FEDFS_OK;
}

/**
 * Add either a new FSN or a new NFS FSN entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
 * @param servername a NUL-terminated C string containing DNS hostname of file server
 * @param serverport port number of file server
 * @param serverpath a NUL-terminated C string containing export pathname to add
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If caller did not provide a serverpath, create a simple fedfsFsl entry.
 * Otherwise, create a full-on fedfsNfsFsl entry.
 */
static FedFsStatus
nsdb_create_fsl_entry_s(LDAP *ld, const char *nce, const char *fsn_uuid,
		const char *fsl_uuid, const char *nsdbname,
		const unsigned short nsdbport, const char *servername,
		const unsigned short serverport, const char *serverpath,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	struct berval xdr_path;

	if (serverpath == NULL) {
		retval = nsdb_create_fsl_add_entry_s(ld, nce, fsn_uuid, fsl_uuid,
							nsdbname, nsdbport,
							servername, serverport,
							ldap_err);
		goto out;
	}

	retval = nsdb_posix_path_to_xdr(serverpath, &xdr_path);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_create_fsl_add_nfs_entry_s(ld, nce, fsn_uuid, fsl_uuid,
						nsdbname, nsdbport,
						servername, serverport,
						&xdr_path, ldap_err);
	free(xdr_path.bv_val);

out:
	return retval;
}

/**
 * Create either a new FSN or a new NFS FSN entry under "nce" (Chapter 5, section 1.3)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param nsdbname a NUL-terminated C string containing DNS hostname of NSDB server
 * @param nsdbport port number of NSDB server
 * @param servername a NUL-terminated C string containing DNS hostname of file server
 * @param serverport port number of file server
 * @param serverpath a NUL-terminated C string containing export pathname to add
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_create_fsl_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		const char *fsl_uuid, const char *nsdbname,
		const unsigned short nsdbport, const char *servername,
		const unsigned short serverport, const char *serverpath,
		unsigned int *ldap_err)
{
	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce == NULL || fsn_uuid == NULL || fsl_uuid == NULL ||
	    nsdbname == NULL || servername == NULL || serverpath == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	return nsdb_create_fsl_entry_s(host->fn_ldap, nce, fsn_uuid, fsl_uuid,
						nsdbname, nsdbport, servername,
						serverport, serverpath, ldap_err);
}

/**
 * Delete an existing FSL entry under "nce" (Chapter 5, section 1.4)
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: fedfsFslUuid="fsl_uuid",fedfsFsnUuid="fsn_uuid","nce"
   changeType: delete
   @endverbatim
 */
static FedFsStatus
nsdb_delete_fsl_entry_s(LDAP *ld, const char *nce,
		const char *fsn_uuid, const char *fsl_uuid,
		unsigned int *ldap_err)
{
	char *dn;
	int rc;

	dn = nsdb_construct_fsl_dn(nce, fsn_uuid, fsl_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	rc = ldap_delete_ext_s(ld, dn, NULL, NULL);
	free(dn);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete FSL entry for %s: %s",
			__func__, fsl_uuid, ldap_err2string(rc));
		switch (rc) {
		case LDAP_NO_SUCH_OBJECT:
			return FEDFS_ERR_NSDB_NOFSL;
		default:
			*ldap_err = rc;
			return FEDFS_ERR_NSDB_LDAP_VAL;
		}
	}

	xlog(D_GENERAL, "%s: Successfully deleted FSL entry for %s",
		__func__, fsl_uuid);
	return FEDFS_OK;
}

/**
 * Delete an existing FSL entry under "nce"
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_fsl_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		const char *fsl_uuid, unsigned int *ldap_err)
{
	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce == NULL || fsn_uuid == NULL || fsl_uuid == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	return nsdb_delete_fsl_entry_s(host->fn_ldap, nce, fsn_uuid,
						fsl_uuid, ldap_err);
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
		const char *attribute, const char *value,
		unsigned int *ldap_err)
{
	struct berval newval;
	FedFsStatus retval;

	if (strcasecmp(attribute, "fedfsNfsPath") == 0) {
		retval = nsdb_posix_path_to_xdr(value, &newval);
		if (retval != FEDFS_OK)
			return retval;
	} else {
		newval.bv_val = (char *)value;
		newval.bv_len = 0;
		if (value != NULL)
			newval.bv_len = (ber_len_t)strlen(value);
	}

	retval = nsdb_modify_attribute_s(ld, dn, attribute,
						&newval, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	xlog(D_CALL, "%s: Successfully updated attribute %s for entry %s",
		__func__, attribute, dn);
	return FEDFS_OK;
}

/**
 * Update an FSL entry under "nce"
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
 * @param fsl_uuid a NUL-terminated C string containing FSL UUID
 * @param attribute a NUL-terminated C string containing the name of an attribute to modify
 * @param value a NUL-terminated C string containing the new value
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_update_fsl_entry_s(LDAP *ld, const char *nce, const char *fsn_uuid,
		const char *fsl_uuid, const char *attribute,
		const char *value, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char *dn;

	dn = nsdb_construct_fsl_dn(nce, fsn_uuid, fsl_uuid);
	if (dn == NULL)
		return FEDFS_ERR_SVRFAULT;

	if (value == NULL)
		retval = nsdb_update_fsl_remove_attribute_s(ld, dn,
							attribute, ldap_err);
	else
		retval = nsdb_update_fsl_update_attribute_s(ld, dn,
							attribute,
							value, ldap_err);

	free(dn);
	return retval;
}

/**
 * Update an FSL entry under "nce" (Chapter 5, section 1.5)
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param fsn_uuid a NUL-terminated C string containing FSN UUID
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
nsdb_update_fsl_s(nsdb_t host, const char *nce, const char *fsn_uuid,
		const char *fsl_uuid, const char *attribute,
		const char *value, unsigned int *ldap_err)
{
	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	if (nce == NULL || fsn_uuid == NULL || fsl_uuid == NULL ||
	    attribute == NULL) {
		xlog(L_ERROR, "%s: Invalid parameter", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	return nsdb_update_fsl_entry_s(host->fn_ldap, nce, fsn_uuid,
						fsl_uuid, attribute, value,
						ldap_err);
}

/**
 * Verify that "nce" is present in a list of naming contexts
 *
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param contexts is a NULL-terminated array of NUL-terminated C strings containing naming contexts
 * @return true if "nce" is contained in the "contexts" list
 */
static _Bool
nsdb_create_nce_verify_naming_contexts(const char *nce, char **contexts)
{
	int i;

	for (i = 0; contexts[i] != NULL; i++)
		if (strcmp(nce, contexts[i]) == 0)
			return true;
	return false;
}

/**
 * Add a default top-level NSDB container entry to the target LDAP server.
 *
 * @param ld an initialized LDAP server descriptor
 * @param aci if true, then an ACI attribute is also added
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: o=fedfs
   changeType: add
   objectClass: top
   objectClass: organization
   objectClass: fedfsNsdbContainerInfo
   o: fedfs
   fedfsNcePrefix:
   description: FedFS NSDB Container
   @endverbatim
 *
 */
static FedFsStatus
nsdb_create_nce_add_default_entry_s(LDAP *ld, const _Bool aci,
		unsigned int *ldap_err)
{
	char *ocvals[3], *ovals[2], *prefixvals[2], *descvals[2], *acivals[2];
	LDAPMod attr[6], *attrs[7];
	int i, rc;

	for (i = 0; i < 7; i++)
		attrs[i] = &attr[i];
	i = 0;

	attr[i].mod_op = 0;
	attr[i].mod_type = "objectClass";
	attr[i].mod_values = ocvals;
	ocvals[0] = "organization";
	ocvals[1] = "fedfsNsdbContainerInfo";
	ocvals[2] = NULL;
	i++;

	nsdb_init_add_attribute(attrs[i++],
				"o", ovals, "fedfs");
	nsdb_init_add_attribute(attrs[i++],
				"fedfsNcePrefix", prefixvals, "");
	nsdb_init_add_attribute(attrs[i++],
				"description", descvals, "FedFS NSDB Container");

	/* Some LDAP servers require a default ACI so the entry
	 * is visible to everyone */
	if (aci) {
		nsdb_init_add_attribute(attrs[i++],
			"aci", acivals,
			"(targetattr = \"*\") "
			"(version 3.0;acl \"Enable anonymous access\";"
			"allow (read,search,compare)"
			"(userdn = \"ldap:///anyone\");)");
	}

	attrs[i] = NULL;

	rc = ldap_add_ext_s(ld, NSDB_DEFAULT_NCE, attrs, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to add new NCE: %s",
			__func__, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully added new NCE");
	return FEDFS_OK;
}

/**
 * Add an NCE entry
 *
 * @param host an initialized and bound nsdb_t object
 * @param aci true if a world-readable ACI is also required on the new entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_create_nce_s(nsdb_t host, const _Bool aci, unsigned int *ldap_err)
{
	FedFsStatus retval;
	char **contexts;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	/*
	 * Verify that o=fedfs is in the NSDB's namingContexts
	 */
	retval = nsdb_get_naming_contexts_s(host, &contexts, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	if (!nsdb_create_nce_verify_naming_contexts("o=fedfs", contexts)) {
		xlog(D_GENERAL, "%s: o=fedfs is not a naming context "
			"for this NSDB", __func__);
		return FEDFS_ERR_NSDB_NONCE;
	}

	retval = nsdb_create_nce_add_default_entry_s(host->fn_ldap,
							aci, ldap_err);

	nsdb_free_string_array(contexts);
	return retval;
}

/**
 * Turn an existing entry on the server into an NSDB container entry
 *
 * @param ld an initialized LDAP server descriptor
 * @param entry a NUL-terminated C string containing DN of entry to convert
 * @param nceprefix a NUL-terminated C string containing value of new FedFsNcePrefix attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If "nceprefix" is NULL, then assign an empty string value to the
 * FedFsNcePrefix attribute.
 *
 * LDIF equivalent:
 *
 * @verbatim

   dn: "entry"
   changeType: modify
   objectClass: fedfsNsdbContainerInfo
   add: fedfsNcePrefix
   fedfsNcePrefix: "nceprefix"
   @endverbatim
 */
static FedFsStatus
nsdb_create_nce_update_entry_s(LDAP *ld, const char *entry,
		const char *nceprefix, unsigned int *ldap_err)
{
	char *ocvals[2], *prefixvals[2];
	LDAPMod *mods[3];
	LDAPMod mod[2];
	int i, rc;

	for (i = 0; i < 2; i++)
		mods[i] = &mod[i];
	i = 0;

	nsdb_init_mod_attribute(mods[i++],
				"objectClass", ocvals, "fedfsNsdbContainerInfo");
	nsdb_init_mod_attribute(mods[i++],
				"fedfsNcePrefix", prefixvals,
				nceprefix == NULL ? "" : nceprefix);

	mods[i] = NULL;

	rc = ldap_modify_ext_s(ld, entry, mods, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to update %s: %s",
			__func__, entry, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}

	xlog(D_CALL, "%s: Successfully updated %s", __func__, entry);
	return FEDFS_OK;
}

/**
 * Modify an entry to become an NCE entry
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of entry to convert
 * @param nceprefix a NUL-terminated C string containing value of new FedFsNcePrefix attribute
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * If "nceprefix" is NULL, then assign an empty string value to the
 * FedFsNcePrefix attribute.
 */
FedFsStatus
nsdb_update_nce_s(nsdb_t host, const char *nce, const char *nceprefix,
		unsigned int *ldap_err)
{
	FedFsStatus retval = false;
	char **contexts;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	/*
	 * Verify that @nce is in the NSDB's namingContexts
	 */
	retval = nsdb_get_naming_contexts_s(host, &contexts, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	if (!nsdb_create_nce_verify_naming_contexts(nce, contexts)) {
		xlog(D_GENERAL, "%s: %s is not a naming context "
			"for this NSDB", __func__, nce);
		return FEDFS_ERR_NSDB_NONCE;
	}

	retval = nsdb_create_nce_update_entry_s(host->fn_ldap, nce,
						nceprefix, ldap_err);

	nsdb_free_string_array(contexts);
	return retval;
}

/**
 * Check that "nce" is an actual FedFS NCE
 *
 * @param ld an initialized LDAP server descriptor
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * ldapsearch equivalent:
 *
 * @verbatim
 *
   ldapsearch -b "nce" -s base objectClass=fedfsNsdbContainerInfo
   @endverbatim
 */
static FedFsStatus
nsdb_delete_nce_check_entry_s(LDAP *ld, const char *nce,
		unsigned int *ldap_err)
{
	LDAPMessage *response;
	FedFsStatus retval;
	int rc;

	rc = ldap_search_ext_s(ld, nce, LDAP_SCOPE_BASE,
				"objectClass=fedfsNsdbContainerInfo",
				NULL, 0, NULL, NULL, NULL, LDAP_NO_LIMIT,
				&response);
	switch (rc) {
	case LDAP_SUCCESS:
		break;
	case LDAP_NO_SUCH_OBJECT:
		xlog(D_GENERAL, "%s: %s is not an NSDB container entry",
			__func__, nce);
		return FEDFS_ERR_NSDB_NONCE;
	default:
		xlog(D_GENERAL, "%s: Failed to retrieve NCE %s: %s",
			__func__, nce, ldap_err2string(rc));
		*ldap_err = rc;
		return FEDFS_ERR_NSDB_LDAP_VAL;
	}
	if (response == NULL) {
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		return FEDFS_ERR_NSDB_RESPONSE;
	}

	retval = FEDFS_ERR_NSDB_NONCE;
	rc = ldap_count_messages(ld, response);
	switch (rc) {
	case -1:
		xlog(D_GENERAL, "%s: Empty LDAP response", __func__);
		break;
	case 1:
		xlog(D_GENERAL, "%s: Entry %s is not an "
			"NSDB Container Entry", __func__, nce);
		break;
	default:
		xlog(D_CALL, "%s: Entry %s is an "
			"NSDB Container Entry", __func__, nce);
		retval = FEDFS_OK;
		break;
	}

	ldap_msgfree(response);
	return retval;
}

/**
 * Delete a FedFS NCE
 *
 * @param host an initialized and bound nsdb_t object
 * @param nce a NUL-terminated C string containing DN of NSDB container entry
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_nce_s(nsdb_t host, const char *nce, unsigned int *ldap_err)
{
	FedFsStatus retval;
	int rc;

	if (host->fn_ldap == NULL) {
		xlog(L_ERROR, "%s: NSDB not open", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = nsdb_delete_nce_check_entry_s(host->fn_ldap,
						nce, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	rc = ldap_delete_ext_s(host->fn_ldap, nce, NULL, NULL);
	if (rc != LDAP_SUCCESS) {
		xlog(D_GENERAL, "%s: Failed to delete NCE %s: %s",
			__func__, nce, ldap_err2string(rc));
		switch (rc) {
		case LDAP_NO_SUCH_OBJECT:
			return FEDFS_ERR_NSDB_NONCE;
		default:
			*ldap_err = rc;
			return FEDFS_ERR_NSDB_LDAP_VAL;
		}
	}

	xlog(D_GENERAL, "%s: Successfully deleted NCE %s",
		__func__, nce);
	return FEDFS_OK;
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
		return FEDFS_ERR_SVRFAULT;
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
		return FEDFS_ERR_SVRFAULT;
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
