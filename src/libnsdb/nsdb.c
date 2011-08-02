/**
 * @file src/libnsdb/nsdb.c
 * @brief Manage nsdb_t objects
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
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <idna.h>
#include <uuid/uuid.h>

#include "fedfs.h"
#include "nsdb.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Environment variable containing default NSDB hostname
 */
#define NSDB_NAME_ENV		"FEDFS_NSDB_HOST"
/* Solaris: FEDFS_ADMIN_HOST for the admin tools */

/**
 * Environment variable containing default NSDB port number
 */
#define NSDB_PORT_ENV		"FEDFS_NSDB_PORT"

/**
 * Environment variable containing default LDAP bind DN for NSDB
 * administrative operations
 */
#define NSDB_BINDDN_ENV		"FEDFS_NSDB_ADMIN"

/**
 * Environment variable containing default NCE DN for NSDB
 */
#define NSDB_NCE_ENV		"FEDFS_NSDB_NCE"

/**
 * Environment variable containing default password for NSDB
 * XXX: not yet implemented
 */
#define NSDB_PASSWORD_ENV	"FEDFS_NSDB_PASSWD"


/**
 * Stores pathname of directory containing fedfsd persistent state
 */
char fedfs_base_dirname[PATH_MAX + 1] =
			FEDFS_DEFAULT_STATEDIR;

/**
 * Stores pathname of directory containing NSDB x509v3 certs
 */
char fedfs_nsdbcerts_dirname[PATH_MAX + 1] =
			FEDFS_DEFAULT_STATEDIR "/" FEDFS_NSDBCERT_DIR;

/**
 * Stores pathname of database containing fedfsd persistent state
 */
static char fedfs_db_filename[PATH_MAX] =
			FEDFS_DEFAULT_STATEDIR "/" FEDFS_DATABASE_FILE;

/**
 * Set pathname of parent
 *
 * @param parentdir NUL-terminated C string containing pathname to on-disk state, or NULL
 * @return true if "parentdir" was valid; otherwise false
 *
 * This runs before logging is set up, so error messages are
 * always directed to stderr.
 */
_Bool
nsdb_set_parentdir(const char *parentdir)
{
	static char buf[PATH_MAX];
	struct stat st;
	char *path;
	int len;

	xlog(D_CALL, "%s: Setting up %s as our fedfs directory",
		__func__, parentdir);

	/* First: test length of name and whether it exists */
	if (lstat(parentdir, &st) == -1) {
		xlog(L_ERROR, "Failed to stat %s: %m", parentdir);
		return false;
	}
	if (!S_ISDIR(st.st_mode)) {
		xlog(L_ERROR, "%s is not a directory", parentdir);
		return false;
	}

	/* Ensure we have a clean directory pathname */
	strncpy(buf, parentdir, sizeof(buf));
	path = dirname(buf);
	if (*path == '.') {
		xlog(L_ERROR, "Unusable pathname %s",
				parentdir);
		return false;
	}

	len = snprintf(buf, sizeof(buf), "%s/%s", parentdir, FEDFS_DATABASE_FILE);
	if (len > PATH_MAX) {
		xlog(L_ERROR, "Fedfsd database pathname is too long");
		return false;
	}
	strcpy(fedfs_db_filename, buf);

	len = snprintf(buf, sizeof(buf), "%s/%s", parentdir, FEDFS_NSDBCERT_DIR);
	if (len > PATH_MAX) {
		xlog(L_ERROR, "Fedfsd cert directory pathname is too long");
		return false;
	}
	strcpy(fedfs_nsdbcerts_dirname, buf);

	strncpy(fedfs_base_dirname, parentdir, sizeof(fedfs_base_dirname));

	return true;
}

/**
 * Predicate: Does parent directory refer to default FedFS state directory?
 *
 * @return true if active fedfsd directory is same as default
 */
_Bool
nsdb_is_default_parentdir(void)
{
	_Bool retval;

	retval = (strcmp(fedfs_base_dirname, FEDFS_DEFAULT_STATEDIR) == 0);
	xlog(D_CALL, "%s: Using %sbase dirname %s",
				__func__, retval ? " " : "default ",
				fedfs_base_dirname);
	return retval;
}

/**
 * Create database table for tracking NSDB data
 *
 * @param db an open sqlite3 database descriptor
 * @return true if table was created or already exists
 */
static _Bool
nsdb_create_tables(sqlite3 *db)
{
	return fedfs_create_table(db, "nsdbs",
				"nsdbName TEXT, "
				"nsdbPort INTEGER, "
				"securityType INTEGER, "
				"securityFilename TEXT, "
				"defaultBindDN TEXT, "
				"defaultNCE TEXT, "
				"followReferrals INTEGER, "
				"UNIQUE (nsdbName,nsdbPort)");
}

/**
 * Ensure database file and tables exist
 *
 * @return true if successful
 */
_Bool
nsdb_init_database(void)
{
	bool_t retval;
	char *err_msg;
	sqlite3 *db;
	int rc;

	xlog(D_CALL, "%s: Initializing database", __func__);

	retval = false;
	db = fedfs_open_db(fedfs_db_filename,
				SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	if (db == NULL)
		goto out;

	/*
	 * Don't delete the journal file after each transaction.
	 * This provides better performance and crash robustness.
	 */
	err_msg = NULL;
	rc = sqlite3_exec(db, "PRAGMA journal_mode=TRUNCATE;", NULL, 0, &err_msg);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to enable persistent journaling: %s",
				err_msg);
		sqlite3_free(err_msg);
		goto out_close;
	}

	if (!nsdb_create_tables(db))
		goto out;

	retval = true;

out_close:
	fedfs_close_db(db);

out:
	return retval;
}

/**
 * Return nsdb_t's hostname
 *
 * @param host pointer to initialized nsdb_t
 * @return NUL-terminated C string containing NSDB's hostname
 *
 * Lifetime of this string is the same as the lifetime of the
 * nsdb_t.  Caller must not free this string, and must not use
 * it after the nsdb_t is freed.
 */
const char *nsdb_hostname(const nsdb_t host)
{
	return host->fn_hostname;
}

/**
 * Return length of nsdb_t's hostname, in bytes
 *
 * @param host pointer to initialized nsdb_t
 * @return NUL-terminated C string containing NSDB's hostname
 */
size_t nsdb_hostname_len(const nsdb_t host)
{
	return strlen(host->fn_hostname);
}

/**
 * Return nsdb_t's port
 *
 * @param host pointer to initialized nsdb_t struct
 * @return NSDB's port number
 */
unsigned short nsdb_port(const nsdb_t host)
{
	return host->fn_port;
}

/**
 * Convert string form of integer into an IP port number
 *
 * @param string a NUL-terminated C string containing number to convert
 * @param port OUT: converted value
 * @return true if a valid port number was obtained, otherwise false
 */
_Bool
nsdb_parse_port_string(const char *string, unsigned short *port)
{
	unsigned long tmp;
	char *endptr;

	if (string == NULL || *string == '\0')
		return false;

	errno = 0;
	tmp = strtoul(string, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || tmp > UINT16_MAX)
		return false;

	*port = (unsigned short)tmp;
	return true;
}

/**
 * Predicate: is input character set for a hostname valid UTF-8?
 *
 * @param hostname NUL-terminated UTF-8 C string containing hostname to check
 * @return true if it can be converted to a valid U-label
 */
_Bool
nsdb_is_hostname_utf8(const char *hostname)
{
	_Bool retval = true;
	char *output;
	int error;

	error = idna_to_ascii_8z(hostname, &output, IDNA_USE_STD3_ASCII_RULES);
	if (error != IDNA_SUCCESS) {
		xlog(D_GENERAL, "%s: %s", __func__, idna_strerror(error));
		retval = false;
	}
	free(output);
	return retval;
}

/**
 * Return NSDB's default bind DN
 *
 * @param host an instantiated nsdb_t object
 * @return a NUL-terminated UTF-8 string containing an LDAP bind DN
 *
 * Lifetime of this string is the same as the lifetime of the
 * nsdb_t.  Caller must not free this string, and must not use
 * it after the nsdb_t is freed.
 */
const char *
nsdb_default_binddn(const nsdb_t host)
{
	return host->fn_default_binddn;
}

/**
 * Return NSDB's default NCE
 *
 * @param host an instantiated nsdb_t object
 * @return a NUL-terminated UTF-8 string containing an NCE DN
 *
 * Lifetime of this string is the same as the lifetime of the
 * nsdb_t.  Caller must not free this string, and must not use
 * it after the nsdb_t is freed.
 */
const char *
nsdb_default_nce(const nsdb_t host)
{
	return host->fn_default_nce;
}

/**
 * Return NSDB's followReferral flag
 *
 * @param host an instantiated nsdb_t object
 * @return a Boolean indicating whether follow LDAP referrals
 */
_Bool
nsdb_follow_referrals(const nsdb_t host)
{
	return host->fn_follow_referrals;
}

/**
 * Retrieve NSDB-related environment variables
 *
 * @param nsdbname OUT: pointer to statically allocated NUL-terminated C string containing NSDB hostname
 * @param nsdbport OUT: pointer to unsigned short NSDB port number
 * @param binddn OUT: pointer to statically allocated NUL-terminated C string containing NSDB bind DN
 * @param nce OUT: pointer to statically allocated NUL-terminated C string containing NSDB container entry DN
 *
 * Any of the returned strings can be NULL pointers, if those
 * variables do not appear in this process's environment.
 * "nsdbport" will contain the value LDAP_PORT if no environment
 * variable specifies an NSDB port number.
 */
void
nsdb_env(char **nsdbname, unsigned short *nsdbport, char **binddn,
		char **nce)
{
	if (nsdbname != NULL)
		*nsdbname = getenv(NSDB_NAME_ENV);
	if (nsdbport != NULL) {
		if (!nsdb_parse_port_string(getenv(NSDB_PORT_ENV),
						nsdbport))
			*nsdbport = LDAP_PORT;
	}
	if (binddn != NULL)
		*binddn = getenv(NSDB_BINDDN_ENV);
	if (nce != NULL)
		*nce = getenv(NSDB_NCE_ENV);
}

/**
 * Construct a new nsdb_t object
 *
 * @param hostname NUL-terminated UTF-8 string containing hostname
 * @param port a putative port number on which to contact the LDAP server
 * @param host OUT: an initialized nsdb_t; caller must free it with nsdb_free_nsdb()
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_new_nsdb(const char *hostname, const unsigned long port, nsdb_t *host)
{
	char *hostname_tmp;
	unsigned short port_tmp;

	if (!nsdb_is_hostname_utf8(hostname))
		return FEDFS_ERR_BADCHAR;
	if (port > UINT16_MAX)
		return FEDFS_ERR_INVAL;

	port_tmp = LDAP_PORT;
	if (port != 0)
		port_tmp = port;

	hostname_tmp = strdup(hostname);
	if (hostname_tmp == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate memory for nsdb object",
				__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	*host = malloc(sizeof(**host));
	if (*host == NULL) {
		free(hostname_tmp);
		xlog(D_GENERAL, "%s: Failed to allocate memory for nsdb object",
				__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	memset(*host, 0, sizeof(**host));
	(*host)->fn_hostname = hostname_tmp;
	(*host)->fn_port = port_tmp;
	return FEDFS_OK;
}

/**
 * Read security data from an existing cert file
 *
 * @param pathname NUL-terminated C string containing pathname of certificate file
 * @param certdata OUT: pointer to buffer containing certificate; caller must free the buffer with free(3)
 * @param certlen OUT: length of buffer containing certificate
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_read_certfile(const char *pathname, char **certdata,
		unsigned int *certlen)
{
	FedFsStatus retval;
	struct stat stb;
	ssize_t size;
	char *buf;
	int fd;

	retval = FEDFS_ERR_SVRFAULT;
	if (lstat(pathname, &stb) == -1) {
		xlog(D_GENERAL, "%s: Failed to stat %s: %m",
			__func__, pathname);
		goto out;
	}

	buf = malloc((size_t)stb.st_size);
	if (buf == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate buffer for %s: %m",
			__func__, pathname);
		goto out;
	}

	fd = open(pathname, O_RDONLY);
	if (fd == -1) {
		xlog(D_GENERAL, "%s: Failed to open %s: %m",
			__func__, pathname);
		goto out;
	}

	size = read(fd, buf, stb.st_size);
	if (size < 0 || (off_t)size != stb.st_size) {
		xlog(D_GENERAL, "%s: Failed to read %s: %m",
			__func__, pathname);
		free(buf);
		(void)close(fd);
		goto out;
	}

	(void)close(fd);
	*certdata = buf;
	*certlen = stb.st_size;
	retval = FEDFS_OK;

out:
	return retval;
}

/**
 * Create a new cert file and store the security data in it
 *
 * @param certdata pointer to buffer containing certificate
 * @param certlen length of certificate in "certdata"
 * @param pathname OUT: pointer to C string containing pathname of new certificate file; caller must free the pathname with free(3)
 * @return a FedFsStatus value
 *
 * On success, FEDFS_OK is returned, a new cert file is created, and the
 * pathname is filled in.
 */
static FedFsStatus
nsdb_new_certfile(const char *certdata, const unsigned int certlen,
		char **pathname)
{
	char pathbuf[PATH_MAX], uuidbuf[FEDFS_UUID_STRLEN];
	FedFsStatus retval;
	ssize_t size;
	int fd, len;
	uuid_t uu;

	/*
	 * We require a guaranteed unique file name for each
	 * new cert.  Use uuid_generate_time(3) to avoid
	 * depleting the local entropy pool.  These files are
	 * private to fedfsd, so no undue exposure of the
	 * local time or MAC address is expected.
	 */
	uuid_generate_time(uu);
	uuid_unparse(uu, uuidbuf);

	retval = FEDFS_ERR_SVRFAULT;
	len = snprintf(pathbuf, sizeof(pathbuf), "%s/%s",
				fedfs_nsdbcerts_dirname, uuidbuf);
	if (len > PATH_MAX) {
		xlog(L_ERROR, "Fedfsd cert directory pathname is too long");
		goto out;
	}

	fd = open(pathbuf, O_WRONLY | O_SYNC | O_CREAT | O_EXCL,
						S_IRUSR | S_IWUSR | S_IRGRP);
	if (fd == -1) {
		xlog(D_GENERAL, "%s: Failed to open %s: %m",
			__func__, pathbuf);
		goto out;
	}

	size = write(fd, certdata, certlen);
	if (size < 0 || (unsigned int)size != certlen) {
		xlog(D_GENERAL, "%s: Failed to write %s: %m",
			__func__, pathbuf);
		(void)unlink(pathbuf);
		(void)close(fd);
		goto out;
	}

	(void)close(fd);

	*pathname = strdup(pathbuf);
	if (*pathname == NULL)
		goto out;

	retval = FEDFS_OK; 
out:
	return retval;
}

/**
 * Read information about an NSDB from our NSDB database
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @return a FedFsStatus code
 *
 * Some fields in the nsdb_t object are populated
 * by this function.
 */
static FedFsStatus
nsdb_read_nsdbname(sqlite3 *db, nsdb_t host)
{
	const char *domainname = host->fn_hostname;
	char *secdata, *def_binddn, *def_nce;
	unsigned int port = host->fn_port;
	int rc, follow_referrals;
	FedFsStatus retval;
	sqlite3_stmt *stmt;

	xlog(D_CALL, "%s: reading info for NSDB '%s'",
			__func__, domainname);

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "SELECT"
			" securityType,securityFilename,defaultBindDN,defaultNCE,followReferrals"
			" FROM nsdbs WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_text(stmt, 1, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(D_GENERAL, "%s: Failed to bind nsdbName %s: %s",
			__func__, domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}
	rc = sqlite3_bind_int(stmt, 2, port);
	if (rc != SQLITE_OK) {
		xlog(D_GENERAL, "%s: Failed to bind port number: %s",
			__func__, sqlite3_errmsg(db));
		goto out_finalize;
	}

	switch (sqlite3_step(stmt)) {
	case SQLITE_ROW:
		xlog(D_GENERAL, "Found row for '%s:%u'", domainname, port);
		secdata = strdup((const char *)sqlite3_column_text(stmt, 1));
		if (secdata == NULL) {
			retval = FEDFS_ERR_SVRFAULT;
			break;
		}
		def_binddn = (char *)sqlite3_column_text(stmt, 2);
		if (def_binddn != NULL) {
			def_binddn = strdup(def_binddn);
			if (def_binddn == NULL) {
				free(secdata);
				retval = FEDFS_ERR_SVRFAULT;
				break;
			}
		}
		def_nce = (char *)sqlite3_column_text(stmt, 3);
		if (def_nce != NULL) {
			def_nce = strdup(def_nce);
			if (def_nce == NULL) {
				free(def_binddn);
				free(secdata);
				retval = FEDFS_ERR_SVRFAULT;
				break;
			}
		}
		follow_referrals = sqlite3_column_int(stmt, 4);
		if (follow_referrals == 0)
			host->fn_follow_referrals = false;
		else
			host->fn_follow_referrals = true;
		host->fn_sectype = sqlite3_column_int(stmt, 0);
		host->fn_secdata = secdata;
		host->fn_default_binddn = def_binddn;
		host->fn_default_nce = def_nce;
		retval = FEDFS_OK;
		break;
	case SQLITE_DONE:
		xlog(D_GENERAL, "%s: Did not find a row for '%s:%u'",
			__func__, domainname, port);
		retval = FEDFS_ERR_NSDB_PARAMS;
		break;
	default:
		xlog(D_GENERAL, "%s: SELECT for '%s:%u' failed on table 'nsdbs': %s",
			__func__, domainname, port, sqlite3_errmsg(db));
		retval = FEDFS_ERR_SVRFAULT;
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Create new NSDB database row
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_new_nsdbname(sqlite3 *db, const nsdb_t host)
{
	const char *domainname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "INSERT INTO nsdbs"
			" (nsdbName,nsdbPort) VALUES(?,?);"))
		goto out;

	rc = sqlite3_bind_text(stmt, 1, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
			domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 2, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Created NSDB info record for '%s:%u' "
			"to nsdbs table", __func__, domainname, port);
		retval = FEDFS_OK;
		break;
	case SQLITE_CONSTRAINT:
		xlog(D_CALL, "%s: NSDB info for '%s:%u' already exists",
			__func__, domainname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to create NSDB info record for '%s:%u': %s",
			domainname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Update information about an NSDB in our NSDB database
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @param sectype an integer value representing the security type
 * @param secdata a NUL-terminated UTF-8 C string containing the name of a file containing security data
 * @return a FedFsStatus code
 *
 * Information is copied from the nsdb_t object to the cert store.
 */
static FedFsStatus
nsdb_update_nsdbname(sqlite3 *db, const nsdb_t host,
		unsigned int sectype, const char *secdata)
{
	const char *domainname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "UPDATE nsdbs "
			" SET securityType=?,securityFilename=?"
			"WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_int(stmt, 1, sectype);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind connection security value: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_text(stmt, 2, secdata, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind security data value: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_text(stmt, 3, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
			domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 4, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Updated NSDB info record for '%s:%u' "
			"to nsdbs table", __func__, domainname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to update NSDB info record for '%s:%u': %s",
			domainname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Update an NSDB's default bind DN
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @param binddn a NUL-terminated UTF-8 string containing new bind DN
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_update_nsdb_default_binddn(sqlite3 *db, const nsdb_t host,
		const char *binddn)
{
	const char *domainname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "UPDATE nsdbs SET defaultBindDN=?"
			" WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_text(stmt, 1, binddn, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind default bind DN%s: %s",
			binddn, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_text(stmt, 2, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
			domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 3, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Updated default bind DN for '%s:%u' "
			"to nsdbs table", __func__, domainname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to update default bind DN for '%s:%u': %s",
			domainname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Update an NSDB's default NCE
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @param nce a NUL-terminated UTF-8 string containing new NCE DN
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_update_nsdb_default_nce(sqlite3 *db, const nsdb_t host,
		const char *nce)
{
	const char *domainname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "UPDATE nsdbs SET defaultNCE=?"
			" WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_text(stmt, 1, nce, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind default NCE DN%s: %s",
			nce, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_text(stmt, 2, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
			domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 3, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Updated default NCE DN for '%s:%u' "
			"to nsdbs table", __func__, domainname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to update default NCE DN for '%s:%u': %s",
			domainname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Update an NSDB's followReferrals flag
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @param follow_referrals true if we're allowed to follow referrals from this NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_update_nsdb_follow_referrals(sqlite3 *db, const nsdb_t host,
		const _Bool follow_referrals)
{
	const char *domainname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "UPDATE nsdbs SET followReferrals=?"
			" WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_int(stmt, 1, follow_referrals ? 1 : 0);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind follow referrals flag: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_text(stmt, 2, domainname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
			domainname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 3, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
			sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Updated referrals flag for '%s:%u' "
			"to nsdbs table", __func__, domainname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to update referrals flag for '%s:%u': %s",
			domainname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Delete information about an NSDB in our NSDB database
 *
 * @param db an open sqlite3 database descriptor
 * @param host an instantiated nsdb_t object
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_delete_nsdbname(sqlite3 *db, const nsdb_t host)
{
	const char *hostname = host->fn_hostname;
	const int port = host->fn_port;
	sqlite3_stmt *stmt;
	FedFsStatus retval;
	int rc;

	/*
	 * Unfortunately, this simple SQL can't tell us if the row
	 * actually existed before the DELETE.  The result is the
	 * same whether there was a matching row or not.
	 */
	retval = FEDFS_ERR_IO;
	if (!fedfs_prepare_stmt(db, &stmt, "DELETE FROM nsdbs "
				"WHERE nsdbName=? and nsdbPort=?;"))
		goto out;

	rc = sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_STATIC);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind NSDB hostname %s: %s",
				hostname, sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_bind_int(stmt, 2, port);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to bind port number: %s",
				sqlite3_errmsg(db));
		goto out_finalize;
	}

	rc = sqlite3_step(stmt);
	switch (rc) {
	case SQLITE_DONE:
		xlog(D_CALL, "%s: Deleted NSDB info record for '%s:%u' "
			"in the nsdbs table", __func__, hostname, port);
		retval = FEDFS_OK;
		break;
	default:
		xlog(L_ERROR, "Failed to delete NSDB info record for '%s:%u': %s",
			hostname, port, sqlite3_errmsg(db));
	}

out_finalize:
	fedfs_finalize_stmt(stmt);
out:
	return retval;
}

/**
 * Read NSDB info for "host" from NSDB database
 *
 * @param host an instantiated nsdb_t object
 * @param sec buffer for returned connection data
 * @return a FedFsStatus code
 *
 * On success, FEDFS_OK is returned, a fresh nsdb_t is returned, and
 * the sectype and secdata fields in the passed-in fedfs_secdata object
 * are filled in.
 */
static FedFsStatus
nsdb_read_nsdbparams(nsdb_t host, struct fedfs_secdata *sec)
{
	FedFsStatus retval;
	sqlite3 *db;

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READONLY);
	if (db == NULL)
		goto out;

	retval = nsdb_read_nsdbname(db, host);
	if (retval != FEDFS_OK)
		goto out_close;

	if (sec != NULL) {
		if (host->fn_sectype != FEDFS_SEC_NONE) {
			retval = nsdb_read_certfile(host->fn_secdata,
					&sec->data, &sec->len);
			if (retval != FEDFS_OK)
				goto out_close;
		} else {
			sec->data = NULL;
			sec->len = 0;
		}
		sec->type = host->fn_sectype;
	}

	retval = FEDFS_OK;

out_close:
	fedfs_close_db(db);
out:
	return retval;
}

/**
 * Read NSDB info for "hostname" and "port" from NSDB database
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param host OUT: an initialized nsdb_t object
 * @param sec buffer for returned connection data
 * @return a FedFsStatus code
 *
 * On success, FEDFS_OK is returned, a fresh nsdb_t is returned, and
 * the sectype and secdata fields in the passed-in fedfs_secdata object
 * are filled in.
 */
FedFsStatus
nsdb_lookup_nsdb(const char *hostname, const unsigned short port,
		nsdb_t *host, struct fedfs_secdata *sec)
{
	FedFsStatus retval;
	nsdb_t new;

	retval = nsdb_new_nsdb(hostname, port, &new);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_read_nsdbparams(new, sec);
	if (retval != FEDFS_OK)
		nsdb_free_nsdb(new);
	else
		*host = new;

	return retval;
}

/**
 * Update connection parameters for an NSDB
 *
 * @param host an instantiated nsdb_t object
 * @param sec new connection parameters
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_update_nsdbparams(nsdb_t host, const struct fedfs_secdata *sec)
{
	FedFsStatus retval;
	char *certfile;
	sqlite3 *db;

	xlog(D_CALL, "%s: writing parameters for NSDB '%s'",
			__func__, host->fn_hostname);

	switch (sec->type) {
	case FEDFS_SEC_NONE:
		certfile = strdup("");
		break;
	case FEDFS_SEC_TLS:
		retval = nsdb_new_certfile(sec->data, sec->len,
							&certfile);
		if (retval != FEDFS_OK)
			goto out;
		break;
	default:
		retval = FEDFS_ERR_INVAL;
		goto out;
	}

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READWRITE);
	if (db == NULL) {
		free(certfile);
		goto out;
	}

	retval = nsdb_new_nsdbname(db, host);
	if (retval != FEDFS_OK) {
		free(certfile);
		goto out_close;
	}

	retval = nsdb_update_nsdbname(db, host, sec->type, certfile);
	if (retval != FEDFS_OK) {
		free(certfile);
		goto out_close;
	}

	host->fn_sectype = (unsigned int)sec->type;
	host->fn_secdata = certfile;
	retval = FEDFS_OK;

out_close:
	fedfs_close_db(db);
out:
	return retval;
}

/**
 * Update connection parameters for an NSDB
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param sec buffer containing new connection data
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_update_nsdb(const char *hostname, const unsigned short port,
		const struct fedfs_secdata *sec)
{
	nsdb_t host;
	FedFsStatus retval;

	retval = nsdb_new_nsdb(hostname, port, &host);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_update_nsdbparams(host, sec);

	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Update stored default bind DN for an NSDB
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param binddn NUL-terminated UTF-8 string containing NSDB bind DN
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_update_default_binddn(const char *hostname, const unsigned short port,
		const char *binddn)
{
	FedFsStatus retval;
	nsdb_t host;
	sqlite3 *db;

	retval = nsdb_lookup_nsdb(hostname, port, &host, NULL);
	if (retval != FEDFS_OK)
		return retval;

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READWRITE);
	if (db == NULL)
		goto out;

	retval = nsdb_update_nsdb_default_binddn(db, host, binddn);

	fedfs_close_db(db);
out:
	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Update stored default NCE for an NSDB
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param nce NUL-terminated UTF-8 string containing NCE DN
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_update_default_nce(const char *hostname, const unsigned short port,
		const char *nce)
{
	FedFsStatus retval;
	nsdb_t host;
	sqlite3 *db;

	retval = nsdb_lookup_nsdb(hostname, port, &host, NULL);
	if (retval != FEDFS_OK)
		return retval;

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READWRITE);
	if (db == NULL)
		goto out;

	retval = nsdb_update_nsdb_default_nce(db, host, nce);

	fedfs_close_db(db);
out:
	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Update stored followReferrals flag setting for an NSDB
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param follow_referrals true if we're allowed to follow referrals from this NSDB
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_update_follow_referrals(const char *hostname, const unsigned short port,
		const _Bool follow_referrals)
{
	FedFsStatus retval;
	nsdb_t host;
	sqlite3 *db;

	retval = nsdb_lookup_nsdb(hostname, port, &host, NULL);
	if (retval != FEDFS_OK)
		return retval;

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READWRITE);
	if (db == NULL)
		goto out;

	retval = nsdb_update_nsdb_follow_referrals(db, host, follow_referrals);

	fedfs_close_db(db);
out:
	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Delete connection parameters for an NSDB
 *
 * @param host an instantiated nsdb_t object
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_delete_nsdbparams(nsdb_t host)
{
	FedFsStatus retval;
	sqlite3 *db;

	xlog(D_CALL, "%s: deleting parameters for NSDB '%s'",
			__func__, host->fn_hostname);

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READWRITE);
	if (db == NULL)
		goto out;

	retval = nsdb_delete_nsdbname(db, host);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = FEDFS_OK;

out_close:
	fedfs_close_db(db);
out:
	return retval;
}

/**
 * Enumerate the NSDBs in our NSDB list
 *
 * @param nsdblist OUT: a NULL-terminated array of NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * The caller must free the returned array with nsdb_free_string_array()
 */
FedFsStatus
nsdb_enumerate_nsdbs(char ***nsdblist)
{
	char *err_msg, **result, **resultp;
	int i, rc, ncols, nrows;
	FedFsStatus retval;
	sqlite3 *db;

	retval = FEDFS_ERR_IO;
	db = fedfs_open_db(fedfs_db_filename, SQLITE_OPEN_READONLY);
	if (db == NULL)
		goto out_close;

	rc = sqlite3_get_table(db, "SELECT nsdbName,nsdbPort from nsdbs;",
					&resultp, &nrows, &ncols, &err_msg);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "%s: Failed to read table nsdbs: %s",
			__func__, err_msg);
		sqlite3_free(err_msg);
		goto out_close;
	}

	xlog(D_CALL, "%s: found %d rows, %d columns",
		__func__, nrows, ncols);

	if (nrows == 0) {
		xlog(D_GENERAL, "%s: nsdbs table is empty",
			__func__);
		retval = FEDFS_ERR_NSDB_PARAMS;
		goto out_close;
	}

	if (nrows < 1 || ncols != 2) {
		xlog(L_ERROR, "%s: Returned table had "
			"incorrect table dimensions: (%d, %d)",
			__func__, nrows, ncols);
		goto out_free;
	}

	result = calloc(nrows + 1, sizeof(char *));
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate memory for result",
			__func__);
		goto out_free;
	}

	for (i = 0; i < nrows; i++) {
		char *hostname = resultp[(i + 1) * 2];
		char *port = resultp[(i + 1) * 2 + 1];
		char *tmp;

		tmp = malloc(strlen(hostname) + strlen(":") + strlen(port) + 1);
		if (tmp == NULL) {
			xlog(L_ERROR, "%s: Failed to allocate memory "
				"for result", __func__);
			nsdb_free_string_array(result);
			goto out_free;
		}

		(void)sprintf(tmp, "%s:%s", hostname, port);

		result[i] = tmp;
	}
	result[i] = NULL;

	*nsdblist = result;
	retval = FEDFS_OK;

out_free:
	sqlite3_free_table(resultp);
out_close:
	fedfs_close_db(db);
	return retval;
}

/**
 * Delete connection parameters for an NSDB
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_delete_nsdb(const char *hostname, const unsigned short port)
{
	nsdb_t host;
	FedFsStatus retval;

	retval = nsdb_new_nsdb(hostname, port, &host);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_delete_nsdbparams(host);

	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Bind to an NSDB
 *
 * @param host an initialized nsdb_t object
 * @param binddn NUL-terminated UTF-8 C string containing DN to which to bind
 * @param passwd NUL-terminated UTF-8 C string containing bind password
 * @param ldap_err OUT: possibly an LDAP error code
 * @return a FedFsStatus code
 *
 * This function may ask for a password on stdin if "binddn" is
 * not NULL but "passwd" is NULL.
 *
 * When false is returned, the nsdb_t object remains closed.
 */
FedFsStatus
nsdb_open_nsdb(nsdb_t host, const char *binddn, const char *passwd,
		unsigned int *ldap_err)
{
	FedFsStatus retval;
	LDAP *ld;

	retval = nsdb_open(host->fn_hostname, host->fn_port, &ld, ldap_err);
	if (retval != FEDFS_OK)
		return retval;

	switch (host->fn_sectype) {
	case FEDFS_SEC_NONE:
		break;
	case FEDFS_SEC_TLS:
		retval = nsdb_start_tls(ld, host->fn_secdata, ldap_err);
		if (retval != FEDFS_OK)
			goto out_unbind;
		break;
	default:
		xlog(D_GENERAL, "%s: Host contains invalid sectype",
			__func__);
		retval = FEDFS_ERR_NSDB_AUTH;
		goto out_unbind;
	}

	retval = nsdb_bind(ld, binddn, passwd, ldap_err);
	if (retval != FEDFS_OK)
		goto out_unbind;

	host->fn_ldap = ld;
	return FEDFS_OK;

out_unbind:
	(void)ldap_unbind_ext_s(ld, NULL, NULL);
	return retval;
}

/**
 * Release LDAP resources for this NSDB
 *
 * @param host an initialized and bound nsdb_t object
 */
void
nsdb_close_nsdb(nsdb_t host)
{
	(void)ldap_unbind_ext_s(host->fn_ldap, NULL, NULL);
	host->fn_ldap = NULL;
}

/**
 * Free an nsdb_t
 *
 * @param host nsdb_t allocated by nsdb_new_nsdb()
 */
void
nsdb_free_nsdb(nsdb_t host)
{
	if (host == NULL)
		return;

	free(host->fn_hostname);
	free(host->fn_secdata);
	nsdb_free_string_array(host->fn_naming_contexts);
	free(host->fn_default_binddn);
	free(host->fn_default_nce);
	free(host);
}
