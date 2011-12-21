/**
 * @file src/libnsdb/path.c
 * @brief Encode and decode FedFS pathnames
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

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ldap.h>

#include <netinet/in.h>

#include "nsdb.h"
#include "junction.h"
#include "xlog.h"

#define STRLEN_SLASH	((size_t)1)	/* strlen("/") */
#define STRLEN_NUL	((size_t)1)	/* strlen("") */

#define XDR_UINT_BYTES	(4)

/**
 * Compute count of XDR 4-octet units from byte count
 *
 * @param bytes number of bytes to convert
 * @return equivalent number of XDR 4-octet units
 */
static inline unsigned int
nsdb_quadlen(const unsigned int bytes)
{
	return (bytes + 3) >> 2;
}

/**
 * Sanitize an incoming POSIX path
 *
 * @param pathname NUL-terminated C string containing a POSIX pathname
 * @return NUL-terminated C string containing sanitized path
 *
 * Caller must free the returned pathname with free(3).
 *
 * Remove multiple sequential slashes and any trailing slashes,
 * but leave "/" by itself alone.
 */
__attribute_malloc__ char *
nsdb_normalize_path(const char *pathname)
{
	size_t i, j, len;
	char *result;

	len = strlen(pathname);
	if (len == 0) {
		xlog(D_CALL, "%s: NULL pathname", __func__);
		return NULL;
	}

	result = malloc(len + 1);
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate pathname buffer",
			__func__);
		return NULL;
	}

	for (i = 0, j = 0; i < len; i++) {
		if (pathname[i] == '/' && pathname[i + 1] == '/')
			continue;
		result[j++] = pathname[i];
	}
	result[j] = '\0';

	if (j > 1 && result[j - 1] == '/')
		result[j - 1] = '\0';

	xlog(D_CALL, "%s: result = '%s'", __func__, result);
	return result;
}

/**
 * Count the number of components in a POSIX pathname
 *
 * @param pathname NUL-terminated C string containing a POSIX pathname
 * @param len OUT: number of bytes the encoded XDR stream will consume
 * @param cnt OUT: component count
 * @return true when successful
 */
static _Bool
nsdb_count_components(const char *pathname, size_t *len,
		unsigned int *cnt)
{
	char *start, *component;
	unsigned int count;
	size_t length;

	/* strtok(3) will tromp on the string */
	start = strdup(pathname);
	if (start == NULL) {
		xlog(L_ERROR, "%s: Failed to duplicate pathname",
			__func__);
		return false;
	}

	length = XDR_UINT_BYTES;
	count = 0;
	component = start;
	for ( ;; ) {
		char *next;

		if (*component == '/')
			component++;
		if (*component == '\0')
			break;
		next = strchrnul(component, '/');
		length += XDR_UINT_BYTES + (nsdb_quadlen(next - component) << 2);
		count++;

		if (*next == '\0')
			break;
		component = next;
	}

	free(start);

	xlog(D_CALL, "%s: length = %zu, count = %u, path = '%s'",
		__func__, length, count, pathname);
	*len = length;
	*cnt = count;
	return true;
}

/**
 * Predicate: is input character set for a POSIX pathname valid UTF-8?
 *
 * @param pathname NUL-terminated C string containing a POSIX path
 * @return true if the string is valid UTF-8
 *
 * XXX: implement this
 */
_Bool
nsdb_pathname_is_utf8(__attribute__((unused)) const char *pathname)
{
	return true;
}

/**
 * XDR encode a POSIX path name
 *
 * @param pathname NUL-terminated C string containing a POSIX path
 * @param xdr_path OUT: pointer to XDR-encoded path in a berval
 * @return a FedFsStatus code
 *
 * Caller must free xdr_path->bv_val with free(3)
 *
 * The XDR encoded result is described by the NSDB protocol draft as
 * "an XDR encoded variable length array of variable length opaque
 * data."  The result of this encoding is a byte stream.
 */
FedFsStatus
nsdb_posix_path_to_xdr(const char *pathname, struct berval *xdr_path)
{
	char *component, *normalized;
	unsigned int i, count;
	uint32_t *xdrbuf;
	size_t length;

	if (pathname == NULL || xdr_path == NULL) {
		xlog(L_ERROR, "%s: Invalid argument", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (!nsdb_pathname_is_utf8(pathname)) {
		xlog(D_GENERAL, "%s: Bad character in pathname", __func__);
		return FEDFS_ERR_BADCHAR;
	}

	normalized = nsdb_normalize_path(pathname);
	if (normalized == NULL)
		return FEDFS_ERR_SVRFAULT;

	/*
	 * Calculate the number of path components and the
	 * number of bytes in the encoded result so that a
	 * buffer for the result can be allocated.
	 */
	if (!nsdb_count_components(normalized, &length, &count))
		return FEDFS_ERR_BADNAME;

	/*
	 * Flatten the POSIX path into an encoded XDR stream
	 * stored in the allocated buffer
	 */
	xdrbuf = malloc(length);
	if (xdrbuf == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate XDR buffer",
			__func__);
		free(normalized);
		return FEDFS_ERR_SVRFAULT;
	}
	memset(xdrbuf, 0, length);

	i = 1;
	xdrbuf[i] = htonl(count);
	component = normalized;
	for ( ;; ) {
		char *next;

		if (*component == '/')
			component++;
		if (*component == '\0')
			break;
		next = strchrnul(component, '/');
		length = next - component;

		xdrbuf[i++] = htonl(length);
		memcpy(&xdrbuf[i], component, length);
		i += nsdb_quadlen(length);

		if (*next == '\0')
			break;
		component = next;
	}

	xdr_path->bv_val = (char *)xdrbuf;
	xdr_path->bv_len = (ber_len_t)(i << 2);

	free(normalized);
	return FEDFS_OK;
}

/**
 * XDR decode an XDR byte stream into a POSIX path name
 *
 * @param xdr_path berval containing XDR-encoded path
 * @param pathname OUT: pointer to NUL-terminated UTF-8 C string containing a POSIX path name
 * @return a FedFsStatus code
 *
 * Caller must free "pathname" with free(3)
 *
 * Note that the count of array items is ignored.  It's not needed to
 * decode the XDR byte stream correctly.  The only important thing is
 * to avoid reading outside the passed-in XDR byte stream.  That can
 * result in incorrect results or even segfaults.
 */
FedFsStatus
nsdb_xdr_to_posix_path(struct berval *xdr_path, char **pathname)
{
	const unsigned int buflen = nsdb_quadlen((unsigned int)xdr_path->bv_len);
	uint32_t *buf = (uint32_t *)xdr_path->bv_val;
	unsigned int i;
	uint32_t size;
	size_t length;
	char *result;

	if (xdr_path == NULL || pathname == NULL) {
		xlog(L_ERROR, "%s: Invalid argument", __func__);
		return FEDFS_ERR_INVAL;
	}

	i = 1;		/* skip the count of array elements */
	length = STRLEN_NUL;
	for ( ;; ) {
		length += STRLEN_SLASH;
		if (i >= buflen)
			break;

		size = ntohl(buf[i++]);
		i += nsdb_quadlen(size);
		if (i == buflen)
			break;
		if (i > buflen) {
			xlog(D_GENERAL, "%s: XDR decoding error", __func__);
			return FEDFS_ERR_BADXDR;
		}

		length += size;
	}

	result = malloc(length);
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate pathname buffer",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}
	result[0] = '\0';

	i = 1;		/* skip the count of elements */
	for ( ;; ) {
		strcat(result, "/");
		if (i == buflen)
			break;

		size = ntohl(buf[i++]);
		strncat(result, (char *)&buf[i], size);
		i += nsdb_quadlen(size);
		if (i == buflen)
			break;
	}

	if (!nsdb_pathname_is_utf8(result)) {
		xlog(D_GENERAL, "%s: Bad character in pathname", __func__);
		free(result);
		return FEDFS_ERR_BADCHAR;
	}

	*pathname = result;
	return FEDFS_OK;
}

/**
 * Free a FedFsPathComponent allocated by nsdb_new_component
 *
 * @param fcomp pointer to FedFsPathComponent to free
 */
static void
nsdb_free_component(FedFsPathComponent *fcomp)
{
	free(fcomp->utf8string_val);
	fcomp->utf8string_val = NULL;
	fcomp->utf8string_len = 0;
}

/**
 * Allocate a FedFsPathComponent
 *
 * @param component UTF-8 C string containing one path component
 * @param length count of bytes in "component"
 * @param fcomp OUT: newly allocated FedFsPathComponent; caller must free with nsdb_free_component
 * @return true if successful, otherwise false
 */
static _Bool
nsdb_new_component(const char *component, size_t length,
		FedFsPathComponent *fcomp)
{
	fcomp->utf8string_val = strndup(component, length);
	if (fcomp->utf8string_val == NULL)
		return false;
	fcomp->utf8string_len = length;
	return true;
}

/**
 * Free resources associated with a FedFsPathName
 *
 * @param fpath pointer to FedFsPathName
 */
void
nsdb_free_fedfspathname(FedFsPathName *fpath)
{
	unsigned int i;

	for (i = 0; i < fpath->FedFsPathName_len; i++)
		nsdb_free_component(&fpath->FedFsPathName_val[i]);
	free(fpath->FedFsPathName_val);
}

/**
 * Construct a FedFsPathName from a C string
 *
 * @param pathname NUL-terminated C string containing a POSIX pathname
 * @param fpath OUT: pointer to FedFsPathName in which to construct path
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_posix_to_fedfspathname(const char *pathname, FedFsPathName *fpath)
{
	char *normalized, *component;
	unsigned int i, count;
	size_t length;

	if (!nsdb_pathname_is_utf8(pathname)) {
		xlog(D_GENERAL, "%s: Bad character in pathname", __func__);
		return FEDFS_ERR_BADCHAR;
	}

	normalized = nsdb_normalize_path(pathname);
	if (normalized == NULL)
		return FEDFS_ERR_SVRFAULT;

	if (!nsdb_count_components(normalized, &length, &count))
		return FEDFS_ERR_BADNAME;

	/* The path "/" MUST be encoded as an array with zero components. */
	if (count == 0) {
		fpath->FedFsPathName_val = NULL;
		fpath->FedFsPathName_len = 0;
		return FEDFS_OK;
	}

	fpath->FedFsPathName_val = calloc(count, sizeof(FedFsPathComponent));
	if (fpath->FedFsPathName_val == NULL)
		return FEDFS_ERR_SVRFAULT;
	fpath->FedFsPathName_len = count;

	i = 0;
	component = normalized;
	for (i = 0; ; i++) {
		char *next;

		if (*component == '/')
			component++;
		if (*component == '\0')
			break;
		next = strchrnul(component, '/');
		length = next - component;

		if (!nsdb_new_component(component,
				length, &fpath->FedFsPathName_val[i]))
			goto out_err;

		if (*next == '\0')
			break;
		component = next;
	}

	return FEDFS_OK;

out_err:
	xlog(D_GENERAL, "%s: Failed to allocate new pathname component",
		__func__);
	nsdb_free_fedfspathname(fpath);
	return FEDFS_ERR_SVRFAULT;
}

/**
 * Construct a local Posix-style path from a FedFsPathName 
 *
 * @param fpath FedFsPathName from which to construct path
 * @param pathname OUT: pointer to NUL-terminated UTF-8 C string containing a Posix-style path
 * @return a FedFsStatus code
 *
 * Caller must free the returned pathname with free(3).
 *
 * NB: The use of fixed constants for NAME_MAX and PATH_MAX are required
 *     here because, on the client side, the pathname likely does not
 *     exist, so pathconf(3) cannot be used.
 */
FedFsStatus
nsdb_fedfspathname_to_posix(const FedFsPathName fpath, char **pathname)
{
	unsigned int i;
	char *result;

	result = malloc(PATH_MAX);
	if (result == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate buffer for result",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}
	result[0] = '\0';

	if (fpath.FedFsPathName_len == 0) {
		xlog(D_GENERAL, "%s: Zero-component pathname", __func__);
		strcat(result, "/");
		*pathname = result;
		return FEDFS_OK;
	}

	for (i = 0; i < fpath.FedFsPathName_len; i++) {
		FedFsPathComponent fcomp = fpath.FedFsPathName_val[i];
		unsigned int len = fcomp.utf8string_len;
		char *component = fcomp.utf8string_val;

		if (len == 0) {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			free(result);
			return FEDFS_ERR_BADNAME;
		}

		if (len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component length too long",
				__func__);
			free(result);
			return FEDFS_ERR_NAMETOOLONG;
		}

		if (strchr(component, '/') != NULL) {
			xlog(D_GENERAL, "%s: Local separator "
				"character found in component",
				__func__);
			free(result);
			return FEDFS_ERR_BADNAME;
		}

		if (strlen(result) + STRLEN_SLASH + len >= PATH_MAX) {
			xlog(D_GENERAL, "%s: FedFsPathName "
				"too long", __func__);
			free(result);
			return FEDFS_ERR_NAMETOOLONG;
		}

		strcat(result, "/");
		strcat(result, component);
	}

	if (!nsdb_pathname_is_utf8(result)) {
		xlog(D_GENERAL, "%s: Bad character in pathname", __func__);
		free(result);
		return FEDFS_ERR_BADCHAR;
	}

	*pathname = nsdb_normalize_path(result);
	free(result);
	if (*pathname == NULL)
		return FEDFS_ERR_SVRFAULT;
	return FEDFS_OK;
}
