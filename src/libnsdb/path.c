/**
 * @file src/libnsdb/path.c
 * @brief Encode and decode FedFS pathnames
 */

/*
 * Copyright 2010, 2011 Oracle.  All rights reserved.
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
#include <uriparser/Uri.h>

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
nsdb_quadlen(unsigned int bytes)
{
	return (bytes + 3) >> 2;
}

/**
 * Bounded search for a character inside a string
 *
 * @param haystack C string to search
 * @param needle character to find
 * @param size number of character in "haystack" to search
 * @return pointer to "needle" in "haystack," or NULL
 */
static const char *
nsdb_strnchr(const char *haystack, char needle, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++)
		if (haystack[i] == needle)
			return &haystack[i];
	return NULL;
}

static FedFsStatus
nsdb_alloc_zero_component_pathname(char ***path_array)
{
	char **result;

	xlog(D_GENERAL, "%s: Zero-component pathname", __func__);

	result = (char **)calloc(1, sizeof(char *));
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate array",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}
	result[0] = NULL;
	*path_array = result;
	return FEDFS_OK;
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
	fpath->FedFsPathName_val = NULL;
	fpath->FedFsPathName_len = 0;
}

/**
 * Construct a local POSIX-style pathname from an array of component strings
 *
 * @param path_array array of pointers to NUL-terminated C strings
 * @param pathname OUT: pointer to NUL-terminated UTF-8 C string containing a POSIX-style path
 * @return a FedFsStatus code
 *
 * Caller must free the returned pathname with free(3).
 */
FedFsStatus
nsdb_path_array_to_posix(char * const *path_array, char **pathname)
{
	char *component, *result;
	unsigned int i, count;
	size_t length, len;

	if (path_array == NULL || pathname == NULL) {
		xlog(L_ERROR, "%s: Invalid argument", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (path_array[0] == NULL) {
		xlog(D_GENERAL, "%s: Zero-component pathname", __func__);
		result = strdup("/");
		if (result == NULL) {
			xlog(D_GENERAL, "%s: Failed to allocate buffer for result",
				__func__);
			return FEDFS_ERR_SVRFAULT;
		}
		*pathname = result;
		return FEDFS_OK;
	}

	for (length = 0, count = 0;
	     path_array[count] != NULL;
	     count++) {
		component = path_array[count];
		len = strlen(component);

		if (len == 0) {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component length too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
		if (strchr(component, '/') != NULL) {
			xlog(D_GENERAL, "%s: Local separator character "
					"found in component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (!nsdb_pathname_is_utf8(component)) {
			xlog(D_GENERAL, "%s: Bad character in component",
				__func__);
			return FEDFS_ERR_BADCHAR;
		}

		length += STRLEN_SLASH + len;

		if (length > PATH_MAX) {
			xlog(D_GENERAL, "%s: Pathname too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
	}

	result = calloc(1, length + 1);
	if (result == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate buffer for result",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; i < count; i++) {
		strcat(result, "/");
		strcat(result, path_array[i]);
	}
	*pathname = nsdb_normalize_path(result);
	free(result);
	if (*pathname == NULL)
		return FEDFS_ERR_SVRFAULT;
	return FEDFS_OK;
}

/**
 * Construct an array of component strings from a local POSIX-style pathname
 *
 * @param pathname NUL-terminated C string containing a POSIX-style pathname
 * @param path_array OUT: pointer to array of pointers to NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * Caller must free "path_array" with nsdb_free_string_array().
 */
FedFsStatus
nsdb_posix_to_path_array(const char *pathname, char ***path_array)
{
	char *normalized, *component, **result;
	unsigned int i, count;
	size_t length;

	if (pathname == NULL || path_array == NULL) {
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

	if (!nsdb_count_components(normalized, &length, &count)) {
		free(normalized);
		return FEDFS_ERR_BADNAME;
	}

	if (count == 0) {
		free(normalized);
		return nsdb_alloc_zero_component_pathname(path_array);
	}

	result = (char **)calloc(count + 1, sizeof(char *));
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate array",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	component = normalized;
	for (i = 0; ; i++) {
		char *next;

		if (*component == '/')
			component++;
		if (*component == '\0')
			break;
		next = strchrnul(component, '/');
		length = next - component;

		result[i] = strndup(component, length);
		if (result[i] == NULL) {
			xlog(D_GENERAL, "%s: Failed to allocate "
					"new pathname component", __func__);
			nsdb_free_string_array(result);
			return FEDFS_ERR_SVRFAULT;
		}

		if (*next == '\0')
			break;
		component = next;
	}

	*path_array = result;
	free(normalized);
	return FEDFS_OK;
}

/**
 * Construct a FedFsPathName from an array of component strings
 *
 * @param path_array array of pointers to NUL-terminated C strings
 * @param fpath OUT: pointer to FedFsPathName in which to construct path
 * @return a FedFsStatus code
 *
 * Caller must free "fpath" with nsdb_free_fedfspathname().
 */
FedFsStatus
nsdb_path_array_to_fedfspathname(char * const *path_array, FedFsPathName *fpath)
{
	unsigned int i, count;
	size_t length, len;
	char *component;

	if (path_array == NULL || fpath == NULL) {
		xlog(L_ERROR, "%s: Invalid argument", __func__);
		return FEDFS_ERR_INVAL;
	}

	/* The path "/" MUST be encoded as an array with zero components. */
	if (path_array[0] == NULL) {
		xlog(D_GENERAL, "%s: Zero-component pathname", __func__);
		fpath->FedFsPathName_val = NULL;
		fpath->FedFsPathName_len = 0;
		return FEDFS_OK;
	}

	for (length = 0, count = 0;
	     path_array[count] != NULL;
	     count++) {
		component = path_array[count];
		len = strlen(component);

		if (len == 0) {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component length too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
		if (strchr(component, '/') != NULL) {
			xlog(D_GENERAL, "%s: Local separator character "
					"found in component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (!nsdb_pathname_is_utf8(component)) {
			xlog(D_GENERAL, "%s: Bad character in component",
				__func__);
			return FEDFS_ERR_BADCHAR;
		}

		length += STRLEN_SLASH + len;

		if (length > PATH_MAX) {
			xlog(D_GENERAL, "%s: Pathname too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
	}

	fpath->FedFsPathName_val = calloc(count + 1, sizeof(FedFsPathComponent));
	if (fpath->FedFsPathName_val == NULL) {
		return FEDFS_ERR_SVRFAULT;
	}
	fpath->FedFsPathName_len = count;

	for (i = 0; i < count; i++) {
		component = path_array[i];
		len = strlen(component);

		if (!nsdb_new_component(component, len,
					&fpath->FedFsPathName_val[i])) {
			xlog(D_GENERAL, "%s: Failed to allocate "
					"new pathname component", __func__);
			nsdb_free_fedfspathname(fpath);
			return FEDFS_ERR_SVRFAULT;
		}
	}

	return FEDFS_OK;
}

/**
 * Construct an array of component strings from a FedFsPathName
 *
 * @param fpath FedFsPathName from which to construct path
 * @param path_array OUT: pointer to array of pointers to NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * Caller must free "path_array" with nsdb_free_string_array().
 *
 * NB: The use of fixed constants for NAME_MAX and PATH_MAX are required
 *     here because, on the client side, the pathname likely does not
 *     exist, so pathconf(3) cannot be used.
 */
FedFsStatus
nsdb_fedfspathname_to_path_array(FedFsPathName fpath, char ***path_array)
{
	char *component, **result;
	FedFsPathComponent fcomp;
	unsigned int i, len;
	size_t length;

	if (path_array == NULL) {
		xlog(L_ERROR, "%s: Invalid argument", __func__);
		return FEDFS_ERR_INVAL;
	}

	if (fpath.FedFsPathName_len == 0)
		return nsdb_alloc_zero_component_pathname(path_array);

	length = 0;
	for (i = 0; i < fpath.FedFsPathName_len; i++) {
		fcomp = fpath.FedFsPathName_val[i];
		len = fcomp.utf8string_len;
		component = fcomp.utf8string_val;

		if (len == 0) {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component length too long",
				__func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
		if (nsdb_strnchr(component, '/', len) != NULL) {
			xlog(D_GENERAL, "%s: Local separator "
				"character found in component",
				__func__);
			return FEDFS_ERR_BADNAME;
		}
		if (!nsdb_pathname_is_utf8(component)) {
			xlog(D_GENERAL, "%s: Bad character in component",
				__func__);
			return FEDFS_ERR_BADCHAR;
		}

		length += STRLEN_SLASH + len;
		if (length > PATH_MAX) {
			xlog(D_GENERAL, "%s: FedFsPathName too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
	}

	result = (char **)calloc(fpath.FedFsPathName_len + 1, sizeof(char *));
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate array",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; i < fpath.FedFsPathName_len; i++) {
		fcomp = fpath.FedFsPathName_val[i];
		len = fcomp.utf8string_len;
		component = fcomp.utf8string_val;

		result[i] = strndup(component, (size_t)len);
		if (result[i] == NULL) {
			xlog(D_GENERAL, "%s: Failed to allocate "
					"new pathname component", __func__);
			nsdb_free_string_array(result);
			return FEDFS_ERR_SVRFAULT;
		}
	}

	*path_array = result;
	return FEDFS_OK;
}

/**
 * Assign the value of "string" to a UriTextRangeA field
 *
 * @param text UriTextRangeA field to assign
 * @param string NUL-terminated C string
 *
 * Note: "string" must not be freed until the text range
 * is no longer used.
 *
 * Note: string is assumed to contain only single-width
 * characters.
 */
void
nsdb_assign_textrange(UriTextRangeA *text, const char *string)
{
	text->first = string;
	text->afterLast = string + strlen(string);
}

/**
 * Allocate a UriPathSegmentA
 *
 * @param name NUL-terminated C string containing path segment
 * @return freshly allocated UriPathSegmentA object
 */
static UriPathSegmentA *
nsdb_new_uri_path_segment(const char *name)
{
	UriPathSegmentA *new;

	new = (UriPathSegmentA *)calloc(1, sizeof(*new));
	if (new != NULL)
		nsdb_assign_textrange(&new->text, name);
	return new;
}

/**
 * Release a list of UriPathSegmentA objects
 *
 * @param pos head of UriPathSegmentA list
 */
static void
nsdb_free_path_segments(UriPathSegmentA *pos)
{
	UriPathSegmentA *next;

	while (pos != NULL) {
		next = pos->next;
		free(pos);
		pos = next;
	}
}

/**
 * Marshal the pathname component of an NFS URI
 *
 * @param path_array array of pointers to NUL-terminated C strings
 * @param uri OUT: a filled-in UriUriA structure
 * @return a FedFsStatus code
 *
 * Caller must free the members of the UriUriA object with
 * uriFreeUriMembersA().
 *
 * @todo Proper i18n of pathname segments
 */
FedFsStatus
nsdb_path_array_to_uri_pathname(char * const *path_array, UriUriA *uri)
{
	UriPathSegmentA *pos, *result;
	size_t length, len;
	char *component;
	unsigned int i;

	pos = nsdb_new_uri_path_segment("");
	if (pos == NULL)
		return FEDFS_ERR_SVRFAULT;
	result = pos;

	length = 0;
	for (i = 0; path_array[i] != NULL; i++) {
		component = path_array[i];
		len = strlen(component);

		if (len == 0) {
			xlog(D_GENERAL, "%s: Zero-length component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (len > NAME_MAX) {
			xlog(D_GENERAL, "%s: Component length too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
		if (strchr(component, '/') != NULL) {
			xlog(D_GENERAL, "%s: Local separator character "
					"found in component", __func__);
			return FEDFS_ERR_BADNAME;
		}
		if (!nsdb_pathname_is_utf8(component)) {
			xlog(D_GENERAL, "%s: Bad character in component",
				__func__);
			return FEDFS_ERR_BADCHAR;
		}

		length += STRLEN_SLASH + len;

		if (length > PATH_MAX) {
			xlog(D_GENERAL, "%s: Pathname too long", __func__);
			return FEDFS_ERR_NAMETOOLONG;
		}

		pos->next = nsdb_new_uri_path_segment(component);
		if (pos->next == NULL) {
			nsdb_free_path_segments(result);
			return FEDFS_ERR_SVRFAULT;
		}
		pos = pos->next;
	}

	uri->pathHead = result;
	return FEDFS_OK;
}

/**
 * Return length in bytes of a URI pathname segment
 *
 * @param segment URI pathname segment
 * @return count of bytes in segment
 *
 * XXX: Isn't there a uriparser API that does this?
 */
static size_t
nsdb_uri_pathname_segment_size(const UriPathSegmentA *segment)
{
	if (segment->text.first == NULL)
		return 0;
	return segment->text.afterLast - segment->text.first;
}

/**
 * Return number of segments in a URI pathname
 *
 * @param uri filled-in URI
 * @return count of segments
 *
 * XXX: Isn't there a uriparser API that does this?
 */
static unsigned int
nsdb_uri_pathname_segment_count(const UriUriA *uri)
{
	UriPathSegmentA *pos;
	unsigned int result;

	if (uri->pathHead->text.first == NULL)
		return 0;

	result = 1;
	for (pos = uri->pathHead; pos != uri->pathTail; pos = pos->next)
		result++;
	return result;
}

/**
 * Unmarshal the pathname component of an NFS URI
 *
 * @param uri a filled-in UriUriA structure
 * @param path_array OUT: array of pointers to NUL-terminated C strings
 * @return a FedFsStatus code
 *
 * Caller must free "path_array" with nsdb_free_string_array().
 *
 * @todo Proper i18n of pathname segments
 * @todo Handling too many slashes in various places
 */
FedFsStatus
nsdb_uri_pathname_to_path_array(const UriUriA *uri, char ***path_array)
{
	unsigned int i, count;
	UriPathSegmentA *pos;
	char **result = NULL;

	if (uri->pathHead == NULL) {
		xlog(D_GENERAL, "%s: NFS URI has no pathname component", __func__);
		return FEDFS_ERR_BADNAME;
	}

	count = nsdb_uri_pathname_segment_count(uri);
	if (count < 2) {
		xlog(D_GENERAL, "%s: NFS URI has short pathname component", __func__);
		return FEDFS_ERR_BADNAME;
	}

	pos = uri->pathHead->next;
	if (count == 2 && nsdb_uri_pathname_segment_size(pos) == 0)
		return nsdb_alloc_zero_component_pathname(path_array);

	result = (char **)calloc(count + 1, sizeof(char *));
	if (result == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate array",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0; pos != NULL; pos = pos->next) {
		size_t len;

		len = nsdb_uri_pathname_segment_size(pos);
		if (len > NAME_MAX) {
			nsdb_free_string_array(result);
			xlog(D_GENERAL, "%s: Component length too long",
				__func__);
			return FEDFS_ERR_NAMETOOLONG;
		}
		if (len == 0)
			continue;

		result[i] = strndup((char *)pos->text.first, len);
		if (result[i] == NULL) {
			nsdb_free_string_array(result);
			xlog(L_ERROR, "%s: Failed to allocate component string",
				__func__);
			return FEDFS_ERR_SVRFAULT;
		}
		i++;
	}

	*path_array = result;
	return FEDFS_OK;
}
