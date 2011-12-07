/**
 * @file src/libnsdb/annotation.c
 * @brief Parse fedfsAnnotation values
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

/*
 * Quoting NSDB draft Section 4.2.1.12:
 *
 * @verbatim

   A fedfsAnnotation attribute is a human-readable sequence of UTF-8
   characters with no non-terminal NUL characters. The value MUST be
   formatted according to the following ABNF [RFC5234] rules:

	ANNOTATION = KEY EQUALS VALUE
	KEY = ITEM
	VALUE = ITEM
	ITEM = BLANK DQUOTE STR DQUOTE BLANK
	BLANK = 0*EMPTY
	EMPTY = SPACE / HTAB
	HTAB = %x09 ; horizontal tab
	STR = 0*UTF8

   The DQUOTE, EQUALS, UTF8, and SPACE rules are defined in [RFC4512].

   The following escape sequences are allowed:

                   +-----------------+-------------+
                   | escape sequence | replacement |
                   +-----------------+-------------+
                   |        \\       |      \      |
                   |        \"       |      "      |
                   +-----------------+-------------+

   A fedfsAnnotation attribute that does not adhere to this format
   SHOULD be ignored.

   @endverbatim
 *
 * Quoting RFC 4512 Section 1.4. "Common ABNF Productions"
 *
 * @verbatim
 *
	SPACE	= %x20 ; space (" ")
	DQUOTE	= %x22 ; quote (""")
	EQUALS	= %x3D ; equals sign ("=")

	; Any UTF-8 [RFC3629] encoded Unicode [Unicode] character
	UTF8	= UTF1 / UTFMB
	UTFMB	= UTF2 / UTF3 / UTF4
	UTF0	= %x80-BF
	UTF1	= %x00-7F
	UTF2	= %xC2-DF UTF0
	UTF3	= %xE0 %xA0-BF UTF0 / %xE1-EC 2(UTF0) /
		  %xED %x80-9F UTF0 / %xEE-EF 2(UTF0)
	UTF4	= %xF0 %x90-BF 2(UTF0) / %xF1-F3 3(UTF0) /
		  %xF4 %x80-8F 2(UTF0)

   @endverbatim
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
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Check for UTF-8 cleanliness and provide proper escaping
 *
 * @param in NUL-terminated C string containing string to sanitize
 * @param out OUT: NUL-terminated C string containing cleansed value
 * @return a FedFsStatus code
 *
 * Caller must free "out" with free(3)
 */
static FedFsStatus
nsdb_sanitize_annotation(const char *in, char **out)
{
	size_t i, j, len;
	char *result;

	/* Assume worst case: every input character must be escaped */
	len = strlen(in);
	result = malloc(len * 2 + 1);
	if (result == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate output buffer",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	for (i = 0, j = 0; i < len; i++) {
		/* escape as needed */
		if (in[i] == '\\' || in[i] == '"')
			result[j++] = '\\';

		result[j++] = in[i];
	}
	result[j] = '\0';

	*out = result;
	xlog(D_CALL, "%s: out_len = %zu, out = \"%s\"",
		__func__, j, result);
	return FEDFS_OK;
}

/**
 * Form a fedfsAnnotation attribute value
 *
 * @param keyword NUL-terminated C string containing keyword part of annotation
 * @param value NUL-terminated C string containing value part of annotation
 * @param annotation OUT: NUL-terminated UTF-8 C string containing full annotation value
 * @return a FedFsStatus code
 *
 * Caller must free "*annotation" with free(3).
 *
 * This function provides a clean and compliant fedfsAnnotation value
 * for adding to an NSDB.
 *
 * We don't check that the annotation value contains valid UTF-8 characters:
 * LDAP will exclude invalid strings.
 */
FedFsStatus
nsdb_construct_annotation(const char *keyword, const char *value,
		char **annotation)
{
	FedFsStatus retval;
	char *tmp, *buf;

	/* Assume worst case: every input character must be escaped */
	buf = malloc(strlen(keyword) * 2 + strlen(value) * 2 +
			strlen("\"\" = \"\""));
	if (buf == NULL) {
		xlog(D_GENERAL, "%s: Failed to allocate output buffer",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}

	buf[0] = '\0';
	strcat(buf, "\"");

	retval = nsdb_sanitize_annotation(keyword, &tmp);
	if (retval != FEDFS_OK)
		goto out_err;
	strcat(buf, tmp);
	free(tmp);
	tmp = NULL;

	strcat(buf, "\" = \"");

	retval = nsdb_sanitize_annotation(value, &tmp);
	if (retval != FEDFS_OK)
		goto out_err;
	strcat(buf, tmp);
	free(tmp);

	strcat(buf, "\"");

	*annotation = buf;
	xlog(D_CALL, "%s: ann_len = %zu, ann = \"%s\"",
		__func__, strlen(buf), buf);
	return FEDFS_OK;

out_err:
	free(buf);
	return retval;
}

/**
 * Process token, minding escape sequences
 *
 * @param buf NUL-terminated C string
 * @param len size of "buf" in bytes
 * @param index OUT: index into "buf"
 * @param tmp OUT: copy of sanitized token
 * @return false if "buf" contains invalid annotation syntax
 *
 * On successful return, "*i" is pointing just past the
 * processed token, and "tmp" is filled in with an escaped
 * copy of the processed token.
 */
static _Bool
nsdb_process_token(const char *buf, const size_t len,
		size_t *index, char *tmp)
{
	size_t j, i = *index;

	j = 0;
	while (i < len) {
		xlog(D_GENERAL, "%s: i=%zu, buf[i]=%c",
			__func__, i, buf[i]);
		if (buf[i] == '\\') {
			if (buf[i + 1] == '"')
				i++;
			else if (buf[i + 1] == '\\')
				i++;
		} else if (buf[i] == '"')
			break;
		tmp[j++] = buf[i++];
	}
	i++;

	*index = i;
	return true;
}

/**
 * Skip over white space in a buffer
 *
 * @param buf NUL-terminated C string
 * @param len size of "buf" in bytes
 * @param index IN: OUT: index into "buf"
 * @param c character that terminates allowable white space
 * @return false if "buf" contains invalid annotation syntax
 *
 * On successful return, "*index" is pointing just past the
 * processed token.
 */
static _Bool
nsdb_skip_whitespace(const char *buf, const size_t len,
		size_t *index, const char c)
{
	size_t i;

	for (i = *index; i < len; i++) {
		if (buf[i] == ' ' || buf[i] == '\t')
			continue;
		if (buf[i] != c)
			return false;
		break;
	}
	i++;

	if (i == len)
		return false;

	*index = i;
	return true;
}

/**
 * Parse a fedfsAnnotation attribute value
 *
 * @param annotation NUL-terminated UTF-8 C string containing full annotation value
 * @param len length of annotation value, in bytes
 * @param keyword OUT: NUL-terminated C string containing keyword part of annotation
 * @param value OUT: NUL-terminated C string containing value part of annotation
 * @return a FedFsStatus code
 *
 * Caller must free "*keyword" and "*value" with free(3).
 *
 * This function parses a fedfsAnnotation value returned from an NSDB.
 *
 * We don't check that the attribute value contains valid UTF-8 characters:
 * LDAP will exclude invalid strings.
 *
 * Quoting NSDB draft Section 4.2.1.12:
 *
 * @verbatim

   A fedfsAnnotation value SHOULD be processed as follows:

   1.  Scan through the attribute value and replace the above escape
       sequences.
   2.  Parse the results of the previous step according to the
       ANNOTATION rule.

   @endverbatim
 */
FedFsStatus
nsdb_parse_annotation(const char *annotation, size_t len,
		char **keyword, char **value)
{
	char *tmpkey = NULL;
	char *tmpval = NULL;
	size_t i;

	/* NSDB draft doesn't limit size of these, but let's 
	 * protect ourselves from badness */
	if (len < strlen("\"\"=\"\"") || len > 8192)
		goto out_ignored;
	if (annotation[0] != '"' || annotation[len - 1] != '"')
		goto out_ignored;
	i = 1;

	/* Made up value that will always be large enough */
	tmpkey = calloc(1, len);
	if (tmpkey == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate buffer for KEY",
			__func__);
		return FEDFS_ERR_SVRFAULT;
	}
	tmpval = calloc(1, len);
	if (tmpval == NULL) {
		xlog(L_ERROR, "%s: Failed to allocate buffer for KEY",
			__func__);
		free(tmpkey);
		return FEDFS_ERR_SVRFAULT;
	}

	if (!nsdb_process_token(annotation, len, &i, tmpkey) ||
	    i == len) {
		xlog(D_CALL, "%s: Failed to find KEY close quote",
			__func__);
		goto out_ignored;
	}

	if (!nsdb_skip_whitespace(annotation, len, &i, '=')) {
		xlog(D_CALL, "%s: Failed to find equals sign",
			__func__);
		goto out_ignored;
	}

	if (!nsdb_skip_whitespace(annotation, len, &i, '"')) {
		xlog(D_CALL, "%s: Failed to find VAL open quote",
			__func__);
		goto out_ignored;
	}

	if (!nsdb_process_token(annotation, len, &i, tmpval) ||
	    i != len) {
		xlog(D_CALL, "%s: Trailing characters", __func__);
		goto out_ignored;
	}

	xlog(D_CALL, "%s: Parsed annotation \"%s\" = \"%s\"",
		__func__, tmpkey, tmpval);
	*keyword = tmpkey;
	*value = tmpval;
	return FEDFS_OK;;

out_ignored:
	free(tmpval);
	free(tmpkey);
	return FEDFS_OK;
}
