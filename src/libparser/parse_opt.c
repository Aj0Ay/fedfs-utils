/*
 * @file src/libparser/parse_opt.c
 * @brief Mount option string parsing helpers
 */

/*
 * Copyright (C) 2007 Oracle.  All rights reserved.
 * Copyright (C) 2007 Chuck Lever <chuck.lever@oracle.com>
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
 * A group of mount options is treated as an ordered list.  The
 * list is ordered from left to right: the rightmost options take
 * precedence over similar options that have come before.
 *
 * Mount options in a string are separated by commas.  However,
 * mount option values may contain quoted commas.
 *
 * Converting a C string containing mount options to a data object
 * and manipulating that object is cleaner in C than manipulating
 * the C string itself.  This is similar to the way Python handles
 * string manipulation.
 *
 * The current implementation uses a linked list as the data object
 * since lists are simple, and mount options lists are not intended
 * to contain more than ten or twenty options at a time.
 *
 * Hopefully the interface is abstract enough that the underlying
 * data structure can be replaced, if needed, without altering the
 * API.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "parse_opt.h"
#include "token.h"

/**
 * Single element of a mount options list
 */
struct mount_option {
	struct list_head	list;
	char			*keyword, *value;
};

/**
 * Allocate an empty element of a mount option list
 *
 * @return freshly allocated mount_option, or NULL
 */
__attribute_malloc__ static struct mount_option *
option_allocate(void)
{
	struct mount_option *new;

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;
	INIT_LIST_HEAD(&new->list);
	return new;
}

/**
 * Free an element of a mount option list
 *
 * @param option mount_option detached from a mount option list
 *
 */
static void
option_destroy(struct mount_option *option)
{
	free(option->keyword);
	free(option->value);
	free(option);
}

/**
 * Create an element of a mount option list
 *
 * @param string NUL-terminated C string of mount option input by a user
 * @return freshly allocated mount_option, or NULL
 *
 * Caller must free returned mount_option with option_destroy
 *
 * Input string is of the form
 *
 *   "keyword"
 *
 * or
 *
 *   "keyword=value"
 *
 * The string is split and the keyword and value strings are stored
 * separately.
 */
__attribute_malloc__ static struct mount_option *
option_create(const char *string)
{
	struct mount_option *new;
	char *opteq;

	if (string == NULL)
		return NULL;

	new = option_allocate();
	if (new == NULL)
		return NULL;

	opteq = strchr(string, '=');
	if (opteq != NULL) {
		new->keyword = strndup(string, opteq - string);
		if (new->keyword == NULL)
			goto fail;
		new->value = strdup(opteq + 1);
		if (new->value == NULL)
			goto fail;
	} else {
		new->keyword = strdup(string);
		if (new->keyword == NULL)
			goto fail;
		new->value = NULL;
	}

	return new;

fail:
	option_destroy(new);
	return NULL;
}

/**
 * Duplicate an element of a mount option list
 *
 * @param option mount_option to clone
 * @return freshly allocate mount_option, or NULL
 *
 * Caller must free returned mount_option with option_destroy
 */
__attribute_malloc__ static struct mount_option *
option_dup(const struct mount_option *option)
{
	struct mount_option *new;

	new = option_allocate();
	if (new == NULL)
		return NULL;

	new->keyword = strdup(option->keyword);
	if (new->keyword == NULL)
		goto fail;

	if (option->value != NULL) {
		new->value = strdup(option->value);
		if (new->value == NULL)
			goto fail;
	} else
		new->value = NULL;

	return new;

fail:
	option_destroy(new);
	return NULL;
}

/**
 * Create a fresh mount options list
 *
 * @return an initialized mount options list
 */
__attribute_malloc__ static struct list_head *
options_create(void)
{
	struct list_head *new;

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return NULL;

	INIT_LIST_HEAD(new);
	return new;
}

/**
 * Remove a mount_option element from a mount options list
 *
 * @param option mount_option to remove from list
 *
 * The element "option" is destroyed by this function.
 */
static void
option_delete(struct mount_option *option)
{
	list_del(&option->list);
	option_destroy(option);
}

/**
 * Remove and free all elements from a mount options list
 *
 * @param options list of mount options to delete
 *
 */
static void
options_delete(struct list_head *options)
{
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, options)
		option_delete(list_entry(pos, struct mount_option, list));
}

/**
 * Release resources associated with a mount options list
 *
 * @param options mount options list to free
 *
 */
void
po_destroy(struct list_head *options)
{
	if (options == NULL)
		return;

	options_delete(options);
	free(options);
}

/**
 * Split options string into group of options
 *
 * @param string NUL-terminated C string containing zero or more comma-delimited options
 * @param options OUT: pointer to a new mount options list
 * @return operation status code
 *
 * Convert an input mount options string to a list object, to make it
 * easier to adjust the options as we go.  This is just an exercise in
 * lexical parsing.  This function doesn't pay attention to the
 * meaning of the options themselves.
 */
po_return_t
po_split(const char *string, struct list_head **options)
{
	struct list_head *new;
	struct tokenizer *tstate;
	char *opt;

	if (string == NULL) {
		new = options_create();
		if (new == NULL)
			return PO_FAILED;
		goto succeed;
	}

	new = options_create();
	if (new == NULL)
		return PO_FAILED;

	tstate = tk_new_tokenizer(string, ',');
	for (opt = tk_next_token(tstate);
	     opt != NULL;
	     opt = tk_next_token(tstate)) {
		struct mount_option *option = option_create(opt);
		free(opt);
		if (option == NULL)
			goto fail;
		list_add_tail(new, &option->list);
	}
	if (tk_tokenizer_error(tstate))
		goto fail;
	tk_free_tokenizer(tstate);

succeed:
	*options = new;
	return PO_SUCCEEDED;

fail:
	tk_free_tokenizer(tstate);
	po_destroy(new);
	return PO_FAILED;
}

/**
 * Duplicate an existing list of options
 *
 * @param source an initialized mount options list
 * @param target OUT: pointer to a new mount options list
 * @return operation status code
 *
 * Caller must free the returned mount options list with po_destroy().
 */
po_return_t
po_dup(const struct list_head *source, struct list_head **target)
{
	struct list_head *new, *pos;

	if (source == NULL)
		return PO_FAILED;

	new = options_create();
	if (new == NULL)
		return PO_FAILED;
	if (list_empty(source))
		goto succeed;

	list_for_each(pos, source) {
		struct mount_option *option;

		option = option_dup(list_entry(pos, struct mount_option, list));
		if (option == NULL) {
			po_destroy(new);
			return PO_FAILED;
		}

		list_add_tail(new, &option->list);
		pos = pos->next;
	}

succeed:
	*target = new;
	return PO_SUCCEEDED;
}

/**
 * Replace mount options in one mount options list with another
 *
 * @param target initialized mount options list to replace
 * @param source mount options list containing source mount options
 *
 * Upon return,
 *
 *   1.  mount_option elements in "target" before the call are released
 *   2.  mount_option elements in "source" are moved, not copied, to
 *	 "target"
 *
 * Thus, "source" is empty, but it still must be freed with po_destroy().
 */
void
po_replace(struct list_head *target, struct list_head *source)
{
	if (target == NULL)
		return;

	options_delete(target);

	if (source == NULL)
		return;

	list_splice(source, target);
	INIT_LIST_HEAD(source);
}

/**
 * Convert "options" back into a C string that the rest of the world
 * understands.
 *
 * @param options mount options list to recombine
 * @param result OUT: a NUL-terminated (single-byte character) C string
 * @return operation status code
 *
 * Caller must free "result" with free(3).
 */
po_return_t
po_join(const struct list_head *options, char **result)
{
	struct mount_option *option;
	struct list_head *pos;
	size_t len = 0;
	char *buf;

	if (options == NULL || result == NULL)
		return PO_FAILED;

	if (list_empty(options)) {
		*result = strdup("");
		return (*result != NULL) ? PO_SUCCEEDED : PO_FAILED;
	}

	/*
	 * Size up the returned string
	 */
	list_for_each(pos, options) {
		option = list_entry(pos, struct mount_option, list);
		len += strlen(option->keyword);
		if (option->value != NULL)
			len += strlen(option->value) + 1;  /* equals sign */
		if (!list_last_entry(pos, options))
			len++;  /* comma */
	}
	len++;	/* NULL on the end */

	buf = calloc(1, len);
	if (buf == NULL)
		return PO_FAILED;

	/*
	 * Build up the result in "buf"
	 */
	list_for_each(pos, options) {
		option = list_entry(pos, struct mount_option, list);
		strcat(buf, option->keyword);
		if (option->value != NULL) {
			strcat(buf, "=");
			strcat(buf, option->value);
		}
		if (!list_last_entry(pos, options))
			strcat(buf, ",");
	}

	*result = buf;
	return PO_SUCCEEDED;
}

/**
 * Concatenate an option onto a group of options
 *
 * @param options mount options list
 * @param string NUL-terminated single byte character C string containing the option to add
 * @return operation status code
 */
po_return_t
po_append(struct list_head *options, const char *string)
{
	struct mount_option *option;

	option = option_create(string);
	if (option == NULL)
		return PO_FAILED;

	list_add_tail(options, &option->list);
	return PO_SUCCEEDED;
}

/**
 * Predicate: Does the list "options" contain option "keyword" ?
 *
 * @param options initialized mount options list
 * @param keyword NUL-terminated single byte character C string containing option keyword
 * @return search result status code
 */
po_found_t
po_contains(const struct list_head *options, const char *keyword)
{
	struct mount_option *option;
	struct list_head *pos;

	if (options == NULL || keyword == NULL)
		return PO_NOT_FOUND;

	list_for_each(pos, options) {
		option = list_entry(pos, struct mount_option, list);
		if (strcmp(option->keyword, keyword) == 0)
			return PO_FOUND;
	}
	return PO_NOT_FOUND;
}

/**
 * Return the value of the rightmost instance of an option
 *
 * @param options initialized mount options list
 * @param keyword NUL-terminated single byte character C string containing option keyword
 * @param value OUT: NUL-terminated single byte character C string
 * @return search result status code
 *
 * Returns:
 *	* PO_FOUND if the keyword was found; "value" is set to the keyword's value
 *	* PO_NOT_FOUND if the keyword was not found, or the keyword was found and has no value
 *	* PO_BAD_VALUE if an error occurred
 *
 * Caller must free the returned string with free(3).
 *
 * If multiple instances of the same option are present in a mount option
 * list, the rightmost instance is always the effective one.
 */
po_found_t
po_get(const struct list_head *options, const char *keyword,
		char **value)
{
	struct mount_option *option;
	struct list_head *pos;
	char *tmp;

	if (options == NULL || keyword == NULL)
		return PO_BAD_VALUE;

	list_for_each_backwardly(pos, options) {
		option = list_entry(pos, struct mount_option, list);
		if (strcmp(option->keyword, keyword) == 0) {
			if (option->value == NULL)
				return PO_NOT_FOUND;
			tmp = strdup(option->value);
			if (tmp == NULL)
				return PO_BAD_VALUE;
			*value = tmp;
			return PO_FOUND;
		}
	}
	return PO_NOT_FOUND;
}

/**
 * Return numeric value of rightmost instance of keyword option
 *
 * @param options initialized mount options list
 * @param keyword NUL-terminated single byte character C string containing option keyword
 * @param value OUT: set to the value of the found mount option
 * @return search result status code
 *
 * This is specifically for parsing keyword options that take only a numeric
 * value.  If multiple instances of the same option are present in a mount
 * option list, the rightmost instance is always the effective one.
 *
 * Returns:
 *	* PO_FOUND if the keyword was found and the value is numeric; "value" is
 *	  set to the keyword's value
 *	* PO_NOT_FOUND if the keyword was not found
 *	* PO_BAD_VALUE if the keyword was found, but the value is not numeric
 *
 * These last two are separate in case the caller wants to warn about bad mount
 * options instead of silently using a default.
 */
po_found_t
po_get_numeric(const struct list_head *options, const char *keyword,
		long *value)
{
	char *option, *endptr;
	po_found_t rc;
	long tmp;

	rc = po_get(options, keyword, &option);
	if (rc != PO_FOUND)
		return rc;

	errno = 0;
	tmp = strtol(option, &endptr, 10);
	if (errno == 0 && endptr != option) {
		*value = tmp;
		return PO_FOUND;
	}
	return PO_BAD_VALUE;
}

/**
 * Determine the precedence of several mount options
 *
 * @param options initialized mount options list
 * @param keys pointer to an array of C strings containing option keywords
 * @return index into "keys" of the option that is rightmost, or -1
 *
 * This function can be used to determine which of several similar
 * options will be the one to take effect.
 *
 * The kernel parses the mount option string from left to right.
 * If an option is specified more than once (for example, "intr"
 * and "nointr"), the rightmost option is the last to be parsed,
 * and it therefore takes effect over previous similar options.
 *
 * This can also be used to distinguish among multiple synonymous
 * options, such as "proto=," "udp" and "tcp."
 *
 * If none of the options listed in "keys" is present in "options,"
 * or if "options" is NULL, this function returns -1.
 */
int
po_rightmost(const struct list_head *options, const char *keys[])
{
	struct mount_option *option;
	struct list_head *pos;
	int i;

	if (options == NULL)
		return -1;

	list_for_each_backwardly(pos, options) {
		option = list_entry(pos, struct mount_option, list);
		for (i = 0; keys[i] != NULL; i++)
			if (strcmp(option->keyword, keys[i]) == 0)
				return i;
	}
	return -1;
}

/**
 * Remove all instances of a keyword from a mount options list
 *
 * @param options initialized mount options list
 * @param keyword NUL-terminated single byte character C string containing an option keyword to remove
 * @return search result status code
 */
po_found_t
po_remove_all(struct list_head *options, const char *keyword)
{
	struct mount_option *option;
	struct list_head *pos, *next;
	int found;

	if (options == NULL || keyword == NULL)
		return PO_NOT_FOUND;

	found = PO_NOT_FOUND;
	list_for_each_safe(pos, next, options) {
		option = list_entry(pos, struct mount_option, list);
		if (strcmp(option->keyword, keyword) == 0) {
			option_delete(option);
			found = PO_FOUND;
		}
	}
	return found;
}
