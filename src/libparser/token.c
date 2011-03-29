/*
 * @file src/libparser/token.c
 * @brief Tokenize strings, a la strtok(3)
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
 * We've constructed a simple string tokenizer that is better than
 * strtok(3) in several ways:
 *
 * 1.  It doesn't interfere with ongoing tokenizations using strtok(3).
 * 2.  It's re-entrant so we can nest tokenizations, if needed.
 * 3.  It can handle double-quoted delimiters (needed for 'context="sd,fslj"').
 * 4.  It doesn't alter the string we're tokenizing, so it can work
 *     on write-protected strings as well as writable strings.
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

#include "token.h"

/**
 * Private tokenizer state object
 */
struct tokenizer {
	const char	*pos;
	char		 delimiter;
	int		 error;
};

/**
 * Locate a non-delimiter character in a string, starting at the current position
 *
 * @param state initialized tokenizer state object
 */
static void
tk_find_next_nondelimiter(struct tokenizer *state)
{
	while (*state->pos != '\0' && *state->pos == state->delimiter)
		state->pos++;
}

/**
 * Locate a delimiter character in a string, starting at the current position
 *
 * @param state initialized tokenizer state object
 * @return count of characters visited, or zero
 *
 * Delimiter characters can be quoted.
 */
static size_t
tk_find_next_delimiter(struct tokenizer *state)
{
	size_t len = 0;
	int quote_seen = 0;

	while (*state->pos != '\0') {
		if (*state->pos == '"')
			quote_seen ^= 1;

		if (!quote_seen && *state->pos == state->delimiter)
			break;

		len++;
		state->pos++;
	}

	/* did the string terminate before the close quote? */
	if (quote_seen) {
		state->error = EINVAL;
		return 0;
	}

	return len;
}

/**
 * Return the next token in the input string
 *
 * @param state initialized tokenizer state object
 * @return pointer to a NUL-terminated C string, or NULL
 *
 * Upon return, state is updated to point to the new current position
 * in the input string.  Caller must free returned string with free(3).
 */
__attribute_malloc__ char *
tk_next_token(struct tokenizer *state)
{
	const char *save;
	char *token;
	size_t len;

	if (!state || !state->pos || state->error)
		return NULL;

	tk_find_next_nondelimiter(state);
	if (*state->pos == '\0')
		goto fail;
	save = state->pos;

	len = tk_find_next_delimiter(state);
	if (len == 0)
		goto fail;

	token = strndup(save, len);
	if (token == NULL) {
		state->error = ENOMEM;
		goto fail;
	}
	return token;

fail:
	state->pos = NULL;
	return NULL;
}

/**
 * Return an initialized tokenizer context object
 *
 * @param string a NUL-terminated (single-byte character) C string
 * @param delimiter a C character that delimits tokens in "string"
 * @return an initialized tokenizer state object, or NULL
 */
__attribute_malloc__ struct tokenizer *
tk_new_tokenizer(const char *string, const char delimiter)
{
	struct tokenizer *state;

	state = calloc(1, sizeof(*state));
	if (state == NULL)
		return NULL;

	state->pos = string;
	state->delimiter = delimiter;
	state->error = 0;
	return state;
}

/**
 * Return error value stored in tokenizer state object
 * @param state initialized tokenizer state object
 * @return errno value
 */
int
tk_tokenizer_error(const struct tokenizer *state)
{
	return state ? state->error : 0;
}

/**
 * Release resources associated with a tokenizer state object
 * @param state initialized tokenizer state object
 */
void
tk_free_tokenizer(struct tokenizer *state)
{
	free(state);
}
