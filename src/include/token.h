/*
 * @file src/include/token.h
 * @brief tokenize strings, a la strtok(3)
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

#ifndef _FEDFS_UTILS_TOKEN_H
#define _FEDFS_UTILS_TOKEN_H

#include <sys/cdefs.h>

/**
 * Private tokenizer state object
 */
struct tokenizer;

__attribute_malloc__
struct tokenizer	*tk_new_tokenizer(const char *string,
						const char delimiter);
__attribute_malloc__
char				*tk_next_token(struct tokenizer *state);
void				 tk_free_tokenizer(struct tokenizer *state);
int				 tk_tokenizer_error(const struct tokenizer *state);

#endif	/* !_FEDFS_UTILS_TOKEN_H */
