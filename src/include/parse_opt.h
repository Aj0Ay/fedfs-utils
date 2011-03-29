/*
 * @file src/include/parse_opt.h
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

#ifndef _FEDFS_UTILS_PARSE_OPT_H
#define _FEDFS_UTILS_PARSE_OPT_H

#include <sys/cdefs.h>

#include "list.h"

typedef enum {
	PO_FAILED = 0,
	PO_SUCCEEDED = 1,
} po_return_t;

typedef enum {
	PO_NOT_FOUND = 0,
	PO_FOUND = 1,
	PO_BAD_VALUE = 2,
} po_found_t;

po_return_t		 po_split(const char *string,
					struct list_head **options);
po_return_t		 po_dup(const struct list_head *source,
					struct list_head **target);
void			 po_replace(struct list_head *target,
					struct list_head *source);
po_return_t		 po_join(const struct list_head *options,
					char **result);
po_return_t		 po_append(struct list_head *options,
					const char *string);
po_found_t		 po_contains(const struct list_head *options,
					const char *keyword);
po_found_t		 po_get(const struct list_head *options,
					const char *keyword, char **value);
po_found_t		 po_get_numeric(const struct list_head *options,
					const char *keyword, long *value);
int			 po_rightmost(const struct list_head *options,
					const char *keys[]);
po_found_t		 po_remove_all(struct list_head *options,
					const char *keyword);
void			 po_destroy(struct list_head *options);

#endif	/* _FEDFS_UTILS_PARSE_OPT_H */
