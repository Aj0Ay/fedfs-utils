/*
 * @file src/include/path.h
 * @brief Declarations for libpath.a
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

#ifndef _FEDFS_PATH_H_
#define _FEDFS_PATH_H_

#include <sys/cdefs.h>

#include "nsdb.h"

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

#endif	/* !_FEDFS_PATH_H_ */
