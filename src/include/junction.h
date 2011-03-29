/*
 * @file src/include/junction.h
 * @brief Declarations for libjunction.a
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

#ifndef _FEDFS_JUNCTION_H_
#define _FEDFS_JUNCTION_H_

#include "nsdb.h"

FedFsStatus	 fedfs_remove_fsn(const char *pathname);
FedFsStatus	 fedfs_store_fsn(const char *pathname, const char *uuid,
				const nsdb_t host);
FedFsStatus	 fedfs_get_fsn(const char *pathname, char **uuid,
				nsdb_t *host);
FedFsStatus	 fedfs_is_prejunction(const char *pathname);
FedFsStatus	 fedfs_is_junction(const char *pathname);

FedFsStatus	 fedfs_save_mode(const char *pathname);
FedFsStatus	 fedfs_restore_mode(const char *pathname);

#endif	/* !_FEDFS_JUNCTION_H_ */
