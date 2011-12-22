/*
 * @file src/libjunction/junction-internal.h
 * @brief Internal declarations for libjunction.a
 */

/*
 * Copyright 2011 Oracle.  All rights reserved.
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

#ifndef _FEDFS_JUNCTION_INTERNAL_H_
#define _FEDFS_JUNCTION_INTERNAL_H_

FedFsStatus	 junction_open_path(const char *pathname, int *fd);
FedFsStatus	 junction_is_directory(int fd, const char *path);
FedFsStatus	 junction_is_sticky_bit_set(int fd, const char *path);
FedFsStatus	 junction_set_sticky_bit(int fd, const char *path);
FedFsStatus	 junction_is_xattr_present(int fd, const char *path,
				const char *name);
FedFsStatus	 junction_read_xattr(int fd, const char *path, const char *name,
				char **contents);
FedFsStatus	 junction_get_xattr(int fd, const char *path, const char *name,
				void **contents, size_t *contentlen);
FedFsStatus	 junction_set_xattr(int fd, const char *path, const char *name,
			const void *contents, const size_t contentlen);
FedFsStatus	 junction_remove_xattr(int fd, const char *pathname,
			const char *name);
FedFsStatus	 junction_save_mode(const char *pathname);
FedFsStatus	 junction_restore_mode(const char *pathname);

#endif	/* !_FEDFS_JUNCTION_INTERNAL_H_ */
