/*
 * @file src/include/nfs-plugin.h
 * @brief Definition of NFS junction plug-in API
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

/*
 * The purpose of this API is to provide an opaque mechanism for
 * the NFS mountd daemon to resolve NFS basic and FedFS junctions.
 * This interface is therefore quite specific to NFS.
 */

#ifndef FEDFS_NFS_PLUGIN_H
#define FEDFS_NFS_PLUGIN_H

#include <stdint.h>

__BEGIN_DECLS

/**
 * Current version of API
 */
#define JP_API_VERSION		(1)

/**
 * A set of NFS FS locations
 */
struct nfs_fsloc_set;
typedef struct nfs_fsloc_set	 *nfs_fsloc_set_t;

/**
 * Junction operation status codes
 */
enum jp_status {
	JP_OK			=  0,
	JP_INVAL		= -1,
	JP_ACCESS		= -2,
	JP_EXIST		= -3,
	JP_TYPE_NOT_SUPP	= -4,
	JP_OP_NOT_SUPP		= -5,
	JP_ISJUNCTION		= -6,
	JP_NOTJUNCTION		= -7,
	JP_NSDBLOCAL		= -8,
	JP_NSDBREMOTE		= -9,
	JP_MEMORY		= -10,
	JP_SYSTEM		= -11,
	JP_PARSE		= -1000,
	JP_EMPTY		= -1001,
};

/**
 * Vector of methods provided by a junction plug-in
 */
struct jp_ops {
	unsigned int	  jp_api_version;

	enum jp_status	  (*jp_init)(_Bool want_debugging);
	void		  (*jp_done)(void);

	const char *	  (*jp_error)(enum jp_status status);
	void		  (*jp_put_locations)(nfs_fsloc_set_t locset);
	enum jp_status	  (*jp_get_locations)(const char *junct_path,
					nfs_fsloc_set_t *locset);
	void		  (*jp_rewind_locations)(nfs_fsloc_set_t locset);
	enum jp_status	  (*jp_get_next_location)(nfs_fsloc_set_t locset,
					char **hostname, char **export_path,
					int *ttl);
};

/**
 * Load this symbol to get access to the junction API
 */
extern struct jp_ops	  nfs_junction_ops;

__END_DECLS

#endif	/* !FEDFS_NFS_PLUGIN_H */
