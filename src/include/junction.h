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

#include <stdint.h>
#include "nsdb.h"

/**
 * Contains NFS fileset location information
 *
 * Each of these represents one server:/rootpath pair.  The NFS
 * implementation can coalesce multiple pairs into a single
 * fs_location4 result if jfl_rootpath is the same across
 * multiple servers.
 *
 * The nfl_server field can contain either one presentation format
 * IP address or one DNS hostname.
 *
 * See Section 11.9 and 11.10 of RFC 5661 or section 4.2.2.3 and
 * 4.2.2.4 of the NSDB protocol draft for details.
 */

struct nfs_fsloc {
	struct nfs_fsloc	 *nfl_next;

	char			 *nfl_hostname;
	uint16_t		  nfl_hostport;
	char			**nfl_rootpath;

	struct {
		_Bool		  nfl_varsub;
	} nfl_flags;
	int32_t			  nfl_currency;
	int32_t			  nfl_validfor;

	struct {
		_Bool		  nfl_writable, nfl_going, nfl_split;
	} nfl_genflags;
	struct {
		_Bool		  nfl_rdma;
	} nfl_transflags;
	struct {
		uint8_t		  nfl_simul, nfl_handle, nfl_fileid;
		uint8_t		  nfl_writever, nfl_change, nfl_readdir;
		uint8_t		  nfl_readrank, nfl_writerank;
		uint8_t		  nfl_readorder, nfl_writeorder;
	} nfl_info;

	int32_t			  nfl_majorver, nfl_minorver;
	int32_t			  nfl_ttl;
};


/**
 ** NFS location data management functions
 **/

void		  nfs_free_location(struct nfs_fsloc *location);
void		  nfs_free_locations(struct nfs_fsloc *locations);
struct nfs_fsloc *nfs_new_location(void);

__attribute_malloc__
char		**nfs_dup_string_array(char **array);
void		  nfs_free_string_array(char **array);


/**
 ** NFS junction management functions
 **/

FedFsStatus	 nfs_delete_junction(const char *pathname);
FedFsStatus	 nfs_add_junction(const char *pathname,
				struct nfs_fsloc *locations);
FedFsStatus	 nfs_get_locations(const char *pathname,
				struct nfs_fsloc **locations);
FedFsStatus	 nfs_is_prejunction(const char *pathname);
FedFsStatus	 nfs_is_junction(const char *pathname);


/**
 ** FedFS junction management functions
 **/

FedFsStatus	 fedfs_delete_junction(const char *pathname);
FedFsStatus	 fedfs_add_junction(const char *pathname, const char *uuid,
				const nsdb_t host);
FedFsStatus	 fedfs_get_fsn(const char *pathname, char **uuid,
				nsdb_t *host);
FedFsStatus	 fedfs_is_prejunction(const char *pathname);
FedFsStatus	 fedfs_is_junction(const char *pathname);

FedFsStatus	 junction_flush_exports_cache(void);

#endif	/* !_FEDFS_JUNCTION_H_ */
