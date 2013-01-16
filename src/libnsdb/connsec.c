/**
 * @file src/libnsdb/connsec.c
 * @brief Handle security-related NSDB connection parameters
 */

/*
 * Copyright 2012 Oracle.  All rights reserved.
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

#include "fedfs.h"
#include "nsdb.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Retrieve certificate data for NSDB "host" from NSDB database
 *
 * @param host an initialized nsdb_t object
 * @param data OUT: buffer containing security data
 * @param len OUT: length of security data buffer
 * @return a FedFsStatus code
 *
 * On success, FEDFS_OK is returned and the security data is filled in.
 *
 * Caller must free the returned buffer with free(3).
 */
FedFsStatus
nsdb_connsec_get_cert_data(nsdb_t host, char **data, unsigned int *len)
{
	FedFsStatus retval;

	if (data == NULL || len == NULL)
		return FEDFS_ERR_INVAL;

	switch (nsdb_sectype(host)) {
	case FEDFS_SEC_NONE:
		retval = FEDFS_ERR_INVAL;
		break;
	case FEDFS_SEC_TLS:
		retval = nsdb_read_certfile(nsdb_certfile(host), data, len);
		break;
	default:
		retval = FEDFS_ERR_SVRFAULT;
	}

	return retval;
}
