/**
 * @file src/include/getsrvinfo.h
 * @brief Retrieve SRV records from DNS
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

#ifndef _FEDFS_GETSRVINFO_H_
#define _FEDFS_GETSRVINFO_H_

/**
 * Single list element containing SRV record data
 */
struct srvinfo {
	struct srvinfo		*si_next;
	char			*si_target;
	unsigned short		 si_priority;
	unsigned short		 si_weight;
	unsigned short		 si_port;
};

enum {
	ESI_SUCCESS	= 0,
	ESI_NONAME	= -2,
	ESI_AGAIN	= -3,
	ESI_FAIL	= -4,
	ESI_NODATA	= -5,
	ESI_SERVICE	= -8,
	ESI_MEMORY	= -10,
	ESI_SYSTEM	= -11,
	ESI_PARSE	= -1000,
};

int		 getsrvinfo(const char *srvname, const char *domainname,
				struct srvinfo **si);
void		 freesrvinfo(struct srvinfo *si);
const char	*gsi_strerror(int status);

#endif	/* !_FEDFS_GETSRVINFO_H_ */
