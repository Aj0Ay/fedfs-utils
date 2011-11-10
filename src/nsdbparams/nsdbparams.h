/**
 * @file src/nsdbparams/nsdbparams.h
 * @brief Declarations and definitions for nsdbparams command line tool
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

#ifndef _FEDFS_NSDBPARAMS_H_
#define _FEDFS_NSDBPARAMS_H_

_Bool	 nsdbparams_drop_privileges(const uid_t uid, const gid_t gid);
int	 nsdbparams_delete(const char *progname, int argc, char **argv);
int	 nsdbparams_list(const char *progname, int argc, char **argv);
int	 nsdbparams_show(const char *progname, int argc, char **argv);
int	 nsdbparams_update(const char *progname, int argc, char **argv);

#endif	/* !_FEDFS_NSDBPARAMS_H_ */
