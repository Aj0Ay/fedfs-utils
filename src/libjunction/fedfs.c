/**
 * @file src/libjunction/fedfs.c
 * @brief Create, delete, and read FedFS junctions on the local file system
 */

/*
 * Copyright 2010, 2011 Oracle.  All rights reserved.
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

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <wchar.h>
#include <memory.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include <attr/xattr.h>

#include "fedfs.h"
#include "nsdb.h"
#include "junction.h"
#include "junction-internal.h"
#include "xlog.h"

/**
 * Magic string planted in the "type" attribute of junctions
 */
#define FEDFS_JUNCTION_TYPE		"fedfs"

/**
 * Name of extended attribute containing junction type
 */
#define FEDFS_XATTR_NAME_TYPE		"trusted.junction.type"

/**
 * Name of extended attribute containing junction's FSN UUID
 */
#define FEDFS_XATTR_NAME_FSNUUID	"trusted.junction.fsnuuid"

/**
 * Name of extended attribute containing hostname of NSDB service
 */
#define FEDFS_XATTR_NAME_NSDB		"trusted.junction.nsdbname"

/**
 * Name of extended attribute containing port of NSDB service
 */
#define FEDFS_XATTR_NAME_PORT		"trusted.junction.nsdbport"


/**
 * Remove all FedFS-related xattrs from a directory
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_remove_fsn(const char *pathname)
{
	FedFsStatus retval;
	int fd;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_remove_xattr(fd, pathname, FEDFS_XATTR_NAME_TYPE);
	if (retval != FEDFS_OK)
		goto out;
	retval = junction_remove_xattr(fd, pathname, FEDFS_XATTR_NAME_FSNUUID);
	if (retval != FEDFS_OK)
		goto out;
	retval = junction_remove_xattr(fd, pathname, FEDFS_XATTR_NAME_NSDB);
	if (retval != FEDFS_OK)
		goto out;
	retval = junction_remove_xattr(fd, pathname, FEDFS_XATTR_NAME_PORT);

out:
	(void)close(fd);
	return retval;
}

/**
 * Store FedFS information into a junction
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param host an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_store_fsn(const char *pathname, const char *fsn_uuid, const nsdb_t host)
{
	FedFsStatus retval;
	char buf[20];
	int fd, len;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_set_xattr(fd, pathname, FEDFS_XATTR_NAME_TYPE,
			FEDFS_XATTR_NAME_TYPE, sizeof(FEDFS_XATTR_NAME_TYPE));
	if (retval != FEDFS_OK)
		goto out;

	retval = junction_set_xattr(fd, pathname, FEDFS_XATTR_NAME_FSNUUID,
			fsn_uuid, strlen(fsn_uuid) + 1);
	if (retval != FEDFS_OK)
		goto out;

	retval = junction_set_xattr(fd, pathname, FEDFS_XATTR_NAME_NSDB,
			nsdb_hostname(host), nsdb_hostname_len(host) + 1);
	if (retval != FEDFS_OK)
		goto out;

	len = snprintf(buf, sizeof(buf), "%u", nsdb_port(host));
	retval = junction_set_xattr(fd, pathname, FEDFS_XATTR_NAME_PORT, buf, len + 1);

out:
	(void)close(fd);
	return retval;
}

/**
 * Add FedFS junction information to a pre-existing object
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param host an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * An error occurs if the object referred to by "pathname" does not
 * exist or contains existing FedFS junction data.
 */
FedFsStatus
fedfs_add_junction(const char *pathname, const char *fsn_uuid, const nsdb_t host)
{
	FedFsStatus retval;

	if (fsn_uuid == NULL || host == NULL)
		return FEDFS_ERR_INVAL;

	retval = fedfs_is_prejunction(pathname);
	if (retval != FEDFS_ERR_NOTJUNCT)
		return retval;

	retval = fedfs_store_fsn(pathname, fsn_uuid, host);
	if (retval != FEDFS_OK)
		goto out_err;

	retval = junction_save_mode(pathname);
	if (retval != FEDFS_OK)
		goto out_err;

	return retval;

out_err:
	(void)fedfs_remove_fsn(pathname);
	return retval;
}

/**
 * Remove FedFS junction information from an object
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * An error occurs if the object referred to by "pathname" does not
 * exist or does not contain FedFS junction data.
 */
FedFsStatus
fedfs_delete_junction(const char *pathname)
{
	FedFsStatus retval;

	retval = fedfs_is_junction(pathname);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_restore_mode(pathname);
	if (retval != FEDFS_OK)
		return retval;

	return fedfs_remove_fsn(pathname);
}

/**
 * Retrieve FSN information from a FedFS junction
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * Caller must free the string returned in "fsn_uuid" with free(3), and
 * free the NSDB host returned in "host" with nsdb_free_nsdb().
 */
FedFsStatus
fedfs_get_fsn(const char *pathname, char **fsn_uuid, nsdb_t *host)
{
	void *uuid_tmp = NULL;
	void *nsdbname_tmp = NULL;
	void *port_tmp = NULL;
	nsdb_t host_tmp = NULL;
	unsigned short port;
	FedFsStatus retval;
	size_t len;
	int fd;

	if (fsn_uuid == NULL || host == NULL)
		return FEDFS_ERR_INVAL;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_get_xattr(fd, pathname, FEDFS_XATTR_NAME_FSNUUID,
							&uuid_tmp, &len);
	if (retval != FEDFS_OK)
		goto out_err;

	retval = junction_get_xattr(fd, pathname, FEDFS_XATTR_NAME_NSDB,
					&nsdbname_tmp, &len);
	if (retval != FEDFS_OK)
		goto out_err;
	retval = junction_get_xattr(fd, pathname, FEDFS_XATTR_NAME_PORT,
					&port_tmp, &len);
	if (retval != FEDFS_OK)
		goto out_err;

	retval = FEDFS_ERR_SVRFAULT;
	if (!nsdb_parse_port_string(port_tmp, &port))
		goto out_err;

	retval = FEDFS_ERR_NSDB_PARAMS;
	if (nsdb_lookup_nsdb(nsdbname_tmp, port, &host_tmp, NULL) != FEDFS_OK)
		goto out_err;

	*fsn_uuid = uuid_tmp;
	*host = host_tmp;
	retval = FEDFS_OK;

out:
	free(port_tmp);
	free(nsdbname_tmp);
	(void)close(fd);
	return retval;

out_err:
	nsdb_free_nsdb(host_tmp);
	free(uuid_tmp);
	goto out;
	
}

/**
 * Predicate: does "pathname" refer to an object that can become a FedFS junction?
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * Return values:
 *	FEDFS_ERR_NOTJUNCT:	"pathname" refers to an object that can be
 *				made into a FedFS junction
 *	FEDFS_ERR_EXIST:	"pathname" refers to something that is
 *				already a FedFS junction
 *	FEDFS_ERR_INVAL:	"pathname" does not exist
 *	Other:			Some error occurred, "pathname" not
 *				investigated
 */
FedFsStatus
fedfs_is_prejunction(const char *pathname)
{
	FedFsStatus retval;
	int fd;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_is_directory(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = junction_is_sticky_bit_set(fd, pathname);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_TYPE);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_FSNUUID);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_NSDB);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}
	
	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_PORT);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

out_close:
	(void)close(fd);
	return retval;
out_exist:
	retval = FEDFS_ERR_EXIST;
	goto out_close;
}

/**
 * Predicate: does "pathname" refer to a FedFS junction?
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * Returns FEDFS_OK if "pathname" refers to a junction, or
 * FEDFS_ERR_NOTJUNCT if "pathname" does not refer to a junction, or
 * FEDFS_ERR_INVAL if "pathname" refers to something that does not exist.
 * Other errors may trickle up from lower layers.
 *
 * Return values:
 *	FEDFS_OK:		"pathname" refers to a FedFS junction
 *	FEDFS_ERR_NOTJUNCT:	"pathname" refers to an object that can be
 *				made into a FedFS junction
 *	FEDFS_ERR_INVAL:	"pathname" does not exist
 *	Other:			Some error occurred, "pathname" not
 *				investigated
 */
FedFsStatus
fedfs_is_junction(const char *pathname)
{
	FedFsStatus retval;
	int fd;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_is_directory(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = junction_is_sticky_bit_set(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_TYPE);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_FSNUUID);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_NSDB);
	if (retval != FEDFS_OK)
		goto out_close;
	
	retval = junction_is_xattr_present(fd, pathname, FEDFS_XATTR_NAME_PORT);

out_close:
	(void)close(fd);
	return retval;
}
