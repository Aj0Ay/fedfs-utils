/**
 * @file src/libjunction/junction.c
 * @brief Create, delete, and read fedfs junctions on the local file system
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
#include "xlog.h"

/**
 * Magic string planted in the "type" attribute of junctions
 */
#define FEDFSD_JUNCTION_TYPE		"fedfs"

/**
 * Name of extended attribute containing saved mode bits
 */
#define FEDFSD_XATTR_NAME_MODE		"trusted.junction.mode"

/**
 * Name of extended attribute containing junction type
 */
#define FEDFSD_XATTR_NAME_TYPE		"trusted.junction.type"

/**
 * Name of extended attribute containing junction's FSN UUID
 */
#define FEDFSD_XATTR_NAME_FSNUUID	"trusted.junction.fsnuuid"

/**
 * Name of extended attribute containing hostname of NSDB service
 */
#define FEDFSD_XATTR_NAME_NSDB		"trusted.junction.nsdbname"

/**
 * Name of extended attribute containing port of NSDB service
 */
#define FEDFSD_XATTR_NAME_PORT		"trusted.junction.nsdbport"


/**
 * Open a file system object
 *
 * @param pathname NUL-terminated C string containing pathname of an object
 * @param fd OUT: a file descriptor number is filled in
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_open_path(const char *pathname, int *fd)
{
	int tmp;

	if (pathname == NULL || fd == NULL)
		return FEDFS_ERR_INVAL;

	tmp = open(pathname, O_DIRECTORY);
	if (tmp == -1) {
		switch (errno) {
		case EPERM:
			return FEDFS_ERR_ACCESS;
		case EACCES:
			return FEDFS_ERR_PERM;
		default:
			xlog(D_GENERAL, "%s: Failed to open path %s: %m",
				__func__, pathname);
			return FEDFS_ERR_INVAL;
		}
	}

	*fd = tmp;
	return FEDFS_OK;
}

/**
 * Predicate: is object a directory?
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_is_directory(int fd, const char *path)
{
	struct stat stb;

	if (fstat(fd, &stb) == -1) {
		xlog(D_GENERAL, "%s: failed to stat %s: %m",
				__func__, path);
		return FEDFS_ERR_ACCESS;
	}

	if (!S_ISDIR(stb.st_mode)) {
		xlog(D_CALL, "%s: %s is not a directory",
				__func__, path);
		return FEDFS_ERR_INVAL;
	}

	xlog(D_CALL, "%s: %s is a directory", __func__, path);
	return FEDFS_OK;
}

/**
 * Predicate: is a directory's sticky bit set?
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_is_sticky_bit_set(int fd, const char *path)
{
	struct stat stb;

	if (fstat(fd, &stb) == -1) {
		xlog(D_GENERAL, "%s: failed to stat %s: %m",
				__func__, path);
		return FEDFS_ERR_ACCESS;
	}

	if (stb.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)) {
		xlog(D_CALL, "%s: execute bit set on %s",
				__func__, path);
		return FEDFS_ERR_NOTJUNCT;
	}

	if (!(stb.st_mode & S_ISVTX)) {
		xlog(D_CALL, "%s: sticky bit not set on %s",
				__func__, path);
		return FEDFS_ERR_NOTJUNCT;
	}

	xlog(D_CALL, "%s: sticky bit is set on %s", __func__, path);
	return FEDFS_OK;
}

/**
 * Set just a directory's sticky bit
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_set_sticky_bit(int fd, const char *path)
{
	struct stat stb;

	if (fstat(fd, &stb) == -1) {
		xlog(D_GENERAL, "%s: failed to stat %s: %m",
			__func__, path);
		return FEDFS_ERR_ACCESS;
	}

	stb.st_mode &= ~ALLPERMS;
	stb.st_mode |= S_ISVTX;

	if (fchmod(fd, stb.st_mode) == -1) {
		xlog(D_GENERAL, "%s: failed to set sticky bit on %s: %m",
			__func__, path);
		return FEDFS_ERR_ROFS;
	}

	xlog(D_CALL, "%s: set sticky bit on %s", __func__, path);
	return FEDFS_OK;
}

/**
 * Predicate: does a directory have an xattr named "name"?
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to check
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_is_xattr_present(int fd, const char *path, const char *name)
{
	int rc;

	/*
	 * Do not assume the total number of extended attributes
	 * this object may have.
	 */
	rc = fgetxattr(fd, name, NULL, 0);
	if (rc == -1) {
		switch (errno) {
		case EPERM:
			xlog(D_CALL, "%s: no access to xattr %s on %s",
				__func__, name, path);
			return FEDFS_ERR_PERM;
		case ENODATA:
			xlog(D_CALL, "%s: no xattr %s present on %s",
				__func__, name, path);
			return FEDFS_ERR_NOTJUNCT;
		default:
			xlog(D_CALL, "%s: xattr %s not found on %s: %m",
				__func__, name, path);
			return FEDFS_ERR_IO;
		}
	}

	xlog(D_CALL, "%s: xattr %s found on %s",
			__func__, name, path);
	return FEDFS_OK;
}

/**
 * Retrieve the contents of xattr "name"
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to retrieve
 * @param contents OUT: opaque byte array containing contents of xattr
 * @param contentlen OUT: size of "contents"
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_get_xattr(int fd, const char *path, const char *name, void **contents,
		size_t *contentlen)
{
	void *xattrbuf = NULL;
	ssize_t len;

	len = fgetxattr(fd, name, xattrbuf, 0);
	if (len == -1) {
		xlog(D_GENERAL, "%s: failed to get size of xattr %s on %s: %m",
			__func__, name, path);
		return FEDFS_ERR_ACCESS;
	}

	xattrbuf = malloc(len);
	if (xattrbuf == NULL) {
		xlog(D_GENERAL, "%s: failed to get buffer for xattr %s on %s",
			__func__, name, path);
		return FEDFS_ERR_SVRFAULT;
	}

	if (fgetxattr(fd, name, xattrbuf, len) == -1) {
		xlog(D_GENERAL, "%s: failed to get xattr %s on %s: %m",
			__func__, name, path);
		free(xattrbuf);
		return FEDFS_ERR_ACCESS;
	}

	xlog(D_CALL, "%s: read xattr %s from path %s",
			__func__, name, path);
	*contents = xattrbuf;
	*contentlen = len;
	return FEDFS_OK;
}

/**
 * Update the contents of an xattr
 *
 * @param fd an open file descriptor
 * @param path NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to set
 * @param contents opaque byte array containing contents of xattr
 * @param contentlen size of "contents"
 * @return a FedFsStatus code
 *
 * The extended attribute is created if it does not exist.
 * Its contents are replaced if it does.
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_set_xattr(int fd, const char *path, const char *name,
			const void *contents, const size_t contentlen)
{
	/*
	 * XXX: Eventually should distinguish among several errors:
	 *	object isn't there, no root access, some other issue
	 */
	if (fsetxattr(fd, name, contents, contentlen, 0) == -1) {
		xlog(D_GENERAL, "%s: Failed to set xattr %s on %s: %m",
			__func__, name, path);
		return FEDFS_ERR_IO;
	}

	xlog(D_CALL, "%s: Wrote xattr %s from path %s",
			__func__, name, path);
	return FEDFS_OK;
}

/**
 * Remove one xattr
 *
 * @param fd an open file descriptor
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to set
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_remove_xattr(int fd, const char *pathname, const char *name)
{
	/*
	 * XXX: Eventually should distinguish among several errors:
	 *	object isn't there, no root access, some other issue
	 */
	if (fremovexattr(fd, name) == -1) {
		xlog(D_GENERAL, "%s: failed to remove xattr %s from %s: %m",
			__func__, name, pathname);
		return FEDFS_ERR_ACCESS;
	}
	xlog(D_CALL, "%s: removed xattr %s from path %s",
			__func__, name, pathname);
	return FEDFS_OK;
}

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

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_remove_xattr(fd, pathname, FEDFSD_XATTR_NAME_TYPE);
	if (retval != FEDFS_OK)
		goto out;
	retval = fedfs_remove_xattr(fd, pathname, FEDFSD_XATTR_NAME_FSNUUID);
	if (retval != FEDFS_OK)
		goto out;
	retval = fedfs_remove_xattr(fd, pathname, FEDFSD_XATTR_NAME_NSDB);
	if (retval != FEDFS_OK)
		goto out;
	retval = fedfs_remove_xattr(fd, pathname, FEDFSD_XATTR_NAME_PORT);

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
 */
static FedFsStatus
fedfs_store_fsn(const char *pathname, const char *fsn_uuid, const nsdb_t host)
{
	FedFsStatus retval;
	char buf[20];
	int fd, len;

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_set_xattr(fd, pathname, FEDFSD_XATTR_NAME_TYPE,
			FEDFSD_XATTR_NAME_TYPE, sizeof(FEDFSD_XATTR_NAME_TYPE));
	if (retval != FEDFS_OK)
		goto out;

	retval = fedfs_set_xattr(fd, pathname, FEDFSD_XATTR_NAME_FSNUUID,
			fsn_uuid, strlen(fsn_uuid) + 1);
	if (retval != FEDFS_OK)
		goto out;

	retval = fedfs_set_xattr(fd, pathname, FEDFSD_XATTR_NAME_NSDB,
			nsdb_hostname(host), nsdb_hostname_len(host) + 1);
	if (retval != FEDFS_OK)
		goto out;

	len = snprintf(buf, sizeof(buf), "%u", nsdb_port(host));
	retval = fedfs_set_xattr(fd, pathname, FEDFSD_XATTR_NAME_PORT, buf, len + 1);

out:
	(void)close(fd);
	return retval;
}

/**
 * Retrieve FSN information from a junction
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
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

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_get_xattr(fd, pathname, FEDFSD_XATTR_NAME_FSNUUID,
							&uuid_tmp, &len);
	if (retval != FEDFS_OK)
		goto out_err;

	retval = fedfs_get_xattr(fd, pathname, FEDFSD_XATTR_NAME_NSDB,
					&nsdbname_tmp, &len);
	if (retval != FEDFS_OK)
		goto out_err;
	retval = fedfs_get_xattr(fd, pathname, FEDFSD_XATTR_NAME_PORT,
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
 * Predicate: does "pathname" refer to an object that can become a junction?
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return true if object referred to by "pathname" can become a junction
 *
 * Returns FEDFS_OK if "pathname" refers to an object we can make into a
 * junction, or FEDFS_ERR_EXIST if "pathname" refers to something that could
 * already be a junction.  Other errors may trickle up from lower layers.
 */
FedFsStatus
fedfs_is_prejunction(const char *pathname)
{
	FedFsStatus retval;
	int fd;

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_is_directory(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = fedfs_is_sticky_bit_set(fd, pathname);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_TYPE);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_FSNUUID);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_NSDB);
	switch (retval) {
	case FEDFS_ERR_NOTJUNCT:
		break;
	case FEDFS_OK:
		goto out_exist;
	default:
		goto out_close;
	}
	
	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_PORT);
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
 * Predicate: does "pathname" refer to a junction?
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return true if object referred to by "pathname" is a junction
 *
 * Returns FEDFS_OK if "pathname" refers to a junction, or
 * FEDFS_ERR_NOTJUNCT if "pathname" does not refer to a junction, or
 * FEDFS_ERR_INVAL if "pathname" refers to something that does not exist.
 * Other errors may trickle up from lower layers.
 */
FedFsStatus
fedfs_is_junction(const char *pathname)
{
	FedFsStatus retval;
	int fd;

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_is_directory(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = fedfs_is_sticky_bit_set(fd, pathname);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_TYPE);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_FSNUUID);
	if (retval != FEDFS_OK)
		goto out_close;

	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_NSDB);
	if (retval != FEDFS_OK)
		goto out_close;
	
	retval = fedfs_is_xattr_present(fd, pathname, FEDFSD_XATTR_NAME_PORT);

out_close:
	(void)close(fd);
	return retval;
}

/**
 * Save the object's mode in an xattr.  Saved mode is human-readable.
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 */
FedFsStatus
fedfs_save_mode(const char *pathname)
{
	FedFsStatus retval;
	unsigned int mode;
	struct stat stb;
	char buf[16];
	int fd;

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	if (fstat(fd, &stb) == -1) {
		xlog(D_GENERAL, "%s: failed to stat %s: %m",
			__func__, pathname);
		return FEDFS_ERR_ACCESS;
	}

	mode = ALLPERMS & stb.st_mode;
	(void)snprintf(buf, sizeof(buf), "%o", mode);
	retval = fedfs_set_xattr(fd, pathname, FEDFSD_XATTR_NAME_MODE,
				buf, strlen(buf));
	if (retval != FEDFS_OK)
		goto out;

	retval = fedfs_set_sticky_bit(fd, pathname);
	if (retval != FEDFS_OK) {
		(void)fedfs_remove_xattr(fd, pathname,
						FEDFSD_XATTR_NAME_MODE);
		goto out;
	}

	xlog(D_CALL, "%s: saved mode %o to %s", __func__, mode, pathname);
	retval = FEDFS_OK;

out:
	(void)close(fd);
	return retval;
}

/**
 * Restore an object's mode bits
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 */
FedFsStatus
fedfs_restore_mode(const char *pathname)
{
	FedFsStatus retval;
	mode_t mode;
	size_t len;
	void *buf;
	int fd;

	retval = fedfs_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_get_xattr(fd, pathname, FEDFSD_XATTR_NAME_MODE, &buf, &len);
	if (retval != FEDFS_OK)
		goto out;

	retval = FEDFS_ERR_SVRFAULT;
	if (sscanf((char *)buf, "%o", &mode) != 1) {
		xlog(D_GENERAL, "%s: failed to parse saved mode on %s",
			__func__, pathname);
		goto out;
	}

	retval = FEDFS_ERR_ROFS;
	if (fchmod(fd, mode) == -1) {
		xlog(D_GENERAL, "%s: failed to set mode of %s to %o: %m",
			__func__, pathname, mode);
		goto out;
	}

	xlog(D_CALL, "%s: restored mode %o to %s", __func__, mode, pathname);
	retval = FEDFS_OK;

out:
	free(buf);
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

	retval = fedfs_save_mode(pathname);
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

	retval = fedfs_restore_mode(pathname);
	if (retval != FEDFS_OK)
		return retval;

	return fedfs_remove_fsn(pathname);
}
