/**
 * @file src/fedfsd/privilege.c
 * @brief Drop privileges.
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
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <libgen.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "xlog.h"

/**
 * Capabilies that fedfsd should retain, in text format.
 */
#define FEDFSD_CAPABILITIES	"cap_net_bind_service=ep "	\
				"cap_fowner=ep "		\
				"cap_dac_override=ep "		\
				"cap_sys_admin=ep"

/**
 * Clear all capabilities but a certain few.
 *
 * @return true if successful
 *
 * This permits callers to acquire privileged source ports and
 * read and alter trusted xattrs.  All other root capabilities
 * are disallowed.
 */
static _Bool
fedfsd_clear_capabilities(void)
{
	cap_t caps;
	char *text;

	caps = cap_from_text(FEDFSD_CAPABILITIES);
	if (caps == NULL) {
		xlog(L_ERROR, "Failed to allocate capability: %m");
		return false;
	}

	if (cap_set_proc(caps) == -1) {
		xlog(L_ERROR, "Failed to set capability flags: %m");
		(void)cap_free(caps);
		return false;
	}

	(void)cap_free(caps);

	/* Check our work */
	caps = cap_get_proc();
	if (caps == NULL)
		goto out;

	text = cap_to_text(caps, NULL);
	if (text == NULL)
		goto out_free;

	xlog(D_GENERAL, "Process capabilities %s", text);
	(void)cap_free(text);

out_free:
	(void)cap_free(caps);
out:
	return true;
}

/**
 * Drop root privileges
 *
 * @param uid run as this effective uid
 * @param gid run as this effective gid
 * @return true if privileges were dropped, otherwise false
 *
 * Set our effective UID and GID to that of our on-disk database.
 */
_Bool
fedfsd_drop_privileges(const uid_t uid, const gid_t gid)
{
	_Bool result = true;

	(void)umask(S_IWGRP | S_IWOTH);

	/*
	 * Don't clear capabilities when dropping root.
	 */
        if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                xlog(L_ERROR, "prctl(PR_SET_KEEPCAPS) failed: %m");
		return false;
	}

	if (setgroups(0, NULL) == -1) {
		xlog(L_ERROR, "Failed to drop supplementary groups: %m");
		return false;
	}

	/*
	 * ORDER
	 *
	 * setgid(2) first, as setuid(2) may remove privileges needed
	 * to set the group id.
	 */
	if (setgid(gid) == -1 || setuid(uid) == -1) {
		xlog(L_ERROR, "Failed to drop privileges: %m");
		return false;
	}

	result = fedfsd_clear_capabilities();

	xlog(D_CALL, "%s: Effective UID, GID: %u, %u",
			__func__, geteuid(), getegid());

	return result;
}
