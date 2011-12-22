/**
 * @file src/libjunction/xml.c
 * @brief Common utilities for managing junction XML
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

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "fedfs.h"
#include "junction.h"
#include "junction-internal.h"
#include "xlog.h"

/**
 * Predicate: is element content empty?
 *
 * @param content element content to test
 * @return true if content is empty
 */
_Bool
junction_xml_is_empty(const xmlChar *content)
{
	return content == NULL || *content == '\0';
}

/**
 * Match an XML parse tree node by its name
 *
 * @param node pointer to a node in an XML parse tree
 * @param name NUL-terminated C string containing name to match
 * @return true if "node" is named "name"
 */
_Bool
junction_xml_match_node_name(xmlNodePtr node, const xmlChar *name)
{
	return (node->type == XML_ELEMENT_NODE) &&
		(xmlStrcmp(node->name, name) == 0);
}

/**
 * Read attribute into an integer
 *
 * @param node pointer to a node in an XML parse tree
 * @param attrname NUL-terminated C string containing attribute name
 * @param value OUT: attribute's value converted to an integer 
 * @return true if attribute "attrname" has a valid integer value
 */
_Bool
junction_xml_get_int_attribute(xmlNodePtr node, const xmlChar *attrname,
		int *value)
{
	char *endptr;
	_Bool retval;
	char *prop;
	long tmp;

	retval = false;
	prop = (char *)xmlGetProp(node, attrname);
	if (prop == NULL)
		goto out;

	errno = 0;
	tmp = strtol(prop, &endptr, 10);
	if (errno != 0 || *endptr != '\0' || tmp > INT32_MAX || tmp < INT32_MIN)
		goto out;

	*value = (int)tmp;
	retval = true;

out:
	xmlFree(prop);
	return retval;
}

/**
 * Set attribute to an integer
 *
 * @param node pointer to a node in an XML parse tree
 * @param attrname NUL-terminated C string containing attribute name
 * @param value integer value to set
 * @return true if attribute "attrname" has a valid integer value
 */
void
junction_xml_set_int_attribute(xmlNodePtr node, const xmlChar *attrname,
		int value)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", value);
	xmlSetProp(node, attrname, (const xmlChar *)buf);
}

/**
 * Parse XML document in a buffer into an XML document tree
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to replace
 * @param buf opaque byte array containing XML to parse
 * @param len size of "buf" in bytes
 * @param doc OUT: an XML parse tree containing junction XML
 * @return a FedFsStatus code
 *
 * If junction_parse_xml_buf() returns success, caller must free "*doc"
 * using xmlFreeDoc(3).
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
junction_parse_xml_buf(const char *pathname, const char *name,
		void *buf, size_t len, xmlDocPtr *doc)
{
	xmlDocPtr tmp;

	tmp = xmlParseMemory(buf, (int)len);
	if (tmp == NULL) {
		xlog(D_GENERAL, "Failed to parse XML in %s(%s)\n",
			pathname, name);
		return FEDFS_ERR_SVRFAULT;
	}

	*doc = tmp;
	return FEDFS_OK;
}

/**
 * Read an XML document from an extended attribute into an XML document tree
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @param fd an open file descriptor
 * @param name NUL-terminated C string containing name of xattr to replace
 * @param doc OUT: an XML parse tree containing junction XML
 * @return a FedFsStatus code
 *
 * If junction_parse_xml_read() returns success, caller must free "*doc"
 * using xmlFreeDoc(3).
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
junction_parse_xml_read(const char *pathname, int fd, const char *name,
		xmlDocPtr *doc)
{
	FedFsStatus retval;
	void *buf = NULL;
	size_t len;

	retval = junction_get_xattr(fd, pathname, name, &buf, &len);
	if (retval != FEDFS_OK)
		return retval;

	xlog(D_CALL, "%s: XML document contained in junction:\n%.*s",
		__func__, len, buf);

	retval = junction_parse_xml_buf(pathname, name, buf, len, doc);

	free(buf);
	return retval;
}

/**
 * Read an XML document from an extended attribute into an XML document tree
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to replace
 * @param doc OUT: an XML parse tree containing junction XML
 * @return a FedFsStatus code
 *
 * If junction_parse_xml() returns success, caller must free "*doc"
 * using xmlFreeDoc(3).
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
FedFsStatus
junction_xml_parse(const char *pathname, const char *name, xmlDocPtr *doc)
{
	FedFsStatus retval;
	int fd;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	retval = junction_parse_xml_read(pathname, fd, name, doc);

	(void)close(fd);
	return retval;
}

/**
 * Write an XML document into an extended attribute
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @param name NUL-terminated C string containing name of xattr to replace
 * @param doc an XML parse tree containing junction XML
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
FedFsStatus
junction_xml_write(const char *pathname, const char *name, xmlDocPtr doc)
{
	xmlChar *buf = NULL;
	FedFsStatus retval;
	int fd, len;

	retval = junction_open_path(pathname, &fd);
	if (retval != FEDFS_OK)
		return retval;

	xmlIndentTreeOutput = 1;
	xmlDocDumpFormatMemoryEnc(doc, &buf, &len, "UTF-8", 1);
	retval = junction_set_xattr(fd, pathname, name, buf, len);
	xmlFree(buf);

	(void)close(fd);
	return retval;
}
