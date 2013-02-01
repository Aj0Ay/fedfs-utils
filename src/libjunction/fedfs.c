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

/*
 * A FedFS junction is an FSN, represented in a well-formed XML document:
 *
 * <?xml version="1.0" encoding="UTF-8"?>
 * <junction>
 *   <savedmode bits="1777" />
 *   <fileset>
 *     <name fsnuuid="d2b09895-98ff-415e-ac73-565fad7b429b"
 *           nsdbname="nsdb.example.net"
 *           nsdbport="389" />
 *   </fileset>
 * </junction>
 *
 * FedFS junction XML is stored in an extended attribute called
 * "trusted.junction.nfs".   The parent object is a directory.
 *
 * To help file servers discover junctions efficiently, the directory
 * has no execute bits, and the sticky bit is set.
 *
 * Finally, for pre-existing directories that are converted to
 * junctions, their mode bits are saved in an extended attribute called
 * "trusted.junction.mode".  When the junction data is removed, the
 * directory's mode bits are restored from this information.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fedfs.h"
#include "nsdb.h"
#include "junction.h"
#include "junction-internal.h"
#include "xlog.h"

/**
 * Tag name of FSN element of a junction XML document
 */
#define FEDFS_XML_FSN_TAG		(const xmlChar *)"name"

/**
 * Name of FSN UUID attribute on a fileset name element
 */
#define FEDFS_XML_FSN_UUID_ATTR		(const xmlChar *)"fsnuuid"

/**
 * Name of NSDB hostname attribute on a fileset name element
 */
#define FEDFS_XML_FSN_NSDBNAME_ATTR	(const xmlChar *)"nsdbname"

/**
 * Name of NSDB port attribute on a fileset name element
 */
#define FEDFS_XML_FSN_NSDBPORT_ATTR	(const xmlChar *)"nsdbport"

/**
 * XPath path to first fileset name element in a junction document
 */
#define FEDFS_XML_FSN_XPATH		(const xmlChar *)	\
						"/junction/fileset/name[1]"


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

	retval = junction_remove_xattr(fd, pathname, JUNCTION_XATTR_NAME_NFS);

	(void)close(fd);
	return retval;
}

/**
 * Construct fileset's "name" element
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fileset parent node of new FSN element
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param nsdb_name a NUL-terminated C string containing NSDB hostname
 * @param nsdb_port the port number of the NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_name_xml(const char *pathname, xmlNodePtr fileset,
		const char *fsn_uuid, const char *nsdb_name,
		unsigned short nsdb_port)
{
	xmlNodePtr new;

	new = xmlNewTextChild(fileset , NULL, FEDFS_XML_FSN_TAG, NULL);
	if (new == NULL) {
		xlog(D_GENERAL, "%s: Failed to add FSN element for %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}

	xmlSetProp(new, FEDFS_XML_FSN_UUID_ATTR, (const xmlChar *)fsn_uuid);
	xmlSetProp(new, FEDFS_XML_FSN_NSDBNAME_ATTR, (const xmlChar *)nsdb_name);
	if (nsdb_port == 0)
		nsdb_port = LDAP_PORT;
	junction_xml_set_int_attribute(new, FEDFS_XML_FSN_NSDBPORT_ATTR,
								nsdb_port);

	return FEDFS_OK;
}

/**
 * Construct a "fileset" element
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param root root element of XML document tree
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param nsdb_name a NUL-terminated C string containing NSDB hostname
 * @param nsdb_port the port number of the NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_fileset_xml(const char *pathname, xmlNodePtr root,
		const char *fsn_uuid, const char *nsdb_name,
		unsigned short nsdb_port)
{
	xmlNodePtr fileset;

	fileset = xmlNewTextChild(root, NULL, JUNCTION_XML_FILESET_TAG, NULL);
	if (fileset == NULL) {
		xlog(D_GENERAL, "%s: Failed to add fileset element for %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}

	return fedfs_name_xml(pathname, fileset, fsn_uuid, nsdb_name, nsdb_port);
}

/**
 * Construct a "savedmode" element
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param root root element of XML document tree
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_savedmode_xml(const char *pathname, xmlNodePtr root)
{
	xmlNodePtr savedmode;
	FedFsStatus retval;
	mode_t mode;
	char buf[8];

	retval = junction_get_mode(pathname, &mode);
	if (retval != FEDFS_OK)
		return retval;

	savedmode = xmlNewTextChild(root, NULL, JUNCTION_XML_SAVEDMODE_TAG, NULL);
	if (savedmode == NULL) {
		xlog(D_GENERAL, "%s: Failed to add savedmode element for %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}

	(void)snprintf(buf, sizeof(buf), "%o", ALLPERMS & mode);
	xmlSetProp(savedmode, JUNCTION_XML_MODEBITS_ATTR, (const xmlChar *)buf);

	return FEDFS_OK;
}

/**
 * Construct FedFS junction XML document
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param doc an XML parse tree in which to construct the junction XML document
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param nsdb_name a NUL-terminated C string containing NSDB hostname
 * @param nsdb_port the port number of the NSDB
 * @return a FedFsStatus code
 */
static FedFsStatus
fedfs_build_xml(const char *pathname, xmlDocPtr doc,
		const char *fsn_uuid, const char *nsdb_name,
		unsigned short nsdb_port)
{
	FedFsStatus retval;
	xmlNodePtr root;

	root = xmlNewNode(NULL, JUNCTION_XML_ROOT_TAG);
	if (root == NULL) {
		xlog(D_GENERAL, "%s: Failed to create root element for %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}
	(void)xmlDocSetRootElement(doc, root);

	retval = fedfs_savedmode_xml(pathname, root);
	if (retval != FEDFS_OK)
		return retval;

	return fedfs_fileset_xml(pathname, root, fsn_uuid, nsdb_name, nsdb_port);
}

/**
 * Write FedFS information into a FedFS junction extended attribute
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param doc an empty XML parse tree in which to construct the junction XML document
 * @param fsn_uuid NUL-terminated C string containing FSN UUID to store
 * @param nsdb_name a NUL-terminated C string containing NSDB hostname
 * @param nsdb_port the port number of the NSDB
 * @return a FedFsStatus code
 *
 * @note Access to trusted attributes requires CAP_SYS_ADMIN.
 */
static FedFsStatus
fedfs_write_junction(const char *pathname, xmlDocPtr doc,
		const char *fsn_uuid, const char *nsdb_name,
		unsigned short nsdb_port)
{
	FedFsStatus retval;

	retval = fedfs_build_xml(pathname, doc, fsn_uuid, nsdb_name, nsdb_port);
	if (retval != FEDFS_OK)
		return retval;

	return junction_xml_write(pathname, JUNCTION_XATTR_NAME_NFS, doc);
}

/**
 * Store FedFS information into a junction object
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
	xmlDocPtr doc;

	doc = xmlNewDoc((xmlChar *)"1.0");
	if (doc == NULL) {
		xlog(D_GENERAL, "%s: Failed to create XML doc for %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = fedfs_write_junction(pathname, doc, fsn_uuid,
					nsdb_hostname(host), nsdb_port(host));

	xmlFreeDoc(doc);
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
 * Parse fileset name information from an XML node
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param node root of XML parse subtree containing fileset name element
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * If fedfs_parse_node() returns FEDFS_OK, caller must free the string
 * returned in "fsn_uuid" with free(3) and the NSDB host returned in "host"
 * with nsdb_free_nsdb().
 */
static FedFsStatus
fedfs_parse_node(const char *pathname, xmlNodePtr node,
		char **fsn_uuid, nsdb_t *host)
{
	xmlChar *nsdb_name_tmp, *fsn_uuid_tmp;
	FedFsStatus retval;
	nsdb_t host_tmp;
	char *tmp;
	int port;

	fsn_uuid_tmp = xmlGetProp(node, FEDFS_XML_FSN_UUID_ATTR);
	nsdb_name_tmp = xmlGetProp(node, FEDFS_XML_FSN_NSDBNAME_ATTR);

	retval = FEDFS_ERR_NOTJUNCT;
	if (fsn_uuid_tmp == NULL) {
		xlog(D_GENERAL, "%s: No UUID found in %s\n",
			__func__, pathname);
		goto out;
	}
	if (nsdb_name_tmp == NULL) {
		xlog(D_GENERAL, "%s: No NSDB name found in %s\n",
			__func__, pathname);
		goto out;
	}

	if (!junction_xml_get_int_attribute(node,
					FEDFS_XML_FSN_NSDBPORT_ATTR, &port))
		port = LDAP_PORT;
	if (port < 1 || port > UINT16_MAX) {
		xlog(D_GENERAL, "%s: Bad NSDB port value in %s\n",
			__func__, pathname);
		goto out;
	}

	retval = FEDFS_ERR_SVRFAULT;
	tmp = strdup((char *)fsn_uuid_tmp);
	if (tmp == NULL)
		goto out;

	retval = FEDFS_ERR_NSDB_PARAMS;
	if (nsdb_lookup_nsdb((const char *)nsdb_name_tmp, (unsigned short)port,
					&host_tmp) != FEDFS_OK) {
		xlog(D_GENERAL, "%s: No NSDB params for %s\n",
			__func__, nsdb_name_tmp);
		free(tmp);
		goto out;
	}

	*fsn_uuid = tmp;
	*host = host_tmp;
	retval = FEDFS_OK;

out:
	xmlFree(nsdb_name_tmp);
	xmlFree(fsn_uuid_tmp);
	return retval;
}

/**
 * Parse fileset name information from a nodeset
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param nodeset XML path context containing junction XML
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * If fedfs_parse_nodeset() returns FEDFS_OK, caller must free the string
 * returned in "fsn_uuid" with free(3) and the NSDB host returned in "host"
 * with nsdb_free_nsdb().
 */
static FedFsStatus
fedfs_parse_nodeset(const char *pathname, xmlNodeSetPtr nodeset,
		char **fsn_uuid, nsdb_t *host)
{
	if (xmlXPathNodeSetIsEmpty(nodeset)) {
		xlog(D_GENERAL, "%s: No fileset names found in %s\n",
			__func__, pathname);
		return FEDFS_ERR_NOTJUNCT;
	}

	return fedfs_parse_node(pathname, nodeset->nodeTab[0],
					fsn_uuid, host);
}

/**
 * Parse fileset name information from junction XML
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param context XML path context containing junction XML
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * If fedfs_parse_context() returns FEDFS_OK, caller must free the string
 * returned in "fsn_uuid" with free(3) and the NSDB host returned in "host"
 * with nsdb_free_nsdb().
 */
static FedFsStatus
fedfs_parse_context(const char *pathname, xmlXPathContextPtr context,
		char **fsn_uuid, nsdb_t *host)
{
	xmlXPathObjectPtr object;
	FedFsStatus retval;

	object = xmlXPathEvalExpression(FEDFS_XML_FSN_XPATH, context);
	if (object == NULL) {
		xlog(D_GENERAL, "%s: Failed to evaluate XML in %s\n",
			__func__, pathname);
		return FEDFS_ERR_NOTJUNCT;
	}

	retval = fedfs_parse_nodeset(pathname, object->nodesetval,
					fsn_uuid, host);

	xmlXPathFreeObject(object);
	return retval;
}

/**
 * Parse fileset name information from junction XML
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param doc XML parse tree containing junction XML document
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * If fedfs_parse_xml() returns FEDFS_OK, caller must free the string returned
 * in "fsn_uuid" with free(3) and the NSDB host returned in "host" with
 * nsdb_free_nsdb().
 */
static FedFsStatus
fedfs_parse_xml(const char *pathname, xmlDocPtr doc, char **fsn_uuid, nsdb_t *host)
{
	xmlXPathContextPtr context;
	FedFsStatus retval;

	context = xmlXPathNewContext(doc);
	if (context == NULL) {
		xlog(D_GENERAL, "%s: Failed to create XPath context from %s\n",
			__func__, pathname);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = fedfs_parse_context(pathname, context, fsn_uuid, host);

	xmlXPathFreeContext(context);
	return retval;
}

/**
 * Retrieve FSN information from a FedFS junction
 *
 * @param pathname NUL-terminated C string containing pathname of a junction
 * @param fsn_uuid OUT: NUL-terminated C string containing FSN UUID to store
 * @param host OUT: an initialized nsdb_t object
 * @return a FedFsStatus code
 *
 * If fedfs_get_fsn() returns FEDFS_OK, caller must free the string returned
 * in "fsn_uuid" with free(3) and the NSDB host returned in "host" with
 * nsdb_free_nsdb().
 */
FedFsStatus
fedfs_get_fsn(const char *pathname, char **fsn_uuid, nsdb_t *host)
{
	FedFsStatus retval;
	xmlDocPtr doc;

	if (fsn_uuid == NULL || host == NULL)
		return FEDFS_ERR_INVAL;

	retval = junction_xml_parse(pathname, JUNCTION_XATTR_NAME_NFS, &doc);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_parse_xml(pathname, doc, fsn_uuid, host);

	xmlFreeDoc(doc);
	return retval;
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
 *				already a junction
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

	retval = junction_is_xattr_present(fd, pathname, JUNCTION_XATTR_NAME_NFS);
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
 * Verify that junction contains FedFS junction XML
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * Return values:
 *	FEDFS_OK:		"pathname" refers to a FedFS junction
 *	FEDFS_ERR_NOTJUNCT:	"pathname" refers to something that is
 *				not a FedFS junction
 *	FEDFS_ERR_INVAL:	"pathname" does not exist
 *	Other:			Some error occurred, "pathname" not
 *				investigated
 *
 * NB: This is an expensive test.  However, it is only done if the object
 * actually has a junction extended attribute, meaning it should be done
 * rarely.  If this is really a problem, we can make the XML test cheaper.
 */
static FedFsStatus
fedfs_is_junction_xml(const char *pathname)
{
	FedFsStatus retval;
	char *fsn_uuid;
	xmlDocPtr doc;
	nsdb_t host;

	retval = junction_xml_parse(pathname, JUNCTION_XATTR_NAME_NFS, &doc);
	if (retval != FEDFS_OK)
		return retval;

	retval = fedfs_parse_xml(pathname, doc, &fsn_uuid, &host);
	if (retval != FEDFS_OK)
		goto out;

	free(fsn_uuid);
	nsdb_free_nsdb(host);
out:
	xmlFreeDoc(doc);
	return retval;
}

/**
 * Predicate: does "pathname" refer to a FedFS junction?
 *
 * @param pathname NUL-terminated C string containing pathname of a directory
 * @return a FedFsStatus code
 *
 * Return values:
 *	FEDFS_OK:		"pathname" refers to a FedFS junction
 *	FEDFS_ERR_NOTJUNCT:	"pathname" refers to an object that is
 *				not a FedFS junction
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

	retval = junction_is_xattr_present(fd, pathname, JUNCTION_XATTR_NAME_NFS);
	if (retval != FEDFS_OK)
		goto out_close;

	(void)close(fd);

	return fedfs_is_junction_xml(pathname);

out_close:
	(void)close(fd);
	return retval;
}
