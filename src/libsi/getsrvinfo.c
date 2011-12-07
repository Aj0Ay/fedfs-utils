/**
 * @file src/libsi/getsrvinfo.c
 * @brief Retrieve SRV records from DNS, modeled after getaddrinfo(3)
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <arpa/nameser_compat.h>
#include <resolv.h>

#include "getsrvinfo.h"

/**
 * Parsing overlay for DNS query result record header.  Fields are
 * in network byte order.
 */
struct rechdr {
	uint16_t		 type;
	uint16_t		 class;
	uint32_t		 ttl;
	uint16_t		 length;
} __attribute__((__packed__));

/**
 * Parsing overlay for DNS query result SRV record data.  Fields
 * are in network byte order.
 */
struct srv {
	uint16_t		 priority;
	uint16_t		 weight;
	uint16_t		 port;
	unsigned char		*target;
} __attribute__((__packed__));

/**
 * Return C string matching error value of "status"
 *
 * @param status error status returned by getsrvinfo
 * @return pointer to static NUL-terminated C string containing error message
 */
const char *
gsi_strerror(int status)
{
	static char buf[256];

	switch (status) {
	case ESI_SUCCESS:
		return "Success";
	case ESI_NONAME:
		return "Name not found";
	case ESI_AGAIN:
		return "Temporary failure in name resolution";
	case ESI_FAIL:
		return "Non-recoverable failure in name resolution";
	case ESI_NODATA:
		return "No SRV record returned";
	case ESI_SERVICE:
		return "Service is not available";
	case ESI_MEMORY:
		return "Memory allocation failure";
	case ESI_SYSTEM:
		snprintf(buf, sizeof(buf), "System error (%d): %s",
				status, strerror(errno));
		return buf;
	case ESI_PARSE:
		return "Failed to parse server response";
	}

	snprintf(buf, sizeof(buf), "Unknown error (%d)", status);
	return buf;
}

/**
 * Release a list of SRV records allocated by getsrvinfo()
 *
 * @param si pointer to first element of a list of struct srvinfo
 *
 */
void freesrvinfo(struct srvinfo *si)
{
	struct srvinfo *tmp;

	while (si != NULL) {
		tmp = si;
		si = si->si_next;
		free(tmp->si_target);
		free(tmp);
	}
}

/**
 * Ordering predicate for srvinfo lists
 *
 * @param a a srvinfo list element to compare
 * @param b another srvinfo list element to compare
 * @return true if "b" should fall later in the list than "a"
 *
 * See RFC 2782.   The list is ordered as follows:
 *
 *  o Lowest priority first.
 *  o In each priority class, highest weight first.
 */
static _Bool
srvinfo_is_after(const struct srvinfo *a, const struct srvinfo *b)
{
	if (a->si_priority > b->si_priority)
		return true;
	if (a->si_priority < b->si_priority)
		return false;

	if (a->si_weight < b->si_weight)
		return true;
	return false;
}

/**
 * Insert a srvinfo element into a list
 *
 * @param head pointer to head of list of elements
 * @param entry new list element to insert
 *
 */
static void
insert_srvinfo(struct srvinfo **head, struct srvinfo *entry)
{
	entry->si_next = *head;
	*head = entry;
}

/**
 * Insert a srvinfo element into a list, in order
 *
 * @param head pointer to head of list of elements
 * @param entry new list element to insert
 *
 */
static void
insert_srvinfo_sorted(struct srvinfo **head, struct srvinfo *entry)
{
	struct srvinfo *spot, *back;

	spot = *head;
	back = NULL;
	while (spot && srvinfo_is_after(spot, entry)) {
		back = spot;
		spot = spot->si_next;
	}

	if (spot == (*head))
		insert_srvinfo(head, entry);
	else {
		insert_srvinfo(&spot, entry);
		/* off the end of the list? */
		if (spot == entry)
			back->si_next = entry;
	}
}

/**
 * Retrieve list of SRV records from DNS service
 *
 * @param srvname NUL-terminated C string containing record type to look up
 * @param domainname NUL-terminated C string containing domain name to look up
 * @param si OUT: list of SRV record information retrieved
 * @return zero on success, or an ESI_ status code describing the error
 *
 * Caller must free list of records using freesrvinfo().
 */
int
getsrvinfo(const char *srvname, const char *domainname, struct srvinfo **si)
{
	unsigned char *msg, *comp_dn;
	struct srvinfo *results;
	unsigned short count;
	int status, i, len;
	char *exp_dn;
	HEADER *hdr;

	msg = calloc(1, NS_MAXMSG);
	exp_dn = calloc(1, NS_MAXDNAME);
	if (msg == NULL || exp_dn == NULL) {
		status = ESI_MEMORY;
		goto out;
	}

	_res.options |= RES_AAONLY;
	len = res_querydomain(srvname, domainname, C_IN, T_SRV, msg, NS_MAXMSG);
	if (len == -1) {
		switch (h_errno) {
		case HOST_NOT_FOUND:
			status = ESI_NONAME;
			break;
		case TRY_AGAIN:
			status = ESI_AGAIN;
			break;
		case NO_RECOVERY:
			status = ESI_FAIL;
			break;
		case NO_DATA:
			status = ESI_NODATA;
			break;
		default:
			fprintf(stderr, "SRV query failed for %s.%s: %s\n",
				srvname, domainname, hstrerror(h_errno));
			status = ESI_FAIL;
		}
		goto out;
	}

	hdr = (HEADER *)msg;
	count = ntohs(hdr->ancount);
	if (count == 0) {
		status = ESI_NODATA;
		goto out;
	}

	comp_dn = &msg[HFIXEDSZ];
	comp_dn += dn_skipname(comp_dn, msg + len) + QFIXEDSZ;

	results = NULL;
	for (i = 0; i < count; i++) {
		struct srvinfo *new;
		struct srv *record;
		int l;

		l = dn_expand(msg, msg + len, comp_dn, exp_dn, NS_MAXDNAME);
		if (l == -1) {
			status = ESI_PARSE;
			goto out_free;
		}

		comp_dn += l;

		record = (struct srv *)&comp_dn[10];

		l = dn_expand(msg, msg + len, comp_dn + 16, exp_dn, NS_MAXDNAME);
		if (l == -1) {
			status = ESI_PARSE;
			goto out_free;
		}

		if (count == 1 && strcmp(exp_dn, ".") == 0) {
			status = ESI_SERVICE;
			goto out_free;
		}

		new = calloc(1, sizeof(*new));
		if (new == NULL) {
			status = ESI_MEMORY;
			goto out;
		}

		new->si_target = strdup(exp_dn);
		if (new->si_target == NULL) {
			free(new);
			status = ESI_MEMORY;
			goto out;
		}
		new->si_priority = ntohs(record->priority);
		new->si_weight = ntohs(record->weight);
		new->si_port = ntohs(record->port);

		insert_srvinfo_sorted(&results, new);
	}

	status = ESI_SUCCESS;
	*si = results;

out:
	free(exp_dn);
	free(msg);
	return status;

out_free:
	freesrvinfo(results);
	goto out;
}
