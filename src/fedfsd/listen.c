/**
 * @file src/fedfsd/listen.c
 * @brief Create fedfsd RPC service listener endpoints.
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

#include <sys/socket.h>
#include <sys/resource.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/svc.h>

#include "fedfs.h"
#include "nsdb.h"
#include "fedfsd.h"
#include "xlog.h"

#define SVC_CREATE_XPRT_CACHE_SIZE	(8)
static SVCXPRT *fedfsd_xprt_cache[SVC_CREATE_XPRT_CACHE_SIZE] = { NULL, };

/**
 * Unregister the FedFS ADMIN service with the local portmapper
 */
static void
fedfsd_unregister(void)
{
	svc_unreg(FEDFS_PROG, FEDFS_V1);
}

/**
 * Handle signals
 */
static void
fedfsd_signalled(int signum)
{
	fedfsd_unregister();
	xlog(L_NOTICE, "Caught signal %d, exiting", signum);
	exit(0);
}

/**
 * Set up signal handlers
 */
static void
fedfsd_init_signal_handlers(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	/*
	 * Ignore SIGPIPE to avoid exiting sideways when peers
	 * close their TCP connection while we're trying to reply
	 * to them.
	 */
	sa.sa_handler = SIG_IGN;
	(void)sigaction(SIGPIPE, &sa, NULL);
	(void)sigaction(SIGCHLD, &sa, NULL);

	sa.sa_handler = fedfsd_signalled;
	(void)sigaction(SIGHUP, &sa, NULL);
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);
}

static _Bool
fedfsd_compare_sockaddr4(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	const struct sockaddr_in *sin1 = (const struct sockaddr_in *)sa1;
	const struct sockaddr_in *sin2 = (const struct sockaddr_in *)sa2;
	return sin1->sin_addr.s_addr == sin2->sin_addr.s_addr;
}

static _Bool
fedfsd_compare_sockaddr6(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	const struct sockaddr_in6 *sin1 = (const struct sockaddr_in6 *)sa1;
	const struct sockaddr_in6 *sin2 = (const struct sockaddr_in6 *)sa2;
	const struct in6_addr *in1 = &sin1->sin6_addr;
	const struct in6_addr *in2 = &sin2->sin6_addr;

	if (IN6_IS_ADDR_LINKLOCAL(in1) && IN6_IS_ADDR_LINKLOCAL(in2))
		if (sin1->sin6_scope_id != sin2->sin6_scope_id)
			return false;

	return IN6_ARE_ADDR_EQUAL(in1, in2);
}

/**
 * Compare two socket addresses
 *
 * @param sa1 pointer to a socket address
 * @param sa2 pointer to a socket address
 * @return true if the two socket addresses contain equivalent network addresses
 */
static inline _Bool
fedfsd_compare_sockaddr(const struct sockaddr *sa1, const struct sockaddr *sa2)
{
	if (sa1 == NULL || sa2 == NULL)
		return false;

	if (sa1->sa_family == sa2->sa_family)
		switch (sa1->sa_family) {
		case AF_INET:
			return fedfsd_compare_sockaddr4(sa1, sa2);
		case AF_INET6:
			return fedfsd_compare_sockaddr6(sa1, sa2);
		}

	return false;
}

/**
 * Cache an SVC xprt in case there are more programs or versions to register against it.
 *
 * @param xprt pointer to SVCXPRT to cache
 */
static void
fedfsd_cache_xprt(SVCXPRT *xprt)
{
	unsigned int i;

	/* Check if we've already got this one... */
	for (i = 0; i < SVC_CREATE_XPRT_CACHE_SIZE; i++)
		if (fedfsd_xprt_cache[i] == xprt)
			return;

	/* No, we don't.  Cache it. */
	for (i = 0; i < SVC_CREATE_XPRT_CACHE_SIZE; i++)
		if (fedfsd_xprt_cache[i] == NULL) {
			fedfsd_xprt_cache[i] = xprt;
			return;
		}

	xlog(L_ERROR, "%s: Failed to cache an xprt", __func__);
}

/*
 * Find a previously cached SVC xprt structure with the given bind address and transport semantics.
 *
 * @param bindaddr bind socket address to search for
 * @param nconf netconfig to search for
 * @return pointer to a cached SVC xprt.
 *
 * If no matching SVC XPRT can be found, NULL is returned.
 */
static SVCXPRT *
fedfsd_find_xprt(const struct sockaddr *bindaddr, const struct netconfig *nconf)
{
	unsigned int i;

	for (i = 0; i < SVC_CREATE_XPRT_CACHE_SIZE; i++) {
		SVCXPRT *xprt = fedfsd_xprt_cache[i];
		struct sockaddr *sap;

		if (xprt == NULL)
			continue;
		if (strcmp(nconf->nc_netid, xprt->xp_netid) != 0)
			continue;
		sap = (struct sockaddr *)xprt->xp_ltaddr.buf;
		if (!fedfsd_compare_sockaddr(bindaddr, sap))
			continue;
		return xprt;
	}
	return NULL;
}

/**
 * Set up an appropriate listen bind address, given "port" and "nconf".
 *
 * @param nconf netconfig parameters
 * @param port IP port number to listen on
 * @return getaddrinfo(3) results if successful.  Caller must free results with freeaddrinfo(3).
 */
static struct addrinfo *
fedfsd_create_bindaddr(struct netconfig *nconf, const uint16_t port)
{
	struct addrinfo *ai;
	struct addrinfo hint = {
		.ai_flags	= AI_PASSIVE | AI_NUMERICSERV,
	};
	char buf[8];
	int error;

	if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
		hint.ai_family = AF_INET;
	else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
		hint.ai_family = AF_INET6;
	else {
		xlog(L_ERROR, "Unrecognized bind address family: %s",
			nconf->nc_protofmly);
		return NULL;
	}

	if (strcmp(nconf->nc_proto, NC_UDP) == 0)
		hint.ai_protocol = (int)IPPROTO_UDP;
	else if (strcmp(nconf->nc_proto, NC_TCP) == 0)
		hint.ai_protocol = (int)IPPROTO_TCP;
	else {
		xlog(L_ERROR, "Unrecognized bind address protocol: %s",
			nconf->nc_proto);
		return NULL;
	}

	(void)snprintf(buf, sizeof(buf), "%u", port);
	error = getaddrinfo(NULL, buf, &hint, &ai);
	switch (error) {
	case 0:
		return ai;
	case EAI_SYSTEM:
		xlog(L_ERROR, "Failed to construct bind address: %m");
		break;
	default:
		xlog(L_ERROR, "Failed to construct bind address: %s",
			gai_strerror(error));
		break;
	}

	return NULL;
}

/**
 * Create a listener socket on a specific bindaddr
 *
 * @param sap bind socket address for listener
 * @param salen size of bind socket address
 * @param nconf netconfig parameters
 * @return an open, bound, and possibly socket file descriptor
 *
 * Set special socket options to allow it to share the same port
 * as other listeners.
 */
static int
fedfsd_create_sock(const struct sockaddr *sap, socklen_t salen,
		struct netconfig *nconf)
{
	int fd, type, protocol;
	int one = 1;

	switch(nconf->nc_semantics) {
	case NC_TPI_CLTS:
		type = SOCK_DGRAM;
		break;
	case NC_TPI_COTS_ORD:
		type = SOCK_STREAM;
		break;
	default:
		xlog(D_GENERAL, "%s: Unrecognized bind address semantics: %u",
			__func__, nconf->nc_semantics);
		return -1;
	}

	if (strcmp(nconf->nc_proto, NC_UDP) == 0)
		protocol = (int)IPPROTO_UDP;
	else if (strcmp(nconf->nc_proto, NC_TCP) == 0)
		protocol = (int)IPPROTO_TCP;
	else {
		xlog(D_GENERAL, "%s: Unrecognized bind address protocol: %s",
			__func__, nconf->nc_proto);
		return -1;
	}

	fd = socket((int)sap->sa_family, type, protocol);
	if (fd == -1) {
		xlog(L_ERROR, "Could not make a socket: %m");
		return -1;
	}

	if (sap->sa_family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
				&one, sizeof(one)) == -1) {
			xlog(L_ERROR, "Failed to set IPV6_V6ONLY: %m");
			(void)close(fd);
			return -1;
		}
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
		       &one, sizeof(one)) == -1) {
		xlog(L_ERROR, "Failed to set SO_REUSEADDR: %m");
		(void)close(fd);
		return -1;
	}

	if (bind(fd, sap, salen) == -1) {
		xlog(L_ERROR, "Could not bind socket: %m");
		(void)close(fd);
		return -1;
	}

	if (nconf->nc_semantics == NC_TPI_COTS_ORD)
		if (listen(fd, SOMAXCONN) == -1) {
			xlog(L_ERROR, "Could not listen on socket: %m");
			(void)close(fd);
			return -1;
		}

	return fd;
}

/**
 * Create a listener on a random ephemeral port
 *
 * @param name NUL-terminated C string containing name of new service
 * @param program RPC program number to register
 * @param version RPC version number to register
 * @param dispatch dispatch function that handles incoming RPC requests
 * @param nconf netconfig parameters
 * @return count of started listeners (one or zero).
 *
 * The simple case is allowing the TI-RPC library to create a
 * transport itself, given just the bind address and transport
 * semantics.
 *
 * The xprt cache is ignored in this path, since the user is
 * not interested in sharing listeners or ports, and the library
 * automatically avoids ports already in use.
 */
static unsigned int
fedfsd_create_nconf_rand_port(const char *name, rpcprog_t program,
		rpcvers_t version,
		void (*dispatch)(struct svc_req *, SVCXPRT *),
		struct netconfig *nconf)
{
	struct t_bind bindaddr;
	struct addrinfo *ai;
	SVCXPRT	*xprt;

	ai = fedfsd_create_bindaddr(nconf, 0);
	if (ai == NULL)
		return 0;

	bindaddr.addr.buf = ai->ai_addr;
	bindaddr.qlen = SOMAXCONN;

	xprt = svc_tli_create(RPC_ANYFD, nconf, &bindaddr, 0, 0);
	freeaddrinfo(ai);
	if (xprt == NULL) {
		xlog(D_GENERAL, "Failed to create listener xprt "
			"(%s, %u, %s)", name, version, nconf->nc_netid);
		return 0;
	}

	if (!svc_reg(xprt, program, version, dispatch, nconf)) {
		/* svc_reg(3) destroys @xprt in this case */
		xlog(D_GENERAL, "Failed to register (%s, %u, %s)",
				name, version, nconf->nc_netid);
		return 0;
	}

	xlog(D_CALL, "Created listener for %s successfully",
		nconf->nc_netid);
	return 1;
}

/**
 * Create a listener on a specific port
 *
 * @param name NUL-terminated C string containing name of new service
 * @param program RPC program number to register
 * @param version RPC version number to register
 * @param dispatch dispatch function that handles incoming RPC requests
 * @param port IP port number to listen on
 * @param nconf netconfig parameters
 * @return count of started listeners (one or zero).
 *
 * If a port is specified on the command line, that port value will be
 * the same for all listeners created here.  Create each listener socket
 * in advance and set SO_REUSEADDR, rather than allowing the RPC library
 * to create the listeners for us on a randomly chosen port (RPC_ANYFD).
 *
 * Also, to support multiple RPC versions on the same listener, register
 * any new versions on the same transport that is already handling other
 * versions on the same bindaddr and transport.  To accomplish this,
 * cache previously created xprts on a list, and check that list before
 * creating a new socket for this [program, version].
 */
static unsigned int
fedfsd_create_nconf_fixed_port(const char *name, rpcprog_t program,
		rpcvers_t version,
		void (*dispatch)(struct svc_req *, SVCXPRT *),
		const uint16_t port, struct netconfig *nconf)
{
	struct addrinfo *ai;
	SVCXPRT	*xprt;

	ai = fedfsd_create_bindaddr(nconf, port);
	if (ai == NULL)
		return 0;

	xprt = fedfsd_find_xprt(ai->ai_addr, nconf);
	if (xprt == NULL) {
		int fd;

		fd = fedfsd_create_sock(ai->ai_addr, ai->ai_addrlen, nconf);
		if (fd == -1)
			goto out_free;

		xprt = svc_tli_create(fd, nconf, NULL, 0, 0);
		if (xprt == NULL) {
			xlog(D_GENERAL, "Failed to create listener xprt "
				"(%s, %u, %s)", name, version, nconf->nc_netid);
			(void)close(fd);
			goto out_free;
		}
	}

	if (!svc_reg(xprt, program, version, dispatch, nconf)) {
		/* svc_reg(3) destroys @xprt in this case */
		xlog(L_ERROR, "Failed to register (%s, %u, %s).",
				name, version, nconf->nc_netid);
		goto out_free;
	}

	fedfsd_cache_xprt(xprt);
	freeaddrinfo(ai);
	xlog(D_CALL, "Created listener for %s successfully",
		nconf->nc_netid);
	return 1;

out_free:
	freeaddrinfo(ai);
	return 0;
}

/**
 * Create one listener, given "port" and "nconf".
 *
 * @name: NUL-terminated C string containing name of new service
 * @param program RPC program number to register
 * @param version RPC version number to register
 * @param dispatch dispatch function that handles incoming RPC requests
 * @param port IP port number to listen on
 * @param nconf netconfig parameters
 * @return count of started listeners (one or zero).
 */
static unsigned int
fedfsd_svc_create_nconf(const char *name, const rpcprog_t program,
		const rpcvers_t version,
		void (*dispatch)(struct svc_req *, SVCXPRT *),
		const uint16_t port, struct netconfig *nconf)
{
	if (port != 0)
		return fedfsd_create_nconf_fixed_port(name, program,
					version, dispatch, port, nconf);

	return fedfsd_create_nconf_rand_port(name, program, version,
					dispatch, nconf);
}

/**
 * Start up RPC listeners
 *
 * @name: NUL-terminated C string containing name of new service
 * @param program RPC program number to register
 * @param version RPC version number to register
 * @param dispatch dispatch function that handles incoming RPC requests
 * @param port if not zero, transport listens on this port
 *
 * Sets up network transports for receiving incoming RPC requests,
 * then invokes the RPC dispatcher.  Normally does not return.
 */
void
fedfsd_svc_create(const char *name, rpcprog_t program, rpcvers_t version,
		void (*dispatch)(struct svc_req *, SVCXPRT *),
		const uint16_t port)
{
	unsigned int visible, up;
	struct netconfig *nconf;
	void *handlep;

	fedfsd_unregister();

	handlep = setnetconfig();
	if (handlep == NULL) {
		xlog(L_ERROR, "Failed to access local netconfig database: %s",
			nc_sperror());
		return;
	}

	visible = 0;
	up = 0;
	while ((nconf = getnetconfig(handlep)) != NULL) {
		if (!(nconf->nc_flag & NC_VISIBLE))
			continue;
		visible++;
		up += fedfsd_svc_create_nconf(name, program, version,
						dispatch, port, nconf);
	}

	if (visible == 0)
		xlog(L_ERROR, "Failed to find any visible netconfig entries");

	if (endnetconfig(handlep) == -1)
		xlog(L_ERROR, "Failed to close local netconfig database: %s",
			nc_sperror());

	if (up > 0) {
		fedfsd_init_signal_handlers();
		atexit(fedfsd_unregister);
		svc_run();
	} else
		xlog(L_ERROR, "No listeners were started");
}
