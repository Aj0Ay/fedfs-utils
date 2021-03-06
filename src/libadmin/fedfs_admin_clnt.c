/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include <memory.h> /* for memset */
#include "fedfs_admin.h"
#include <string.h>
#define FEDFS_ADMIN_X

/* Default timeout can be changed using clnt_control() */
static struct timeval TIMEOUT = { 25, 0 };

void *
fedfs_null_1(void *argp, CLIENT *clnt)
{
	static char clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_NULL,
		(xdrproc_t) xdr_void, (caddr_t) argp,
		(xdrproc_t) xdr_void, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return ((void *)&clnt_res);
}

FedFsStatus *
fedfs_create_junction_1(FedFsCreateArgs *argp, CLIENT *clnt)
{
	static FedFsStatus clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_CREATE_JUNCTION,
		(xdrproc_t) xdr_FedFsCreateArgs, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsStatus, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsStatus *
fedfs_delete_junction_1(FedFsPath *argp, CLIENT *clnt)
{
	static FedFsStatus clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_DELETE_JUNCTION,
		(xdrproc_t) xdr_FedFsPath, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsStatus, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsLookupRes *
fedfs_lookup_junction_1(FedFsLookupArgs *argp, CLIENT *clnt)
{
	static FedFsLookupRes clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_LOOKUP_JUNCTION,
		(xdrproc_t) xdr_FedFsLookupArgs, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsLookupRes, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsStatus *
fedfs_create_replication_1(FedFsCreateArgs *argp, CLIENT *clnt)
{
	static FedFsStatus clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_CREATE_REPLICATION,
		(xdrproc_t) xdr_FedFsCreateArgs, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsStatus, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsStatus *
fedfs_delete_replication_1(FedFsPath *argp, CLIENT *clnt)
{
	static FedFsStatus clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_DELETE_REPLICATION,
		(xdrproc_t) xdr_FedFsPath, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsStatus, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsLookupRes *
fedfs_lookup_replication_1(FedFsLookupArgs *argp, CLIENT *clnt)
{
	static FedFsLookupRes clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_LOOKUP_REPLICATION,
		(xdrproc_t) xdr_FedFsLookupArgs, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsLookupRes, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsStatus *
fedfs_set_nsdb_params_1(FedFsSetNsdbParamsArgs *argp, CLIENT *clnt)
{
	static FedFsStatus clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_SET_NSDB_PARAMS,
		(xdrproc_t) xdr_FedFsSetNsdbParamsArgs, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsStatus, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsGetNsdbParamsRes *
fedfs_get_nsdb_params_1(FedFsNsdbName *argp, CLIENT *clnt)
{
	static FedFsGetNsdbParamsRes clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_GET_NSDB_PARAMS,
		(xdrproc_t) xdr_FedFsNsdbName, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsGetNsdbParamsRes, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}

FedFsGetLimitedNsdbParamsRes *
fedfs_get_limited_nsdb_params_1(FedFsNsdbName *argp, CLIENT *clnt)
{
	static FedFsGetLimitedNsdbParamsRes clnt_res;

	memset((char *)&clnt_res, 0, sizeof(clnt_res));
	if (clnt_call (clnt, FEDFS_GET_LIMITED_NSDB_PARAMS,
		(xdrproc_t) xdr_FedFsNsdbName, (caddr_t) argp,
		(xdrproc_t) xdr_FedFsGetLimitedNsdbParamsRes, (caddr_t) &clnt_res,
		TIMEOUT) != RPC_SUCCESS) {
		return (NULL);
	}
	return (&clnt_res);
}
