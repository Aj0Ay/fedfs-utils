/**
 * @file src/libadmin/fedfs_admin.x
 * @brief FedFS ADMIN protocol RPCL specification
 */

#ifdef RPC_CLNT
%#include <string.h>
#endif

/*
 * Copyright (c) 2010-2012 IETF Trust and the persons identified
 * as authors of the code.  All rights reserved.
 *
 * The authors of the code are the authors of
 * [draft-ietf-nfsv4-federated-fs-admin-xx.txt]: J. Lentini,
 * C. Everhart, D. Ellard, R. Tewari, and M. Naik.
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *   EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

enum FedFsStatus {
 FEDFS_OK                                 = 0,
 FEDFS_ERR_ACCESS                         = 1,
 FEDFS_ERR_BADCHAR                        = 2,
 FEDFS_ERR_BADNAME                        = 3,
 FEDFS_ERR_NAMETOOLONG                    = 4,
 FEDFS_ERR_LOOP                           = 5,
 FEDFS_ERR_BADXDR                         = 6,
 FEDFS_ERR_EXIST                          = 7,
 FEDFS_ERR_INVAL                          = 8,
 FEDFS_ERR_IO                             = 9,
 FEDFS_ERR_NOSPC                          = 10,
 FEDFS_ERR_NOTJUNCT                       = 11,
 FEDFS_ERR_NOTLOCAL                       = 12,
 FEDFS_ERR_PERM                           = 13,
 FEDFS_ERR_ROFS                           = 14,
 FEDFS_ERR_SVRFAULT                       = 15,
 FEDFS_ERR_NOTSUPP                        = 16,
 FEDFS_ERR_NSDB_ROUTE                     = 17,
 FEDFS_ERR_NSDB_DOWN                      = 18,
 FEDFS_ERR_NSDB_CONN                      = 19,
 FEDFS_ERR_NSDB_AUTH                      = 20,
 FEDFS_ERR_NSDB_LDAP                      = 21,
 FEDFS_ERR_NSDB_LDAP_VAL                  = 22,
 FEDFS_ERR_NSDB_NONCE                     = 23,
 FEDFS_ERR_NSDB_NOFSN                     = 24,
 FEDFS_ERR_NSDB_NOFSL                     = 25,
 FEDFS_ERR_NSDB_RESPONSE                  = 26,
 FEDFS_ERR_NSDB_FAULT                     = 27,
 FEDFS_ERR_NSDB_PARAMS                    = 28,
 FEDFS_ERR_NSDB_LDAP_REFERRAL             = 29,
 FEDFS_ERR_NSDB_LDAP_REFERRAL_VAL         = 30,
 FEDFS_ERR_NSDB_LDAP_REFERRAL_NOTFOLLOWED = 31,
 FEDFS_ERR_NSDB_PARAMS_LDAP_REFERRAL      = 32,
 FEDFS_ERR_PATH_TYPE_UNSUPP               = 33,
 FEDFS_ERR_DELAY                          = 34,
 FEDFS_ERR_NO_CACHE                       = 35,
 FEDFS_ERR_UNKNOWN_CACHE                  = 36,
 FEDFS_ERR_NO_CACHE_UPDATE                = 37
};

typedef opaque                 utf8string<>;
typedef utf8string             ascii_REQUIRED4;
typedef utf8string             utf8val_REQUIRED4;

typedef opaque FedFsUuid[16];

struct FedFsNsdbName {
        unsigned int           port;
        utf8val_REQUIRED4      hostname;
};

typedef ascii_REQUIRED4 FedFsPathComponent;
typedef FedFsPathComponent FedFsPathName<>;

struct FedFsFsn {
        FedFsUuid              fsnUuid;
        FedFsNsdbName          nsdbName;
};

enum FedFsFslType {
 FEDFS_NFS_FSL = 0
 /* other types TBD */
};

struct FedFsNfsFsl {
        FedFsUuid              fslUuid;
        unsigned int           port;
        utf8val_REQUIRED4      hostname;
        FedFsPathName          path;
};

union FedFsFsl switch(FedFsFslType type) {
 case FEDFS_NFS_FSL:
        FedFsNfsFsl            nfsFsl;
};

enum FedFsPathType {
 FEDFS_PATH_SYS = 0,
 FEDFS_PATH_NFS = 1
 /* other types TBD */
};

union FedFsPath switch(FedFsPathType type) {
 case FEDFS_PATH_SYS: /* administrative path */
        FedFsPathName          adminPath;
 case FEDFS_PATH_NFS: /* NFS namespace path */
        FedFsPathName          nfsPath;
};

struct FedFsCreateArgs {
        FedFsPath              path;
        FedFsFsn               fsn;
};

enum FedFsResolveType {
 FEDFS_RESOLVE_NONE  = 0,
 FEDFS_RESOLVE_CACHE = 1,
 FEDFS_RESOLVE_NSDB  = 2
};

struct FedFsLookupArgs {
        FedFsPath              path;
        FedFsResolveType       resolve;
};

struct FedFsLookupResOk {
        FedFsFsn               fsn;
        FedFsFsl               fsl<>;
};

struct FedFsLookupResReferralVal {
        FedFsNsdbName          targetNsdb;
        unsigned int           ldapResultCode;
};

union FedFsLookupRes switch (FedFsStatus status) {
 case FEDFS_OK:
 case FEDFS_ERR_NO_CACHE_UPDATE:
        FedFsLookupResOk           resok;
 case FEDFS_ERR_NSDB_LDAP_VAL:
        unsigned int               ldapResultCode;
 case FEDFS_ERR_NSDB_LDAP_REFERRAL:
 case FEDFS_ERR_NSDB_PARAMS_LDAP_REFERRAL:
        FedFsNsdbName              targetNsdb;
 case FEDFS_ERR_NSDB_LDAP_REFERRAL_VAL:
        FedFsLookupResReferralVal  resReferralVal;
 default:
        void;
};

enum FedFsConnectionSec {
 FEDFS_SEC_NONE = 0,
 FEDFS_SEC_TLS = 1 /* StartTLS mechanism; RFC4513, Section 3 */
 /* other mechanisms TBD */
};

union FedFsNsdbParams switch (FedFsConnectionSec secType) {
 case FEDFS_SEC_TLS:
        opaque                   secData<>;
 default:
        void;
};

struct FedFsSetNsdbParamsArgs {
        FedFsNsdbName            nsdbName;
        FedFsNsdbParams          params;
};

union FedFsGetNsdbParamsRes switch (FedFsStatus status) {
 case FEDFS_OK:
        FedFsNsdbParams          params;
 default:
        void;
};

union FedFsGetLimitedNsdbParamsRes switch (FedFsStatus status) {
 case FEDFS_OK:
        FedFsConnectionSec       secType;
 default:
        void;
};

program FEDFS_PROG {
 version FEDFS_V1 {
     void FEDFS_NULL(void) = 0;
     FedFsStatus FEDFS_CREATE_JUNCTION(
                  FedFsCreateArgs) = 1;
     FedFsStatus FEDFS_DELETE_JUNCTION(
                  FedFsPath) = 2;
     FedFsLookupRes FEDFS_LOOKUP_JUNCTION(
                  FedFsLookupArgs) = 3;
     FedFsStatus FEDFS_CREATE_REPLICATION(
                  FedFsCreateArgs) = 7;
     FedFsStatus FEDFS_DELETE_REPLICATION(
                  FedFsPath) = 8;
     FedFsLookupRes FEDFS_LOOKUP_REPLICATION(
                  FedFsLookupArgs) = 9;
     FedFsStatus FEDFS_SET_NSDB_PARAMS(
                  FedFsSetNsdbParamsArgs) = 4;
     FedFsGetNsdbParamsRes FEDFS_GET_NSDB_PARAMS(
                  FedFsNsdbName) = 5;
     FedFsGetLimitedNsdbParamsRes FEDFS_GET_LIMITED_NSDB_PARAMS(
                  FedFsNsdbName) = 6;
 } = 1;
} = 100418;

%#define FEDFS_ADMIN_X
