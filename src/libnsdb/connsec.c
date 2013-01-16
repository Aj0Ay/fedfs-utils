/**
 * @file src/libnsdb/connsec.c
 * @brief Handle security-related NSDB connection parameters
 */

/*
 * Copyright 2012 Oracle.  All rights reserved.
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

#include <stdbool.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/err.h>

#include "fedfs.h"
#include "nsdb.h"
#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Flatten X509 object into a buffer
 * Fire up the crypto library
 */
void
nsdb_connsec_crypto_startup(void)
{
	xlog(D_CALL, "%s");

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	ENGINE_load_builtin_engines();
}

/**
 * Fire up the crypto library
 */
void
nsdb_connsec_crypto_shutdown(void)
{
	xlog(D_CALL, "%s");

	OBJ_cleanup();
	EVP_cleanup();
	ENGINE_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_thread_state(NULL);
	ERR_free_strings();
}

/**
 * Calculate size of buffer to contain DER-encoded certificates from "bio"
 *
 * @param certfile NUL-terminated C string containing pathname of file
 * @param bio open BIO struct of file to analyze
 * @param len OUT: size of buffer required, in bytes
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_connsec_buffer_size(const char *certfile, BIO *bio, unsigned int *len)
{
	unsigned int result;
	X509 *x509;

	(void)BIO_reset(bio);
	result = 0;
	while ((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		int size;

		size = i2d_X509(x509, NULL);
		X509_free(x509);
		if (size < 0) {
			xlog(D_GENERAL, "%s: failed to parse %s",
				__func__, certfile);
			return FEDFS_ERR_SVRFAULT;
		}

		xlog(D_GENERAL, "%s: certificate in %s need %u bytes",
			__func__, certfile, size);
		result += size + 1;
	}

	if (result == 0) {
		xlog(D_CALL, "%s: no certificates found in %s",
			__func__, certfile);
		return FEDFS_ERR_INVAL;
	}

	xlog(D_CALL, "%s: buffer for %s should contain %u bytes",
		__func__, certfile, result);
	*len = result;
	return FEDFS_OK;
}

/**
 * Read certificate data into a buffer
 *
 * @param certfile NUL-terminated C string containing pathname of file containing PEM-encoded x.509 certificate material
 * @param bio open BIO struct of file to read
 * @param buf OUT: pointer to buffer containing DER-encoded x.509 certificate
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_connsec_read_bio_x509_buf(const char *certfile, BIO *bio,
		unsigned char *buf)
{
	FedFsStatus retval;
	X509 *x509;

	(void)BIO_reset(bio);
	retval = FEDFS_ERR_IO;
	while((x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		int size;

		size = i2d_X509(x509, &buf);
		X509_free(x509);
		if (size < 0) {
			xlog(D_GENERAL, "%s: failed to parse %s",
				__func__, certfile);
			return FEDFS_ERR_SVRFAULT;
		}
		xlog(D_CALL, "%s: read a certificate from %s",
			__func__, certfile);
		retval = FEDFS_OK;
	}

	return retval;
}

/**
 * Read certificate data from a file
 *
 * @param certfile NUL-terminated C string containing pathname of file containing PEM-encoded x.509 certificate material
 * @param bio open BIO struct of file to read
 * @param data OUT: pointer to buffer containing DER-encoded x.509 certificate
 * @param len OUT: length of buffer containing certificate
 * @return a FedFsStatus code
 *
 * Caller must free returned "data" with free(3)
 */
static FedFsStatus
nsdb_connsec_read_bio_x509(const char *certfile, BIO *bio,
		unsigned char **data, unsigned int *len)
{
	FedFsStatus retval;
	unsigned char *buf;
	unsigned int size;

	retval = nsdb_connsec_buffer_size(certfile, bio, &size);
	if (retval != FEDFS_OK)
		return retval;

	buf = (unsigned char *)calloc(1, size);
	if (buf == NULL) {
		xlog(D_GENERAL, "%s: failed to allocate buffer", __func__);
		return FEDFS_ERR_SVRFAULT;
	}

	retval = nsdb_connsec_read_bio_x509_buf(certfile, bio, buf);
	if (retval != FEDFS_OK) {
		free(buf);
		return retval;
	}

	*data = buf;
	*len = size;
	return FEDFS_OK;
}

/**
 * Read certificate material from a file
 *
 * @param certfile NUL-terminated C string containing pathname of file containing PEM-encoded x.509 certificate material
 * @param data OUT: pointer to buffer containing DER-encoded x.509 certificates
 * @param len OUT: size of "data", in bytes
 * @return a FedFsStatus code
 *
 * Caller must free returned "data" with free(3)
 */
FedFsStatus
nsdb_connsec_read_pem_file(const char *certfile,
		char **data, unsigned int *len)
{
	FedFsStatus retval;
	BIO *bio;

	if (certfile == NULL || data == NULL || len == NULL)
		return FEDFS_ERR_INVAL;

	xlog(D_CALL, "%s: %s", __func__, certfile);

	retval = FEDFS_ERR_ACCESS;
	bio = BIO_new_file(certfile, "r");
	if (bio == NULL) {
		xlog(D_GENERAL, "%s: failed to open %s", __func__, certfile);
		goto out;
	}

	retval = nsdb_connsec_read_bio_x509(certfile, bio,
						(unsigned char **)data, len);

	BIO_free_all(bio);

out:
	ERR_clear_error();
	return retval;
}

/**
 * Store certificate data in a file
 *
 * @param certfile NUL-terminated C string containing name of file to write
 * @param bio open BIO struct of file to write
 * @param data pointer to buffer containing DER-encoded x.509 certificate
 * @param len size of "data" in bytes
 * @return a FedFsStatus code
 */
static FedFsStatus
nsdb_connsec_write_bio_x509(const char *certfile, BIO *bio,
		const unsigned char *data, long len)
{
	const unsigned char *p, *q;
	FedFsStatus retval;

	(void)BIO_reset(bio);
	p = data;

	retval = FEDFS_ERR_INVAL;
	q = p;
	do {
		X509 *x509;
		int result;

		x509 = d2i_X509(NULL, &data, len);
		if (x509 == NULL)
			break;
		xlog(D_CALL, "%s: parsed %d bytes", __func__, q - p);
		len -= q - p;
		p = q;

		result = PEM_write_bio_X509(bio, x509);
		X509_free(x509);
		if (result < 0) {
			xlog(D_GENERAL, "%s: failed to write certificate to %s",
				__func__, certfile);
			return FEDFS_ERR_IO;
		}

		xlog(D_CALL, "%s: wrote a certificate to %s",
			__func__, certfile);
		retval = FEDFS_OK;
	} while (1);

	if (retval != FEDFS_OK)
		xlog(D_CALL, "%s: found no certificates in buffer", __func__);
	return retval;
}

/**
 * Store certificate data in a file
 *
 * @param certfile NUL-terminated C string containing name of file to write
 * @param data pointer to buffer containing DER-encoded x.509 certificate
 * @param len size of "data" in bytes
 * @return a FedFsStatus code
 */
FedFsStatus
nsdb_connsec_write_pem_file(const char *certfile,
		const char *data, unsigned int len)
{
	char *tmpfile = NULL;
	FedFsStatus retval;
	BIO *bio;

	if (certfile == NULL || data == NULL)
		return FEDFS_ERR_INVAL;

	xlog(D_CALL, "%s: %u bytes to %s", __func__, len, certfile);

	tmpfile = malloc(strlen(certfile) + 5);
	if (tmpfile == NULL)
		return FEDFS_ERR_SVRFAULT;
	strcpy(tmpfile, certfile);
	strcat(tmpfile, ".TMP");

	retval = FEDFS_ERR_INVAL;
	bio = BIO_new_file(tmpfile, "w");
	if (bio == NULL) {
		xlog(D_GENERAL, "%s: failed to open temporary certificate file %s",
			__func__, certfile);
		goto out;
	}

	retval = nsdb_connsec_write_bio_x509(certfile, bio,
					(const unsigned char *)data,
					(long)len);

	BIO_free_all(bio);

	if (retval == FEDFS_OK) {
		if (rename(tmpfile, certfile) == -1) {
			xlog(D_GENERAL, "%s: rename failed: %m",
				__func__);
			(void)unlink(tmpfile);
			retval = FEDFS_ERR_IO;
		}
	}

out:
	free(tmpfile);
	ERR_clear_error();
	return retval;
}

/**
 * Create a private file and store certficate data in it
 *
 * @param data pointer to buffer containing DER-encoded x.509 certificate
 * @param len size of "data" in bytes
 * @param pathname OUT: pointer to NUL-terminated C string containing pathname of new file
 * @return a FedFsStatus code
 *
 * On success, FEDFS_OK is returned, a new cert file is created in our
 * private certificate directory, the certificate material is copied to it
 * in PEM format, and "pathname" is filled in.
 *
 * Caller must free the pathname with free(3)
 */
static FedFsStatus
nsdb_connsec_create_pem_file(const char *data, const unsigned int len,
		char **pathname)
{
	FedFsStatus retval;
	char *tmp;

	retval = nsdb_create_private_certfile(&tmp);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_connsec_write_pem_file(tmp, data, len);
	if (retval != FEDFS_OK) {
		(void)unlink(tmp);
		free(tmp);
		return retval;
	}

	*pathname = tmp;
	return FEDFS_OK;
}

/**
 * Remove the cert file for an NSDB
 *
 * @param certfile NUL-terminated UTF-8 string containing pathname of file
 */
void
nsdb_connsec_remove_certfile(const char *certfile)
{
	if (certfile == NULL || *certfile == '\0')
		return;

	xlog(D_CALL, "%s: %s", __func__, certfile);
	if (unlink(certfile) == -1)
		xlog(D_GENERAL, "%s: unlink: %m", __func__);
}

/**
 * Retrieve certificate data for NSDB "host" from NSDB database
 *
 * @param host an initialized nsdb_t object
 * @param data OUT: buffer containing security data
 * @param len OUT: length of security data buffer
 * @return a FedFsStatus code
 *
 * On success, FEDFS_OK is returned and the security data is filled in.
 * For the TLS security type, this is DER-encoded certificate material.
 *
 * Caller must free the returned buffer with free(3).
 */
FedFsStatus
nsdb_connsec_get_cert_data(nsdb_t host, char **data, unsigned int *len)
{
	FedFsStatus retval;

	if (data == NULL || len == NULL)
		return FEDFS_ERR_INVAL;

	switch (nsdb_sectype(host)) {
	case FEDFS_SEC_NONE:
		retval = FEDFS_ERR_INVAL;
		break;
	case FEDFS_SEC_TLS:
		retval = nsdb_connsec_read_pem_file(nsdb_certfile(host),
								data, len);
		break;
	default:
		retval = FEDFS_ERR_SVRFAULT;
	}

	return retval;
}

/**
 * Set connection security parameters for an NSDB to "NONE"
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @return a FedFsStatus code
 *
 * Affects only new connections to the NSDB.  Existing connections
 * are not changed or closed by this call.
 */
FedFsStatus
nsdb_connsec_set_none(const char *hostname, const unsigned short port)
{
	const char *old_certfile;
	FedFsStatus retval;
	nsdb_t host;

	xlog(D_CALL, "%s: %s:%u", __func__, hostname, port);

	retval = nsdb_lookup_nsdb(hostname, port, &host);
	if (retval != FEDFS_OK)
		return retval;
	old_certfile = nsdb_certfile(host);

	retval = nsdb_update_security_nsdbparams(host, FEDFS_SEC_NONE, "");
	if (retval == FEDFS_OK)
		nsdb_connsec_remove_certfile(old_certfile);

	nsdb_free_nsdb(host);
	return retval;
}

/**
 * Set connection security parameters for an NSDB to "TLS"
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param data buffer containing certificate material
 * @param len length of "data" in bytes
 * @return a FedFsStatus code
 *
 * "data" contains DER-encoded x.509 certificate material.
 *
 * Affects only new connections to the NSDB.  Existing connections
 * are not changed or closed by this call.
 */
FedFsStatus
nsdb_connsec_set_tls_buf(const char *hostname, const unsigned short port,
		char *data, unsigned int len)
{
	char *new_certfile = NULL;
	const char *old_certfile;
	FedFsStatus retval;
	nsdb_t host = NULL;

	retval = nsdb_connsec_create_pem_file(data, len, &new_certfile);
	if (retval != FEDFS_OK)
		goto out;

	xlog(D_CALL, "%s: %s:%u, %s", __func__, hostname, port, new_certfile);

	retval = nsdb_lookup_nsdb(hostname, port, &host);
	if (retval != FEDFS_OK)
		return retval;
	old_certfile = nsdb_certfile(host);

	retval = nsdb_update_security_nsdbparams(host, FEDFS_SEC_TLS,
								new_certfile);
	if (retval == FEDFS_OK)
		nsdb_connsec_remove_certfile(old_certfile);

out:
	nsdb_free_nsdb(host);
	free(new_certfile);
	return retval;
}

/**
 * Set connection security parameters for an NSDB to "TLS"
 *
 * @param hostname NUL-terminated UTF-8 string containing NSDB hostname
 * @param port integer port number of NSDB
 * @param certfile NUL-terminated UTF-8 string containing pathname of file
 * @return a FedFsStatus code
 *
 * "certfile" is a file containing a PEM-encoded x.509 certificate.
 *
 * Affects only new connections to the NSDB.  Existing connections
 * are not changed or closed by this call.
 */
FedFsStatus
nsdb_connsec_set_tls_file(const char *hostname, const unsigned short port,
		const char *certfile)
{
	const char *old_certfile;
	char *new_certfile;
	FedFsStatus retval;
	char *data = NULL;
	unsigned int len;
	nsdb_t host;

	xlog(D_CALL, "%s: %s:%u, %s", __func__, hostname, port, certfile);

	retval = nsdb_connsec_read_pem_file(certfile, &data, &len);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_connsec_create_pem_file(data, len, &new_certfile);
	if (retval != FEDFS_OK)
		return retval;

	retval = nsdb_lookup_nsdb(hostname, port, &host);
	if (retval != FEDFS_OK)
		return retval;
	old_certfile = nsdb_certfile(host);

	retval = nsdb_update_security_nsdbparams(host, FEDFS_SEC_TLS,
							new_certfile);
	if (retval == FEDFS_OK)
		nsdb_connsec_remove_certfile(old_certfile);

	nsdb_free_nsdb(host);
	free(new_certfile);
	free(data);
	return retval;
}
