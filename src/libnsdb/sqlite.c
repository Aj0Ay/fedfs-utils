/**
 * @file src/libnsdb/sqlite.c
 * @brief fedfs sqlite3 helper functions
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
#include <grp.h>

#include "nsdb-internal.h"
#include "xlog.h"

/**
 * Get a handle to an sqlite3 database
 *
 * @param db_filename NUL-terminated C string containing pathname of db file
 * @param flags Sqlite3 open flags
 * @return pointer to an open sqlite3 db handle, or NULL
 */
sqlite3 *
nsdb_open_db(const char *db_filename, int flags)
{
	sqlite3 *db;
	int rc;

	rc = sqlite3_initialize();
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to initialize sqlite3: %d", rc);
		return NULL;
	}

	rc = sqlite3_open_v2(db_filename, &db, flags, NULL);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to open sqlite3 database in %s: %s",
			db_filename, sqlite3_errmsg(db));
		xlog(L_ERROR, "Check that the full database pathname is correct, and that");
		xlog(L_ERROR, "the database file exists and has proper permissions");
		(void)sqlite3_close(db);
		return NULL;
	}

	/*
	 * Retry SQLITE_BUSY for 100 msec before returning an error.
	 */
	(void)sqlite3_busy_timeout(db, 100);

	return db;
}

/**
 * Deallocate an sqlite3 database handle
 *
 * @param db pointer to an sqlite3 database handle
 */
void
nsdb_close_db(sqlite3 *db)
{
	int rc;

	rc = sqlite3_close(db);
	if (rc != SQLITE_OK)
		xlog(L_ERROR, "Failed to close sqlite3 database: %s",
			sqlite3_errmsg(db));

	rc = sqlite3_shutdown();
	if (rc != SQLITE_OK)
		xlog(L_ERROR, "Failed to shut sqlite3 down: %d", rc);
}

/**
 * Prepare an SQL statement for execution
 *
 * @param db pointer to an sqlite3 database handle
 * @param stmt OUT: allocated sqlite3 statement handle
 * @param sql NUL-terminated C string containing human-readable SQL to prepare
 * @return true if statement was prepared, otherwise false
 */
_Bool
nsdb_prepare_stmt(sqlite3 *db, sqlite3_stmt **stmt, const char *sql)
{
	int rc;

	rc = sqlite3_prepare_v2(db, sql, -1, stmt, NULL);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to compile SQL: %s",
			sqlite3_errmsg(db));
		xlog(L_ERROR, "SQL: %s", sql);
		return false;
	}
	return true;
}

/**
 * Deallocate a prepared SQL statement handle
 *
 * @param stmt pointer to sqlite3 statement handle to free
 */
void
nsdb_finalize_stmt(sqlite3_stmt *stmt)
{
	sqlite3 *db = sqlite3_db_handle(stmt);
	int rc;

	rc = sqlite3_finalize(stmt);
	switch(rc) {
	case SQLITE_OK:
	case SQLITE_ABORT:
	case SQLITE_CONSTRAINT:
		break;
	default:
		xlog(L_ERROR, "Failed to finalize SQL statement: %s",
			sqlite3_errmsg(db));
	}
}

/**
 * Start a sqlite3 transaction
 *
 * @param db pointer to an sqlite3 database handle
 * @return true if the transaction was started; otherwise FALSE 
 */
_Bool
nsdb_begin_transaction(sqlite3 *db)
{
	char *err_msg;
	int rc;

	err_msg = NULL;
	rc = sqlite3_exec(db, "BEGIN IMMEDIATE TRANSACTION;",
					NULL, NULL, &err_msg);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to start transaction: %s", err_msg);
		sqlite3_free(err_msg);
		return false;
	}

	xlog(D_CALL, "Transaction started");
	return true;
}

/**
 * Close and commit a sqlite3 transaction
 *
 * @param db pointer to an sqlite3 database handle
 */
void
nsdb_end_transaction(sqlite3 *db)
{
	char *err_msg;
	int rc;

	err_msg = NULL;
	rc = sqlite3_exec(db, "COMMIT TRANSACTION;", NULL, NULL, &err_msg);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to commit transaction: %s", err_msg);
		sqlite3_free(err_msg);
		return;
	}

	xlog(D_CALL, "Transaction committed");
}

/**
 * Roll back an active sqlite3 transaction
 *
 * @param db pointer to an sqlite3 database handle
 */
void
nsdb_rollback_transaction(sqlite3 *db)
{
	char *err_msg;
	int rc;

	err_msg = NULL;
	rc = sqlite3_exec(db, "ROLLBACK TRANSACTION;", NULL, NULL, &err_msg);
	if (rc != SQLITE_OK) {
		xlog(L_ERROR, "Failed to roll back transaction: %s", err_msg);
		sqlite3_free(err_msg);
		return;
	}

	xlog(D_CALL, "Transaction rolled back");
}

/**
 * Create a new table in an sqlite3 database
 *
 * @param db pointer to an sqlite3 database handle
 * @param table_name NUL-terminated C string containing name of new table
 * @param table_def NUL-terminated C string containing definition of new table
 * @return true if table was created or already exists, otherwise false
 *
 * NB: Do not pass untrusted strings to this function!
 */
_Bool
nsdb_create_table(sqlite3 *db, const char *table_name, const char *table_def)
{
	sqlite3_stmt *stmt;
	char *sql;
	int rc;

	sql = sqlite3_mprintf("CREATE TABLE %q (%q);", table_name, table_def);
	if (sql == NULL) {
		xlog(L_ERROR, "Failed to construct SQL command while "
			"creating table %s", table_name);
		return false;
	}

	rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
	sqlite3_free(sql);
	switch (rc) {
	case SQLITE_OK:
		break;
	case SQLITE_ERROR:
		xlog(D_CALL, "Table %s already exists", table_name);
		return true;
	default:
		xlog(L_ERROR, "Failed to compile SQL while creating table %s: %s",
			table_name, sqlite3_errmsg(db));
		xlog(L_ERROR, "SQL: %s");
		return false;
	}

	rc = sqlite3_step(stmt);
	if (rc != SQLITE_DONE) {
		xlog(L_ERROR, "Failed to create %s table: %s",
			table_name, sqlite3_errmsg(db));
		nsdb_finalize_stmt(stmt);
		return false;
	}
	nsdb_finalize_stmt(stmt);

	xlog(D_CALL, "Created table %s successfully", table_name);
	return true;
}
