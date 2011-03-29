/**
 * @file src/libxlog/xlog.c
 * @brief Post notices and errors to system log or stderr
 */

/*
 * Authors:	Donald J. Becker, <becker@super.org>
 *		Rick Sladkey, <jrs@world.std.com>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Olaf Kirch, <okir@monad.swb.de>
 *
 *		This software maybe be used for any purpose provided
 *		the above copyright notice is retained.  It is supplied
 *		as is, with no warranty expressed or implied.
 */

#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>

#include "xlog.h"

#undef	VERBOSE_PRINTF

static int  log_stderr = 1;
static int  log_syslog = 1;
static int  logging = 0;		/* enable/disable DEBUG logs	*/
static int  logmask = 0;		/* What will be logged		*/
static char log_name[256];		/* name of this program		*/
static int  log_pid = -1;		/* PID of this program		*/

static void xlog_toggle(int sig);

/**
 * Map debug facility names to syslog facility numbers
 */
static struct xlog_debugfac	debugnames[] = {
	{ "general",	D_GENERAL, },
	{ "call",	D_CALL, },
	{ "auth",	D_AUTH, },
	{ "parse",	D_PARSE, },
	{ "all",	D_ALL, },
	{ NULL,		0, },
};

/**
 * Open the syslog and provide the name of the running program
 *
 * @param progname NUL-terminated C string containing name of program
 */
void
xlog_open(char *progname)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));

	openlog(progname, LOG_PID, LOG_DAEMON);

	strncpy(log_name, progname, sizeof (log_name) - 1);
	log_name[sizeof (log_name) - 1] = '\0';
	log_pid = getpid();

	sa.sa_handler = xlog_toggle;
	(void)sigaction(SIGUSR1, &sa, NULL);
	(void)sigaction(SIGUSR2, &sa, NULL);
}

/**
 * Toggle logging to stderr
 *
 * @param on 1 means do post messages to stderr, 0 means do not
 */
void
xlog_stderr(int on)
{
	log_stderr = on;
}

/**
 * Toggle logging to syslog
 *
 * @param on 1 means do post messages to syslog, 0 means do not
 */
void
xlog_syslog(int on)
{
	log_syslog = on;
}

/**
 * Handle SIGUSR1 and SIGUSR2 signals
 * 
 * @param sig POSIX signal number to handle
 */
static void
xlog_toggle(int sig)
{
	unsigned int	tmp, i;

	if (sig == SIGUSR1) {
		if ((logmask & D_ALL) && !logging) {
			xlog(D_GENERAL, "turned on logging");
			logging = 1;
			return;
		}
		tmp = ~logmask;
		logmask |= ((logmask & D_ALL) << 1) | D_GENERAL;
		for (i = -1, tmp &= logmask; tmp; tmp >>= 1, i++)
			if (tmp & 1)
				xlog(D_GENERAL,
					"turned on logging level %d", i);
	} else {
		xlog(D_GENERAL, "turned off logging");
		logging = 0;
	}
	signal(sig, xlog_toggle);
}

/**
 * Control syslog facility
 *
 * @param fac syslog facility to use
 * @param on 1 means post subsequent messages, 0 means do not
 */
void
xlog_config(int fac, int on)
{
	if (on)
		logmask |= fac;
	else
		logmask &= ~fac;
	if (on)
		logging = 1;
}

/**
 * Control behavior of debug-level logging
 *
 * @param kind NUL-terminated C string containing name of facility to control
 * @param on 1 means post subsequent debugging messages, 0 means do not
 */
void
xlog_sconfig(char *kind, int on)
{
	struct xlog_debugfac	*tbl = debugnames;

	while (tbl->df_name != NULL && strcasecmp(tbl->df_name, kind)) 
		tbl++;
	if (!tbl->df_name) {
		xlog (L_WARNING, "Invalid debug facility: %s\n", kind);
		return;
	}
	xlog_config(tbl->df_fac, on);
}

/**
 * Get the status of a logging facility
 *
 * @param fac syslog facility to query
 * @return 1 if the facility is enabled, 0 if not
 */
int
xlog_enabled(int fac)
{
	return (logging && (fac & logmask));
}

/**
 * Write something to the system logfile and/or stderr
 *
 * @param kind syslog facility to use
 * @param fmt NUL-terminated C string containing printf-style format
 * @param args list of arguments to go with "fmt"
 */
void
xlog_backend(int kind, const char *fmt, va_list args)
{
	va_list args2;

	if (!(kind & (L_ALL)) && !(logging && (kind & logmask)))
		return;

	if (log_stderr)
		va_copy(args2, args);

	if (log_syslog) {
		switch (kind) {
		case L_FATAL:
			vsyslog(LOG_ERR, fmt, args);
			break;
		case L_ERROR:
			vsyslog(LOG_ERR, fmt, args);
			break;
		case L_WARNING:
			vsyslog(LOG_WARNING, fmt, args);
			break;
		case L_NOTICE:
			vsyslog(LOG_NOTICE, fmt, args);
			break;
		default:
			if (!log_stderr)
				vsyslog(LOG_INFO, fmt, args);
			break;
		}
	}

	if (log_stderr) {
#ifdef VERBOSE_PRINTF
		time_t		now;
		struct tm	*tm;

		time(&now);
		tm = localtime(&now);
		fprintf(stderr, "%s[%d] %04d-%02d-%02d %02d:%02d:%02d ",
				log_name, log_pid,
				tm->tm_year+1900, tm->tm_mon + 1, tm->tm_mday,
				tm->tm_hour, tm->tm_min, tm->tm_sec);
#else
		fprintf(stderr, "%s: ", log_name);
#endif
		vfprintf(stderr, fmt, args2);
		fprintf(stderr, "\n");
		va_end(args2);
	}

	if (kind == L_FATAL)
		exit(1);
}

/**
 * Post a log message
 *
 * @param kind facility to use
 * @param fmt NUL-terminated C string containing printf-style format
 */
void
xlog(int kind, const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	xlog_backend(kind, fmt, args);
	va_end(args);
}

/**
 * Post a warning log message
 *
 * @param fmt NUL-terminated C string containing printf-style format
 */
void
xlog_warn(const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	xlog_backend(L_WARNING, fmt, args);
	va_end(args);
}

/**
 * Post a fatal log message
 *
 * @param fmt NUL-terminated C string containing printf-style format
 */
void
xlog_err(const char* fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	xlog_backend(L_FATAL, fmt, args);
	va_end(args);
}
