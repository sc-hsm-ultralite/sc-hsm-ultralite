/**
 * SmartCard-HSM Ultra-Light Library
 *
 * Copyright (c) 2013. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the BSD 3-Clause License. You should have
 * received a copy of the BSD 3-Clause License along with this program.
 * If not, see <http://opensource.org/licenses/>
 *
 * @file log.c
 * @author Keith Morgan
 */

#include <stdarg.h>
#include <stdio.h>

/* WARNING: These functions are NOT thread-safe. */

#define ERR_TIMESTAMP "0000-00-00T00:00:00.000+00:00"
static char timestamp[64];

#ifdef _WIN32
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#define getpid GetCurrentThreadId
long long unix_base;
static void init_unix_base()
{
	SYSTEMTIME st;
	memset(&st, 0, sizeof(st));
	st.wYear = 1970;
	st.wMonth = 1;
	st.wDay = 1;
	SystemTimeToFileTime(&st, (FILETIME*)&unix_base);
}
const char* GetTimestamp()
{
	int n, err;
	long long nowft;
	struct tm lt;
	time_t t64;
	int seconds, millis;
	long gmtoff;
	char strf[20]; /* 20 => length of yyyy-mm-ddThh:mm:ss + null term */
	GetSystemTimeAsFileTime((FILETIME*)&nowft);
	if (unix_base == 0)
		init_unix_base();
	seconds = (int)((nowft - unix_base) / 10000000);
	millis = (int)(nowft % 10000000 / 10000);
	t64 = seconds;
	err = _localtime64_s(&lt, &t64);
	if (err)
		return ERR_TIMESTAMP;
	err = _get_timezone(&gmtoff);
	if (err)
		return ERR_TIMESTAMP;
	if (lt.tm_isdst)
		gmtoff -= 3600;
	n = strftime(strf, sizeof(strf), "%Y-%m-%dT%H:%M:%S", &lt);
	if (n == 0)
		return ERR_TIMESTAMP;
	n = _snprintf(timestamp, sizeof(timestamp), "%s.%03d%+03d:%02d", strf, millis, -gmtoff / 3600, abs(gmtoff) % 3600 / 60);
	if (n < 0 || n >= sizeof(timestamp))
		return ERR_TIMESTAMP;
	return timestamp;
}
#elif defined __linux__
#include <time.h>
#include <sys/time.h>
const char* GetTimestamp()
{
	time_t now;
	struct timeval tv;
	int n, err, gmtoff;
	struct tm lt;
	char strf[20]; /* 20 => length of yyyy-mm-ddThh:mm:ss + null term */
	err = gettimeofday(&tv, 0);
	if (err)
		return ERR_TIMESTAMP;
	localtime_r(&tv.tv_sec, &lt);
	gmtoff = lt.tm_gmtoff;
	if (lt.tm_isdst)
		gmtoff -= 3600;
	n = strftime(strf, sizeof(strf), "%Y-%m-%dT%H:%M:%S", &lt);
	if (n == 0)
		return ERR_TIMESTAMP;
	n = snprintf(timestamp, sizeof(timestamp), "%s.%03d%+03d:%02d", strf, (int)tv.tv_usec / 1000, gmtoff / 3600, gmtoff % 3600 / 60);
	if (n < 0 || n >= sizeof(timestamp))
		return ERR_TIMESTAMP;
	return timestamp;
}
#else
#error "Must implement GetTimestamp() AND getpid() for your operating system, OR use different logging methods."
#endif

static int pid;
int GetPid()
{
	if (!pid)
		pid = getpid();
	return pid;
}

void _log_err(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "@E %s [%d]: ", GetTimestamp(), GetPid());
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void _log_wrn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stderr, "@W %s [%d]: ", GetTimestamp(), GetPid());
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void _log_inf(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	fprintf(stdout, "@I %s [%d]: ", GetTimestamp(), GetPid());
	vfprintf(stdout, fmt, args);
	va_end(args);
}
