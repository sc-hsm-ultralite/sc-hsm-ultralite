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

#if defined(NO_LOG) /* No Logging */

void _log_err(const char* fmt, ...) {}
void _log_wrn(const char* fmt, ...) {}
void _log_inf(const char* fmt, ...) {}

#else /* Basic Logging */

#include <stdarg.h>
#include <stdio.h>

void _log_err(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void _log_wrn(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

void _log_inf(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
}

#endif
