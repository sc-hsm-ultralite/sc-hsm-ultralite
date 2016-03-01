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
 * @file log.h
 * @author Keith Morgan
 */

#ifndef __log_h__
#define __log_h__

#ifdef __cplusplus
extern "C" {
#endif

/* WARNING: These functions are NOT thread-safe. */
void _log_err(const char* fmt, ...);
void _log_wrn(const char* fmt, ...);
void _log_inf(const char* fmt, ...);

#if defined(_DEBUG) || defined(DEBUG)
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define BT " (at '" __FILE__ "':" TOSTRING(__LINE__) ")"
#define log_err(fmt, ...) _log_err(fmt "%s\n", ##__VA_ARGS__, BT)
#else
#define log_err(fmt, ...) _log_err(fmt   "\n", ##__VA_ARGS__)
#endif
#define log_wrn(fmt, ...) _log_wrn(fmt   "\n", ##__VA_ARGS__)
#define log_inf(fmt, ...) _log_inf(fmt   "\n", ##__VA_ARGS__) 

#ifdef __cplusplus
}
#endif
#endif /* __log_h__ */
