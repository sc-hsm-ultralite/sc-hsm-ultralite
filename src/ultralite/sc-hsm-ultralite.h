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
 * @file sc-hsm-ultralite.h
 * @author Christoph Brunhuber
 * @brief Functions for RSA-2k signing of SHA1, SHA-256, SHA-384, SHA-512
 *                  ECDSA-prime256 signing of SHA1, SHA-256
 *                  Card Devices, Version 1.0
 */

#ifndef _sc_hsm_ultralite_h_
#define _sc_hsm_ultralite_h_

/* Remove on a big endian system */
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif

#ifndef ERR_INVALID
#define CT               1
#define HOST             2
#define OK               0   /** Successful completion            */
#define ERR_INVALID     -1   /** Invalid parameter or value       */
#define ERR_MUTEX       -2   /** Mutex operation failed           */
#define ERR_CT          -8   /** Cardterminal error               */
#define ERR_TRANS       -10  /** Transmission error               */
#define ERR_MEMORY      -11  /** Memory allocate error            */
#define ERR_HOST        -127 /** Function aborted by host os      */
#define ERR_HTSI        -128 /** 'HTSI' error                     */
#endif
#define ERR_CONTEXT   (-1000 -  0)
#define ERR_READER    (-1000 -  1)
#define ERR_CARD      (-1000 -  2)
#define ERR_PIN       (-1000 -  3)
#define ERR_APDU      (-1000 -  4)
#define ERR_KEY       (-1000 -  5)
#define ERR_TEMPLATE  (-1000 -  6)
#define ERR_VERSION   (-1000 -  7)
#define ERR_SANITY    (-1000 -  8)
#define ERR_KEY_SIZE  (-1000 -  9)
#define ERR_HASH      (-1000 - 10)
#define ERR_TIME      (-1000 - 11)

#ifndef _USRDLL
#define EXPORT_FUNC
#else
#ifdef _WIN32
#define EXPORT_FUNC __declspec(dllexport) __cdecl
#else
#define EXPORT_FUNC
#endif
#endif

int EXPORT_FUNC sign_hash(const char *pin, const char *label,
	const unsigned char *hash, int hashLen,
	const unsigned char **ppCMS);

int EXPORT_FUNC sign_hash2(const char *reader, const char *pin, const char *label,
	const unsigned char *hash, int hashLen,
	const unsigned char **ppCMS);

void EXPORT_FUNC release_template();

typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} sha256_context;

void EXPORT_FUNC sha256_starts(sha256_context *ctx);
void EXPORT_FUNC sha256_update(sha256_context *ctx, unsigned char *input, unsigned int length);
void EXPORT_FUNC sha256_finish(sha256_context *ctx, unsigned char digest[32]);

#endif /* _sc_hsm_ultralite_h_ */
