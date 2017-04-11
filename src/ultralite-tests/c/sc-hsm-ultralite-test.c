/**
 * SmartCard-HSM Ultra-Light Library Test Application
 *
 * Copyright (c) 2013. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the BSD 3-Clause License. You should have
 * received a copy of the BSD 3-Clause License along with this program.
 * If not, see <http://opensource.org/licenses/>
 *
 * @file sc-hsm-ultralite-test.c
 * @author Keith Morgan, Christoph Brunhuber
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ultralite/log.h>
#include <ultralite/sc-hsm-ultralite.h>

#ifdef _WIN32
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#include <windows.h>
/* define below after <stdio.h> */
#define snprintf _snprintf
#ifndef usleep
#define usleep(us) Sleep((us) / 1000)
#endif
#else
#include <dirent.h>
#define MAX_PATH PATH_MAX
/* Windows GetTickCount() returns ms since startup.
 * This function returns ms since the Epoch.
 * Since we're doing a delta it's OK
 */
long GetTickCount()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
#endif

int main(int argc, char **argv)
{
	int i, rv;
	FILE* fp;
	unsigned char buf[0x10000], hash[32]; /* 32 => 256-bit sha256 */
	sha256_context ctx;
	const unsigned char *pCms = 0;
	int count = argc >= 4 ? atoi(argv[3]) : 1;
	int wait  = argc >= 5 ? atoi(argv[4]) : 10000;

#if defined(_WIN32) && defined(_DEBUG)
	atexit((void(*)(void))_CrtDumpMemoryLeaks);
#endif

	/* Check args */
	if (argc < 3) {
		fprintf(stderr, "Usage: pin label [count [wait]]\n");
		fprintf(stderr, "Signs this executable.\n");
		fprintf(stderr, "If the optional argument 'count' is specified, repeats signing 'count' times.\n");
		fprintf(stderr, "If the optional argument 'wait'  is specified, waits 'wait' ms between each\n");
		fprintf(stderr, "signing operation. By default, waits 10 seconds between operations.\n");
		return 1;
	}

	/* Disable buffering on stdout/stderr to prevent mixing the order of
	   messages to stdout/stderr when redirected to the same log file */
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* Create a SHA-256 hash of this executable */
	sha256_starts(&ctx);
	fp = fopen(argv[0], "rb");
	if (!fp) {
		int e = errno;
		log_err("error opening file '%s': %s", argv[0], strerror(e));
		return e;
	}
	for (;;) {
		int n = fread(buf, 1, sizeof(buf), fp);
		if (n <= 0)
			break;
		sha256_update(&ctx, buf, n);
	}
	rv = fclose(fp);
	if (rv) {
		int e = errno;
		log_err("error closing file '%s': %s", argv[0], strerror(e));
		return e;
	}
	sha256_finish(&ctx, hash);

	/* Sign the hash of this executable n times, where n = count */
	rv = 0;
	for (i = 0; i < count; i++) {
		int n, len;
		long start, end;
		char sig_path[MAX_PATH];
		if (i > 0 && count > 1) {
			log_inf("wait %d ms for next signature", wait);
			usleep(wait * 1000);
		}
		start = GetTickCount();
		len   = sign_hash(argv[1], argv[2], hash, sizeof(hash), &pCms);
		end   = GetTickCount();
		if (len <= 0) { /* sign_hash error */
			rv = len;
			break;
		}
		log_inf("test ok, time used: %ld ms", end - start);
		n = snprintf(sig_path, sizeof(sig_path), "%s.p7s", argv[0]);
		if (n < 0 || n >= sizeof(sig_path)) {
			rv = ENAMETOOLONG;
			log_err("error building sig file path '%s.p7s'", argv[0]);
			break;
		}
		fp = fopen(sig_path, "wb");
		if (!fp) {
			int e = rv = errno;
			log_err("error opening file '%s': %s", sig_path, strerror(e));
			break;
		}
		n = fwrite(pCms, 1, len, fp);
		if (n != len) {
			int e = rv = ferror(fp);
			log_err("error writing to sig file '%s': %s", sig_path, strerror(e));
			fclose(fp);
			break;
		}
		fclose(fp);
	}
	release_template();

	return rv;
}
