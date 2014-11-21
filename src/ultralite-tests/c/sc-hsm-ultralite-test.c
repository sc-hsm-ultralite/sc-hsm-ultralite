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
#include <ultralite/sc-hsm-ultralite.h>

#ifdef _WIN32
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#include <windows.h>
#ifndef usleep
#define usleep(us) Sleep((us) / 1000)
#endif
#else
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
	int i;
	FILE* fp;
	unsigned char buf[0x10000], hash[32]; /* 32 => 256-bit sha256 */
	sha256_context ctx;
	char name[256];
	const unsigned char *pCms = 0;
	int count = argc >= 4 ? atoi(argv[3]) : 1;
	int wait  = argc >= 5 ? atoi(argv[4]) : 10000;

#if defined(_WIN32) && defined(_DEBUG)
	atexit((void(*)(void))_CrtDumpMemoryLeaks);
#endif

	/* Check args */
	if (argc < 3) {
		printf("Usage: pin label [count [wait-in-milliseconds]]\nSign this executable (%s).\n", argv[0]);
		return 1;
	}

	/* Create a SHA-256 hash of this executable */
	sha256_starts(&ctx);
	fp = fopen(argv[0], "rb");
	if (!fp) {
		int e = errno;
		printf("error opening file '%s': %s\n", argv[0], strerror(e));
		return e;
	}
	for (;;) {
		int n = fread(buf, 1, sizeof(buf), fp);
		if (n <= 0)
			break;
		sha256_update(&ctx, buf, n);
	}
	fclose(fp);
	sha256_finish(&ctx, hash);

	/* Sign the hash of this executable n times, where n = count */
	for (i = 0; i < count; i++) {
		int len;
		long start, end;
		if (i > 0 && count > 1) {
			printf("wait %d milliseconds for next signature\n", wait);
			usleep(wait * 1000);
		}
		start = GetTickCount();
		len   = sign_hash(argv[1], argv[2], hash, sizeof(hash), &pCms);
		end   = GetTickCount();
		printf("sign_hash returned: %d, time used: %ld ms\n", len, end - start);
		if (len <= 0) /* sign_hash error */
			break;
		sprintf(name, "%s.p7s", argv[0]);
		fp = fopen(name, "wb");\
		if (!fp) {
			int e = errno;
			printf("error opening file '%s': %s\n", name, strerror(e));
			break;
		}
		fwrite(pCms, 1, len, fp);
		fclose(fp);
	}
	release_template();

	return 0;
}
