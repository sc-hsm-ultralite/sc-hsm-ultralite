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
 * @file utils.h
 * @author Christoph Brunhuber
 * @brief Internal use only.
 */

#ifndef __utils_h__
#define __utils_h__

#if defined(_WIN32) || defined(__linux__)
#define MAX_OUT_IN 8192
#else /* save stack space on systems with limited memory */
#define MAX_OUT_IN 256
#endif

typedef unsigned char uint8;
typedef unsigned short uint16;

#ifdef __cplusplus
extern "C" {
#endif

/* utility functions */

int SC_Open(const char *pin, const char *reader);
int SC_Close();
int SC_Logon(const char *pin);
int SC_ReadFile(uint16 fid, int off, uint8 *data, int dataLen);
int SC_WriteFile(uint16 fid, int off, uint8 *data, int dataLen);
int SC_Sign(uint8 op, uint8 keyFid,
	uint8 *outBuf, int outLen,
	uint8 *inBuf, int inSize);
int SC_ProcessAPDU(
	int todad,
	uint8 cla, uint8 ins, uint8 p1, uint8 p2,
	uint8 *outData, int outLen,
	uint8 *inData, int inLen,
	uint16 *sw1sw2);

#define SaveToFile(name, ptr, len) {\
	FILE *f = fopen(name, "wb");\
	if (f) {\
		if ((len) > 0)\
			fwrite(ptr, 1, len, f);\
		fclose(f);\
	}\
}

#define ReadFromFile(name, ptr, len) {\
	FILE *f = fopen(name, "rb");\
	ptr = 0;\
	len = -1;\
	if (f) {\
		fseek(f, 0, SEEK_END);\
		len = ftell(f);\
		if (len > 0) {\
			ptr = (uint8*)malloc(len);\
			if (ptr) {\
				fseek(f, 0, SEEK_SET);\
				len = fread(ptr, 1, len, f);\
			}\
		}\
		fclose(f);\
	}\
}

#ifdef __cplusplus
}
#endif
#endif /* __utils_h__ */
