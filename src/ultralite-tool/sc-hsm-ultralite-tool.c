/**
 * SmartCard-HSM Ultra-Light Library Tool
 *
 * Copyright (c) 2013. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the BSD 3-Clause License. You should have
 * received a copy of the BSD 3-Clause License along with this program.
 * If not, see <http://opensource.org/licenses/>
 *
 * @file sc-hsm-ultralite-tool.c
 * @author Christoph Brunhuber
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ultralite/utils.h>
#include <ultralite/sc-hsm-ultralite.h>

#if defined(_WIN32) && defined(_DEBUG)
#include <crtdbg.h>
#endif

int Hex2Bin(const char* hex, int len, uint8* bin)
{
	int i;
	if (len & 1) {
		printf("invalid hex number (odd length): '%s'\n", hex);
		return ERR_INVALID;
	}
	for (i = 0; i < len; i += 2) {
		int hi = hex[i + 0];
		int lo = hex[i + 1];
#define HEX(ch) (\
		'0' <= ch && ch <= '9' \
		? ch - '0' \
		: 'A' <= ch && ch <= 'F' \
			? 10 + ch - 'A' \
			: 'a' <= ch && ch <= 'f' \
				? 10 + ch - 'a' \
				: -1)
		int b = HEX(hi) << 4 | HEX(lo);
#undef HEX
		if (b < 0) {
			printf("invalid hex number (non hex digit): '%s'\n", hex);
			return ERR_INVALID;
		}
		bin[i / 2] = b;
	}
	return 0;
}

int GetPinStatus()
{
	uint16 sw1sw2;
	int rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: VERIFY */
	rc = SC_ProcessAPDU(
		0, 0x00,0x20,0x00,0x81,
		NULL, 0,
		NULL, 0,
		&sw1sw2);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int InitializeToken(const char *pin, const char *sopin, int dkeksCount, uint8 *dkeks)
{
	uint16 sw1sw2;
	int rc, i;
	uint8 data[2 + 2 + 18 + 18 + 2 + 2];
	uint8 *p = data;
	int pin_len = strlen(pin);
	if (!(6 <= pin_len && pin_len <= 16)) {
		printf("PIN must have 6 - 16 chars\n");
		return ERR_INVALID;
	}
	/* Configuration Options (currently '0001') */
	*p++ = 0x80; *p++ = 0x02; *p++ = 0x00; *p++ = 0x01;
	/* Initial PIN value */
	*p++ = 0x81; *p++ = (uint8)pin_len; memcpy(p, pin, pin_len); p += pin_len;
	/* Initialization Code (== SO_PIN) */
	*p++ = 0x82; *p++ = 0x08;
	if (sopin == 0) {
		memcpy(p, "\x35\x37\x36\x32\x31\x38\x38\x30", 8);
	} else {
		if (strlen(sopin) != 16) {
			printf("SO_PIN must have 16 hex-digits\n");
			return ERR_INVALID;
		}
		rc = Hex2Bin(sopin, 16, p);
		if (rc)
			return rc;
	}
	p += 8;
	/* Retry Counter Initial Value */
	*p++ = 0x91; *p++ = 0x01; *p++ = 3;
	/* Number of Device Encryption Key shares */
	if (dkeksCount) {
		*p++ = 0x92; *p++ = 0x01; *p++ = dkeksCount;
	}

	rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: INITIALIZE DEVICE */
	rc = SC_ProcessAPDU(
		0, 0x80,0x50,0x00,0x00,
		data, (int)(p - data),
		NULL, 0,
		&sw1sw2);
	if (rc < 0) {
		SC_Close();
		return rc;
	}
	if (sw1sw2 != 0x9000) {
		SC_Close();
		return sw1sw2;
	}
	for (i = 0, p = dkeks; i < dkeksCount; i++, p += 0x20) {
		uint8 buf[10];
		/* - SmartCard-HSM: IMPORT DKEK SHARE */
		rc = SC_ProcessAPDU(
			0, 0x80,0x52,0x00,0x00,
			p, 0x20,
			buf, 10,
			&sw1sw2);
		if (rc < 0) {
			SC_Close();
			return rc;
		}
		if (sw1sw2 != 0x9000) {
			SC_Close();
			return sw1sw2;
		}
		printf("total shares: %d, outstanding shares: %d, key check value: %02x%02x%02x%02x%02x%02x%02x%02x\n",
			buf[0],
			buf[1],
			buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]);
	}
	SC_Close();
	return sw1sw2;
}

int UnlockPin(const char *sopin)
{
	uint16 sw1sw2;
	int rc;
	uint8 so_pin[8];
	if (strlen(sopin) != 16) {
		printf("SO_PIN must have 16 hex-digits\n");
		return ERR_INVALID;
	}
	rc = Hex2Bin(sopin, 16, so_pin);
	if (rc)
		return rc;
	rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: RESET RETRY COUNTER */
	rc = SC_ProcessAPDU(
		0, 0x00,0x2C,0x01,0x81,
		so_pin, 8,
		NULL, 0,
		&sw1sw2);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int SetPin(const char *pin, const char *sopin)
{
	uint16 sw1sw2;
	int rc;
	uint8 so_pin_pin[8 + 16];
	int pin_len = strlen(pin);
	if (!(6 <= pin_len && pin_len <= 16)) {
		printf("PIN must have 6 - 16 chars\n");
		return ERR_INVALID;
	}
	if (sopin == 0) {
		memcpy(so_pin_pin, "\x35\x37\x36\x32\x31\x38\x38\x30", 8);
	} else {
		if (strlen(sopin) != 16) {
			printf("SO_PIN must have 16 hex-digits\n");
			return ERR_INVALID;
		}
		rc = Hex2Bin(sopin, 16, so_pin_pin);
		if (rc)
			return rc;
	}
	memcpy(so_pin_pin + 8, pin, pin_len); /* no 0 terminator */
	rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: RESET RETRY COUNTER */
	rc = SC_ProcessAPDU(
		0, 0x00,0x2C,0x00,0x81,
		so_pin_pin, 8 + pin_len,
		NULL, 0,
		&sw1sw2);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int ChangePin(const char *oldpin, const char *newpin)
{
	uint16 sw1sw2;
	int rc, old_len, new_len;
	uint8 pins[32];
	old_len = strlen(oldpin);
	if (!(6 <= old_len && old_len <= 16)) {
		printf("old PIN must have 6 - 16 chars\n");
		return ERR_INVALID;
	}
	new_len = strlen(newpin);
	if (new_len != old_len) {
		printf("new PIN must have same size as old pin\n");
		return ERR_INVALID;
	}
	memcpy(pins,           oldpin, old_len); /* no 0 terminator */
	memcpy(pins + old_len, newpin, new_len); /* no 0 terminator */
	rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: CHANGE REFERENCE DATA */
	rc = SC_ProcessAPDU(
		0, 0x00,0x24,0x00,0x81,
		pins, old_len + new_len,
		NULL, 0,
		&sw1sw2);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int ChangeSoPin(const char *oldsopin, const char *newsopin)
{
	uint16 sw1sw2;
	int rc;
	uint8 so_pin_so_pin[8 + 8];
	if (strlen(oldsopin) != 16) {
		printf("old SO_PIN must have 16 hex-digits\n");
		return ERR_INVALID;
	}
	rc = Hex2Bin(oldsopin, 16, so_pin_so_pin);
	if (rc)
		return rc;
	if (strlen(newsopin) != 16) {
		printf("new SO_PIN must have 16 hex-digits\n");
		return ERR_INVALID;
	}
	rc = Hex2Bin(newsopin, 16, so_pin_so_pin + 8);
	if (rc)
		return rc;
	rc = SC_Open(0, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: CHANGE REFERENCE DATA */
	rc = SC_ProcessAPDU(
		0, 0x00,0x24,0x00,0x88,
		so_pin_so_pin, 8 + 8,
		NULL, 0,
		&sw1sw2);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int WrapKey(const char *pin, int keyid, const char* filename)
{
	uint16 sw1sw2;
	uint8 wrapped[1024];
	int rc;
	if (!(1 <= keyid && keyid <= 127)) {
		printf("keyid (%d) must be between 1 and 127\n", keyid);
		return ERR_INVALID;
	}
	rc = SC_Open(pin, 0);
	if (rc < 0)
		return rc;
	/* - SmartCard-HSM: WRAP KEY */
	rc = SC_ProcessAPDU(
		0, 0x80,0x72,keyid,0x92,
		NULL, 0,
		wrapped, sizeof(wrapped),
		&sw1sw2);
	SC_Close();
	if (rc <= 0)
		return rc;
	SaveToFile(filename, wrapped, rc);
	return sw1sw2;
}

int UnwrapKey(const char *pin, int keyid, const char* filename)
{
	uint16 sw1sw2;
	uint8 *pWrapped;
	int len;
	int rc = SC_Open(pin, 0);
	if (rc < 0)
		return rc;
	if (!(1 <= keyid && keyid <= 127)) {
		printf("keyid (%d) must be between 1 and 127\n", keyid);
		return ERR_INVALID;
	}
	ReadFromFile(filename, pWrapped, len);
	if (pWrapped == NULL) {
		printf("file '%s' not found\n", filename);
		return ERR_INVALID;
	}
	if (len <= 0) {
		free(pWrapped);
		printf("file '%s' empty\n", filename);
		return ERR_INVALID;
	}
	/* - SmartCard-HSM: UNWRAP KEY */
	rc = SC_ProcessAPDU(
		0, 0x80,0x74,keyid,0x93,
		pWrapped, len,
		NULL, 0,
		&sw1sw2);
	free(pWrapped);
	SC_Close();
	if (rc < 0)
		return rc;
	return sw1sw2;
}

int DumpAllFiles(const char *pin)
{
	uint8 list[2 * 128];
	uint16 sw1sw2;
	int rc, i;
	rc = SC_Open(pin, 0);
	if (rc < 0)
		return rc;

	/* - SmartCard-HSM: ENUMERATE OBJECTS */
	rc = SC_ProcessAPDU(
		0, 0x80,0x58,0x00,0x00,
		NULL, 0,
		list, sizeof(list),
		&sw1sw2);
	if (rc < 0) {
		SC_Close();
		return rc;
	}
	/* save dir and all files */
	printf("write 'dir.hsm'\n");
	SaveToFile("dir.hsm", list, rc);
	for (i = 0; i < rc; i += 2) {
		uint8 buf[8192], *p;
		char name[10];
		int rc, off;
		uint16 fid = list[i] << 8 | list[i + 1];
		if (list[i] == 0xcc) /* never readable */
			continue;
		for (p = buf, off = 0; off < sizeof(buf); p += rc) {
			int l = sizeof(buf) - off;
			if (l > MAX_OUT_IN)
				l = MAX_OUT_IN;
			rc = SC_ReadFile(fid, off, p, l);
			if (rc < 0)
				break;
			off += rc;
			if (rc < l)
				break;
		}
		if (rc >= 0) {
			sprintf(name, "%04X.asn", fid);
			printf("write '%s'\n", name);
			SaveToFile(name, buf, off);
		}
	}
	SC_Close();
	return 0;
}

int Usage()
{
	printf("\
Usage: action args...\n\n\
  --get-pin-status \n\
  --save-files [pin] (write all token elementary files to disk)\n\
  --restore-files pin abcd.asn ... (restore the specified elementary files)\n\
  --init-token pin [so-pin [file-of-DKEK-shares]] (so-pin defaults to '3537363231383830')\n\
  --unlock-pin so-pin\n\
  --set-pin pin [so-pin] (so-pin defaults to '3537363231383830')\n\
  --change-pin old-pin new-pin\n\
  --change-so-pin old-so-pin new-so-pin\n\
  --wrap-key pin key-id file-name\n\
  --unwrap-key pin key-id file-name\n");
	return 1;
}


int main(int argc, char **argv)
{
	int i, rc;
#if defined(_WIN32) && defined(_DEBUG)
	atexit((void(*)(void))_CrtDumpMemoryLeaks);
#endif
	if (argc < 2)
		return Usage();

	if (strcmp(argv[1], "--get-pin-status") == 0) {
		rc = GetPinStatus();
		printf("get-pin-status returns: 0x%4x\n", rc);
		return 0;
	}
	if (strcmp(argv[1], "--save-files") == 0) {
		DumpAllFiles(argc >= 3 ? argv[2] : 0);
		return 0;
	}
	if (argc < 3)
		return Usage();

	if (strcmp(argv[1], "--restore-files") == 0) {
		int rc = SC_Open(argv[2], 0);
		if (rc < 0)
			return rc;
		for (i = 3; i < argc; i++) {
			const char *name = argv[i];
			int dataLen, off;
			uint8 *pData;
			uint8 afid[2];
			uint16 fid;
			if (strlen(name) != 8 || strcmp(name + 4, ".asn") || Hex2Bin(name, 4, afid)) {
				printf("filename '%s' must be 'abcd.asn' where abcd is a valid hex number\n", name);
				continue;
			}
			fid = afid[0] << 8 | afid[1];
			if (fid == 0x2f02) {
				printf("filename '%s' skipped, EF_DevAut is readonly\n", name);
				continue;
			}
			ReadFromFile(name, pData, dataLen);
			if (pData == NULL) {
				printf("cant read file '%s'\n", name);
				continue;
			}
			if (dataLen == 0) {
				free(pData);
				printf("file '%s' empty\n", name);
				continue;
			}
			rc = 0;
			for (off = 0; off < dataLen;) {
				int len = dataLen - off;
				if (len > MAX_OUT_IN - 6)
					len = MAX_OUT_IN - 6;
				rc = SC_WriteFile(fid, off, pData + off, len);
				if (rc < 0)
					break;
				off += len;
			}
			free(pData);
			if (rc < 0) {
				printf("write error %d file '%s'\n", rc, name);
				continue;
			}
			printf("file '%s' successfully restored\n", name);
		}
		SC_Close();
		return 0;
	}
	if (strcmp(argv[1], "--init-token") == 0) {
		int len;
		uint8* buf;
		switch (argc) {
		default:
			return Usage();
		case 3:
			rc = InitializeToken(argv[2], NULL, 0, NULL);
			break;
		case 4:
			rc = InitializeToken(argv[2], argv[3], 0, NULL);
			break;
		case 5:
			ReadFromFile(argv[4], buf, len);
			if (buf == NULL) {
				printf("file '%s' not found\n", argv[4]);
				return ERR_INVALID;
			}
			if (len < 32 || (len & 31)) {
				free(buf);
				printf("file length of '%s' must be a positive multiple of 32\n", argv[4]);
				return ERR_INVALID;
			}
			rc = InitializeToken(argv[2], argv[3], len / 32, buf);
			free(buf);
			break;
		}
		printf("init-token returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--unlock-pin") == 0) {
		if (!(3 <= argc && argc <= 3))
			return Usage();
		rc = UnlockPin(argv[2]);
		printf("unlock-pin returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--set-pin") == 0) {
		if (!(3 <= argc && argc <= 4))
			return Usage();
		rc = SetPin(argv[2], argc == 3 ? NULL : argv[3]);
		printf("set-pin returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--change-pin") == 0) {
		if (!(4 <= argc && argc <= 4))
			return Usage();
		rc = ChangePin(argv[2], argv[3]);
		printf("change-pin returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--change-so-pin") == 0) {
		if (!(4 <= argc && argc <= 4))
			return Usage();
		rc = ChangeSoPin(argv[2], argv[3]);
		printf("change-pin returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--wrap-key") == 0) {
		if (!(5 <= argc && argc <= 5))
			return Usage();
		rc = WrapKey(argv[2], atoi(argv[3]), argv[4]);
		printf("wrap-key returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	if (strcmp(argv[1], "--unwrap-key") == 0) {
		if (!(5 <= argc && argc <= 5))
			return Usage();
		rc = UnwrapKey(argv[2], atoi(argv[3]), argv[4]);
		printf("unwrap-key returns: 0x%4x\n", rc);
		return rc == 0x9000 ? 0 : rc;
	}
	return Usage();
}
