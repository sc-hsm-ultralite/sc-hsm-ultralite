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
 * @file utils.c
 * @author Christoph Brunhuber
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "utils.h"
#include "sc-hsm-ultralite.h"

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 *********************** SmartCard Helper Functions ****************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

#ifdef CTAPI /* via libusb */
#include <ctccid/ctapi.h>

static uint16 Ctn;

/* used only for SC_Open */
static int SC_Init()
{
	uint8 dad = 1;   /* Reader */
	uint8 sad = 2;   /* Host   */
	uint8 buf[260];
	uint16 len = sizeof(buf);
	/* - REQUEST ICC */
	int rc = CT_data(Ctn, &dad, &sad, 5, (uint8*)"\x20\x12\x00\x01\x00", &len, buf);
	if (rc < 0 || buf[0] == 0x64 || buf[0] == 0x62)
		return ERR_CARD;
	return buf[len - 1] == 0x00 ? 1 : 2;  /* Memory or processor card ? */
}

#define MAXPORT 2

int SC_Open(const char *pin, const char *reader)
{
	int rc;
	uint16 i;
	/* find 1st available card */
	for (i = 0; i < MAXPORT; i++) {
		if (CT_init(i, i) < 0)
			continue;
		Ctn = i;
		if (SC_Init() < 0) {
			CT_close(i);
			continue;
		}
		break;
	}
	if (Ctn == MAXPORT) {
		log_err("no card found");
		return ERR_CARD;
	}
	rc = SC_Logon(pin);
	if (rc < 0) {
		CT_close(Ctn);
		return ERR_PIN;
	}
	return 0;
}

int SC_Close()
{
	return CT_close(Ctn);
}

#else /* via PCSC */
#ifndef _WIN32
#include <pcsclite.h>
#endif
#include <winscard.h>

static SCARDCONTEXT hContext;
static SCARDHANDLE hCard;

int SC_Open(const char *pin, const char* notused)
{
	int rc, len, found;
	LPSTR readerNames, readerName;
	DWORD readersLen;
	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rc != SCARD_S_SUCCESS) {
		log_err("could not establish pcsc context");
		return ERR_CONTEXT;
	}
	readersLen = SCARD_AUTOALLOCATE;
	rc = SCardListReaders(hContext, 0, (LPTSTR)&readerNames, &readersLen);
	if (rc != SCARD_S_SUCCESS || readerNames == NULL/*avoid compiler warning*/) {
		log_err("no reader found");
		rc = SCardReleaseContext(hContext);
		return ERR_READER;
	}
	hCard = 0;
	found = 0;
	// find 1st token which supports the CardContact application (see SC_Logon)
	for (readerName = readerNames; readerName[0] != 0; readerName += len) {
		DWORD proto;
		len = strlen(readerName) + 1;
		rc = SCardConnect(hContext, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &hCard, &proto);
		if (rc == SCARD_S_SUCCESS) {
			if (SC_Logon(NULL) == 0) {
				found = 1;
				break;
			} else {
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				hCard = 0;
			}
		}
	}
	SCardFreeMemory(hContext, readerNames);
	if (!found) {
		log_err("no card found");
		SC_Close();
		return ERR_CARD;
	}
	rc = SC_Logon(pin);
	if (rc < 0) {
		SC_Close();
		return ERR_PIN;
	}
	return 0;
}

int SC_Close()
{
	int rc;
	rc = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
	hCard = 0;
	rc = SCardReleaseContext(hContext);
	hContext = 0;
	return rc;
}

#endif /* !CTAPI */

int SC_Logon(const char *pin)
{
	uint16 sw1sw2;
	int rc, pinLen;
/*
The SELECT APDU allows the terminal to select the SmartCard-HSM application on the
device. The application is identified by the application identifier:
E8 2B 06 01 04 01 81 C3 1F 02 01
The aid represents the object identifier
iso(1) org(3) dod(6) internet(1) private(4) enterprise(1)
CardContact(24991) iso7816(2) smartcardhsm(1)
*/
	static uint8 aid[] = {
		0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01
	};
	/* - SmartCard-HSM: SELECT APPLICATION */
	rc = SC_ProcessAPDU(
		0, 0x00,0xA4,0x04,0x0C,
		aid, sizeof(aid),
		NULL, 0,
		&sw1sw2);
	if (rc < 0) {
		log_err("select applet returned %d", rc);
		return rc;
	}
	if (sw1sw2 != 0x9000) {
		log_err("select applet returned 0x%x", sw1sw2);
		return ERR_APDU;
	}

	if (pin == 0)
		return rc;
	pinLen = strlen(pin);
	/* - SmartCard-HSM: VERIFY PIN */
	rc = SC_ProcessAPDU(
		0, 0x00,0x20,0x00,0x81,
		(uint8*)pin, pinLen,
		NULL, 0,
		&sw1sw2);
	if (rc < 0) {
		log_err("verify pin returned %d", rc);
		return rc;
	}
	switch (sw1sw2) {
	case 0x9000:
		break;
	case 0x6700:
		log_err("verify pin returned 0x%x: Wrong length", sw1sw2);
		return ERR_PIN;
	case 0x6982:
		log_err("verify pin returned 0x%x: Authentication method blocked", sw1sw2);
		return ERR_PIN;
	default:
		if ((sw1sw2 & 0xfff0) == 0x63C0) {
			log_err("verify pin returned 0x%x: Wrong PIN, %d tries left", sw1sw2, sw1sw2 & 0xf);
			return ERR_PIN;
		}
		log_err("verify pin returned 0x%x", sw1sw2);
		return ERR_PIN;
	}
	return rc;
}

int SC_ReadFile(uint16 fid, int off, uint8 *data, int dataLen)
{
	uint16 sw1sw2;
	int rc;
	uint8 offset[4];
	offset[0] = 0x54;
	offset[1] = 0x02;
	offset[2] = off >> 8;
	offset[3] = off >> 0;
	/* - SmartCard-HSM: READ BINARY */
	rc = SC_ProcessAPDU(
		0, 0x00,
		0xB1,      /* READ BINARY */
		fid >> 8,  /* MSB(fid) */
		fid >> 0,  /* LSB(fid) */
		offset, 4,
		data, dataLen,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	return rc;
}

int SC_WriteFile(uint16 fid, int off, uint8 *data, int dataLen)
{
	uint16 sw1sw2;
	int rc;
	uint8 buf[MAX_OUT_IN];
	if (dataLen > MAX_OUT_IN - 6)
		return ERR_MEMORY;
	buf[0] = 0x54;
	buf[1] = 0x02;
	buf[2] = off >> 8;
	buf[3] = off >> 0;
	buf[4] = 0x53;
	buf[5] = 0;
	memcpy(buf + 6, data, dataLen);

	/* - SmartCard-HSM: UPDATE BINARY */
	rc = SC_ProcessAPDU(
		0, 0x00,
		0xD7,      /* UPDATE BINARY */
		fid >> 8,  /* MSB(fid) */
		fid >> 0,  /* LSB(fid) */
		buf, 6 + dataLen,
		NULL, 0,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000)
		return ERR_APDU;
	return rc;
}

int SC_Sign(uint8 op, uint8 keyFid,
	uint8 *outBuf, int outLen,
	uint8 *inBuf, int inSize)
{
	uint16 sw1sw2;
	int rc;
	/* - SmartCard-HSM: SIGN */
	rc = SC_ProcessAPDU(
		0, 0x80,
		0x68, /* SIGN */
		keyFid,
		op, /* Plain RSA(0x20) or ECDSA(0x70) signature */
		outBuf, outLen,
		inBuf, inSize,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	return rc;
}

/*
 *  Process an ISO 7816 APDU with the underlying terminal hardware.
 *
 *  cla     : Class byte of instruction
 *  ins     : Instruction byte
 *  p1      : Parameter P1
 *  p2      : Parameter P2
 *  outData : Outgoing data or NULL if none
 *  outLen  : Length of outgoing data (Lc)
 *  inData  : Input buffer for incoming data
 *  inLen   : Length of incoming data (Le)
 *  sw1sw2  : Address of short integer to receive sw1sw2
 *
 *  Returns : < 0 Error >= 0 Bytes read
 */
int SC_ProcessAPDU(
	int todad,
	uint8 cla, uint8 ins, uint8 p1, uint8 p2,
	uint8 *outData, int outLen,
	uint8 *inData, int inLen,
	uint16 *sw1sw2)
{
	uint8 scr[4 + 5 + MAX_OUT_IN];
	int rc;
#ifdef CTAPI
	uint16 len;
#else
	DWORD len;
#endif
	uint8 dad, sad;
	uint8 *p;

	/* Reset status word */
	*sw1sw2 = 0x0000;

	if (!scr
		|| 4 + 5 + outLen > sizeof(scr)        /* worst case: long APDU and in and out */
		|| inLen + 2 > sizeof(scr)             /* need space for sw1sw2 */
		|| !(0 <= inLen  && inLen  <= 0x10000) /* crazy - invalid in length */
		|| !(0 <= outLen && outLen <= 0x10000) /* crazy - invalid out length */
		|| outLen > 0 && !outData              /* no out buffer */
		|| inLen  > 0 && !inData               /* no in buffer */
	)
		return ERR_MEMORY;

	p = scr;
	*p++ = cla;
	*p++ = ins;
	*p++ = p1;
	*p++ = p2;
	/* if Lc not present use long APDU for inLen == 256 */
	/* outLen == 0 && inLen == 256 => ambiguous b/c first byte 0 should mean extended APDU */
	if (outLen <= 255
		&& (inLen <= 255 || outLen > 0 && inLen == 256))
	{                                    /* use short APDU */
		if (outLen > 0) {                /* Lc present */
			*p++ = (uint8)outLen;
			memcpy(p, outData, outLen);
			p += outLen;
		}
		if (inLen > 0)                   /* Le present */
			*p++ = (uint8)inLen;         /* (uint8)256 == 0 */
	} else {                             /* use long APDU */
		*p++ = 0;                        /* indicate long APDU */
		if (outLen > 0) {                /* Lc present */
			*p++ = (uint8)(outLen >> 8);
			*p++ = (uint8)(outLen     );
			memcpy(p, outData, outLen);
			p += outLen;
		}
		if (inLen > 0) {                 /* Le present */
			*p++ = (uint8)(inLen >> 8);
			*p++ = (uint8)(inLen     );
		}
	}
	sad = HOST;
	dad = todad;
	len = sizeof(scr);
#ifdef CTAPI
	rc = CT_data(Ctn, &dad, &sad, (unsigned short)(p - scr), scr, &len, scr);
#else
	rc = SCardTransmit(hCard, SCARD_PCI_T1, scr, (unsigned)(p - scr), 0, scr, &len);
#endif
	if (rc < 0)
		return rc;
	if (len < 2) /* sw1sw2 missing? */
		return ERR_INVALID;
	if (len - 2 > inLen) /* never truncate */
		return ERR_INVALID;
	if (scr[len - 2] == 0x6C) /* not enough buffer supplied */
		return ERR_MEMORY;
	rc = len - 2;
	if (inLen > 0)
		memcpy(inData, scr, rc);
	*sw1sw2 = scr[len - 2] << 8 | scr[len - 1];
	return rc;
}

