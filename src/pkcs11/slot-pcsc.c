/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2013, CardContact Systems GmbH, Minden, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of CardContact Systems GmbH nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CardContact Systems GmbH BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file    slot-pcsc.c
 * @author  Frank Thater
 * @brief   Slot implementation for PC/SC reader
 */

#ifndef CTAPI

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot-pcsc.h>
#include <pkcs11/strbpcpy.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#ifndef _WIN32
#include <pcsclite.h>
#endif

#include <winscard.h>

extern struct p11Context_t *context;

static unsigned char ATRs[][24] = { /* expected (A)nswer (T)o (R)equest */
	0x3B, 0xFE, 0x18, 0x00, 0x00, 0x81, 0x31, 0xFE,
	0x45, 0x80, 0x31, 0x81, 0x54, 0x48, 0x53, 0x4D,
	0x31, 0x73, 0x80, 0x21, 0x40, 0x81, 0x07, 0xFA,

	0x3B, 0xDE, 0x96, 0xFF, 0x81, 0x91, 0xFE, 0x1F,
	0xC3, 0x80, 0x31, 0x81, 0x54, 0x48, 0x53, 0x4D,
	0x31, 0x73, 0x80, 0x21, 0x40, 0x81, 0x07, 0x92,
};

#ifdef DEBUG

#define _75 75

char* pcsc_error_to_string(const LONG error, char strError[_75])
{
	switch (error) {
		case SCARD_S_SUCCESS:
			(void) strncpy(strError, "Command successful.", _75);
			break;
		case SCARD_F_INTERNAL_ERROR:
			(void) strncpy(strError, "Internal error.", _75);
			break;
		case SCARD_E_CANCELLED:
			(void) strncpy(strError, "Command cancelled.", _75);
			break;
		case SCARD_E_INVALID_HANDLE:
			(void) strncpy(strError, "Invalid handle.", _75);
			break;
		case SCARD_E_INVALID_PARAMETER:
			(void) strncpy(strError, "Invalid parameter given.", _75);
			break;
		case SCARD_E_INVALID_TARGET:
			(void) strncpy(strError, "Invalid target given.", _75);
			break;
		case SCARD_E_NO_MEMORY:
			(void) strncpy(strError, "Not enough memory.", _75);
			break;
		case SCARD_F_WAITED_TOO_LONG:
			(void) strncpy(strError, "Waited too long.", _75);
			break;
		case SCARD_E_INSUFFICIENT_BUFFER:
			(void) strncpy(strError, "Insufficient buffer.", _75);
			break;
		case SCARD_E_UNKNOWN_READER:
			(void) strncpy(strError, "Unknown reader specified.", _75);
			break;
		case SCARD_E_TIMEOUT:
			(void) strncpy(strError, "Command timeout.", _75);
			break;
		case SCARD_E_SHARING_VIOLATION:
			(void) strncpy(strError, "Sharing violation.", _75);
			break;
		case SCARD_E_NO_SMARTCARD:
			(void) strncpy(strError, "No smart card inserted.", _75);
			break;
		case SCARD_E_UNKNOWN_CARD:
			(void) strncpy(strError, "Unknown card.", _75);
			break;
		case SCARD_E_CANT_DISPOSE:
			(void) strncpy(strError, "Cannot dispose handle.", _75);
			break;
		case SCARD_E_PROTO_MISMATCH:
			(void) strncpy(strError, "Card protocol mismatch.", _75);
			break;
		case SCARD_E_NOT_READY:
			(void) strncpy(strError, "Subsystem not ready.", _75);
			break;
		case SCARD_E_INVALID_VALUE:
			(void) strncpy(strError, "Invalid value given.", _75);
			break;
		case SCARD_E_SYSTEM_CANCELLED:
			(void) strncpy(strError, "System cancelled.", _75);
			break;
		case SCARD_F_COMM_ERROR:
			(void) strncpy(strError, "RPC transport error.", _75);
			break;
		case SCARD_F_UNKNOWN_ERROR:
			(void) strncpy(strError, "Unknown error.", _75);
			break;
		case SCARD_E_INVALID_ATR:
			(void) strncpy(strError, "Invalid ATR.", _75);
			break;
		case SCARD_E_NOT_TRANSACTED:
			(void) strncpy(strError, "Transaction failed.", _75);
			break;
		case SCARD_E_READER_UNAVAILABLE:
			(void) strncpy(strError, "Reader is unavailable.", _75);
			break;
		case SCARD_E_PCI_TOO_SMALL:
			(void) strncpy(strError, "PCI struct too small.", _75);
			break;
		case SCARD_E_READER_UNSUPPORTED:
			(void) strncpy(strError, "Reader is unsupported.", _75);
			break;
		case SCARD_E_DUPLICATE_READER:
			(void) strncpy(strError, "Reader already exists.", _75);
			break;
		case SCARD_E_CARD_UNSUPPORTED:
			(void) strncpy(strError, "Card is unsupported.", _75);
			break;
		case SCARD_E_NO_SERVICE:
			(void) strncpy(strError, "Service not available.", _75);
			break;
		case SCARD_E_SERVICE_STOPPED:
			(void) strncpy(strError, "Service was stopped.", _75);
			break;
		case SCARD_E_NO_READERS_AVAILABLE:
			(void) strncpy(strError, "Cannot find a smart card reader.", _75);
			break;
		case SCARD_W_UNSUPPORTED_CARD:
			(void) strncpy(strError, "Card is not supported.", _75);
			break;
		case SCARD_W_UNRESPONSIVE_CARD:
			(void) strncpy(strError, "Card is unresponsive.", _75);
			break;
		case SCARD_W_UNPOWERED_CARD:
			(void) strncpy(strError, "Card is unpowered.", _75);
			break;
		case SCARD_W_RESET_CARD:
			(void) strncpy(strError, "Card was reset.", _75);
			break;
		case SCARD_W_REMOVED_CARD:
			(void) strncpy(strError, "Card was removed.", _75);
			break;
		case SCARD_E_UNSUPPORTED_FEATURE:
			(void) strncpy(strError, "Feature not supported.", _75);
			break;
	};

	/* add a null byte */
	strError[_75 - 1] = '\0';

	return strError;
}



char* pcsc_feature_to_string(const WORD feature, char strFeature[_75])
{
	switch (feature) {
		case FEATURE_VERIFY_PIN_START:
			(void) strncpy(strFeature, "VERIFY_PIN_START", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_FINIS:
			(void) strncpy(strFeature, "VERIFY_PIN_FINISH", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_START:
			(void) strncpy(strFeature, "MODIFY_PIN_START", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_FINISH:
			(void) strncpy(strFeature, "MODIFY_PIN_FINISH", sizeof(strFeature));
			break;
		case FEATURE_GET_KEY_PRESSED:
			(void) strncpy(strFeature, "GET_KEY_PRESSED", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_DIRECT:
			(void) strncpy(strFeature, "VERIFY_PIN_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_DIRECT:
			(void) strncpy(strFeature, "MODIFY_PIN_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MCT_READER_DIRECT:
			(void) strncpy(strFeature, "MCT_READER_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MCT_UNIVERSAL:
			(void) strncpy(strFeature, "MCT_UNIVERSAL", sizeof(strFeature));
			break;
		case FEATURE_IFD_PIN_PROPERTIES:
			(void) strncpy(strFeature, "IFD_PIN_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_ABORT:
			(void) strncpy(strFeature, "ABORT", sizeof(strFeature));
			break;
		case FEATURE_SET_SPE_MESSAGE:
			(void) strncpy(strFeature, "SET_SPE_MESSAGE", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_DIRECT_APP_ID:
			(void) strncpy(strFeature, "VERIFY_PIN_DIRECT_APP_ID", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_DIRECT_APP_ID:
			(void) strncpy(strFeature, "MODIFY_PIN_DIRECT_APP_ID", sizeof(strFeature));
			break;
		case FEATURE_WRITE_DISPLAY:
			(void) strncpy(strFeature, "WRITE_DISPLAY", sizeof(strFeature));
			break;
		case FEATURE_GET_KEY:
			(void) strncpy(strFeature, "GET_KEY", sizeof(strFeature));
			break;
		case FEATURE_IFD_DISPLAY_PROPERTIES:
			(void) strncpy(strFeature, "IFD_DISPLAY_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_GET_TLV_PROPERTIES:
			(void) strncpy(strFeature, "GET_TLV_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_CCID_ESC_COMMAND:
			(void) strncpy(strFeature, "CCID_ESC_COMMAND", sizeof(strFeature));
			break;
		default:
			(void) strncpy(strFeature, "Unknown feature.", sizeof(strFeature));
			break;
	};

	/* add a null byte */
	strFeature[sizeof(strFeature) - 1] = '\0';

	return strFeature;
}
#endif /* DEBUG */



/**
 * Transmit APDU using PC/SC
 *
 * @param slot the slot to use for communication
 * @param capdu the command APDU
 * @param capdu_len the length of the command APDU
 * @param rapdu the response APDU
 * @param rapdu_len the length of the response APDU
 * @return -1 for error or length of received response APDU
 */
int transmitAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len)
{
	LONG rc;
	DWORD lenr;
#ifdef DEBUG
	char str75[_75];
#endif

	FUNC_CALLED();

	if (!slot->card) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "No card handle");
	}

	lenr = rapdu_len;

	rc = SCardTransmit(slot->card, SCARD_PCI_T1, capdu, capdu_len, NULL, rapdu, &lenr);

#ifdef DEBUG
	debug("SCardTransmit: %s\n", pcsc_error_to_string(rc, str75));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(-1, "SCardTransmit failed");
	}

	FUNC_RETURNS(lenr);
}



int transmitVerifyPinAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
	unsigned char pinblockstring, unsigned char pinlengthformat,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len)
{
	LONG rc;
	DWORD lenr;
	PIN_VERIFY_DIRECT_STRUCTURE_t verify;
#ifdef DEBUG
	 char str75[_75];
#endif

	FUNC_CALLED();

	if (!slot->card) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "No card handle");
	}

	verify.bTimeOut = 0x00;
	verify.bTimeOut2 = 0x00;
	verify.bmFormatString = 0x80 | pinformat;
	verify.bmPINBlockString = pinblockstring;
	verify.bmPINLengthFormat = pinlengthformat;

	verify.wPINMaxExtraDigit = (minpinsize << 8) | maxpinsize;

	/*
	 * Bit 7-3: RFU
	 * Bit   2: Timout occurred
	 * Bit   1: Validation Key pressed
	 * Bit   0: Max size reached
	 */
	verify.bEntryValidationCondition = 0x02;

	verify.bNumberMessage = 0x01;
	verify.wLangID        = 0x0904;
	verify.bMsgIndex      = 0;

	verify.bTeoPrologue[0]= 0;
	verify.bTeoPrologue[1]= 0;
	verify.bTeoPrologue[2]= 0;

	verify.ulDataLength = capdu_len;
	memcpy(verify.abData, capdu, capdu_len);

	lenr = rapdu_len;

	rc = SCardControl(slot->card, slot->hasFeatureVerifyPINDirect, &verify,  18 + capdu_len + 1, rapdu, rapdu_len, &lenr);

#ifdef DEBUG
	debug("SCardControl (VERIFY_PIN_DIRECT): %s\n", pcsc_error_to_string(rc, str75));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(-1, "SCardControl failed");
	}

	FUNC_RETURNS(lenr);
}



/**
 * checkForNewPCSCToken looks into a specific slot for a token.
 *
 * @param slot       Pointer to slot structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>Error opening slot directory           </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
static int checkForNewPCSCToken(struct p11Slot_t *slot)
{
	struct p11Token_t *token;
	int rc, i;
	LONG rv;
	DWORD dwActiveProtocol;
	WORD feature;
	DWORD featurecode, lenr, atrlen, readernamelen, state, protocol;
	unsigned char buf[256];
	unsigned char atr[sizeof(ATRs[0])];
#ifdef DEBUG
	char str75[_75];
#endif

	FUNC_CALLED();

	rv = SCardConnect(slot->context, slot->readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &slot->card, &dwActiveProtocol);

#ifdef DEBUG
	debug("SCardConnect (%i, %s): %s\n", slot->id, slot->readerName, pcsc_error_to_string(rv, str75));
#endif

	switch (rv) {
	case SCARD_S_SUCCESS:
		break;
	case SCARD_E_NO_SMARTCARD:
	case SCARD_W_REMOVED_CARD:
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	default:
		FUNC_FAILS(CKR_DEVICE_ERROR, pcsc_error_to_string(rv, str75));
	}

	readernamelen = 0;
	atrlen = sizeof(atr);

	rc = SCardStatus(slot->card, NULL, &readernamelen, &state, &protocol, atr, &atrlen);

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, pcsc_error_to_string(rc, str75));
	}

	if (atrlen != sizeof(ATRs[0]) ||
		memcmp(atr, ATRs[0], atrlen) != 0 && memcmp(atr, ATRs[1], atrlen) != 0)
	{
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "ATR mismatch.");
	}

	rc = newToken(slot, &token);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "newToken() failed");
	}

	addToken(slot, token);

	if (!slot->hasFeatureVerifyPINDirect) {
		rv = SCardControl(slot->card, SCARD_CTL_CODE(3400), NULL,0, buf, sizeof(buf), &lenr);

#ifdef DEBUG
		debug("SCardControl (CM_IOCTL_GET_FEATURE_REQUEST): %s\n", pcsc_error_to_string(rv, str75));
#endif

		if (rv != SCARD_S_SUCCESS) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "SCardControl failed");
		}

		for (i = 0; i < lenr; i += 6){
			feature = buf[i];
			featurecode = (buf[i + 2] << 24) | (buf[i + 3] << 16) | (buf[i + 4] << 8) | buf[i + 5];
#ifdef DEBUG
			debug("%s - 0x%08X\n", pcsc_feature_to_string(feature, str75), featurecode);
#endif
			if (feature == FEATURE_VERIFY_PIN_DIRECT) {
				slot->hasFeatureVerifyPINDirect = featurecode;
#ifdef DEBUG
				debug("Slot supports feature VERIFY_PIN_DIRECT - setting CKF_PROTECTED_AUTHENTICATION_PATH for token\n");
#endif
				token->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
			}
		}
	}

	FUNC_RETURNS(rc);
}



/**
 * checkForRemovedPCSCToken looks into a specific slot for a removed token.
 *
 * @param slot       Pointer to slot structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>Error opening slot directory           </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
static int checkForRemovedPCSCToken(struct p11Slot_t *slot)
{
	LONG rv;
#ifdef DEBUG
	char str75[_75];
#endif

	FUNC_CALLED();

	if (!slot->card) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	rv = SCardStatus(slot->card, NULL, 0, 0, 0, 0, 0);

#ifdef DEBUG
	debug("SCardStatus: %s\n", pcsc_error_to_string(rv, str75));
#endif

	if (rv == SCARD_S_SUCCESS) {
		FUNC_RETURNS(CKR_OK);
	}

	removeToken(slot);

	switch (rv) {
	case SCARD_W_REMOVED_CARD:
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	case SCARD_E_READER_UNAVAILABLE:
		closeSlot(slot);
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	default:
		closeSlot(slot);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error getting PC/SC card terminal status");
	}

}



int getPCSCToken(struct p11Slot_t *slot, struct p11Token_t **ppToken)
{
	int rc;

	if (slot->token) {
		rc = checkForRemovedPCSCToken(slot);
	} else {
		rc = checkForNewPCSCToken(slot);
	}

	*ppToken = slot->token;
	return rc;
}



int updatePCSCSlots(struct p11SlotPool_t *slotPool)
{
	struct p11Slot_t *slot;
	LPTSTR readers = NULL, reader;
	DWORD cch = SCARD_AUTOALLOCATE;
	LONG rc;
	int match;
	SCARDCONTEXT hContext;
#ifdef DEBUG
	char str75[_75];
#endif

	FUNC_CALLED();

	/*
	 * Keeping a global context causes problems if pcscd is restarted
	 */
	rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);

#ifdef DEBUG
	debug("SCardEstablishContext: %s\n", pcsc_error_to_string(rc, str75));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not establish context to PC/SC manager");
	}

	rc = SCardListReaders(hContext, NULL, (LPTSTR)&readers, &cch);

#ifdef DEBUG
	debug("SCardListReaders: %s\n", pcsc_error_to_string(rc, str75));
#endif

	if (rc != SCARD_S_SUCCESS) {
		SCardReleaseContext(hContext);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error listing PC/SC card terminals");
	}

	/* Determine the total number of readers */	
	for (reader = readers; *reader != '\0'; reader += 1 + strlen(reader)) {
#ifdef DEBUG
		debug("%s\n", reader);
#endif

		/* Check if the already have a slot for the reader */
		match = FALSE;
		FOR_EACH(slot, slotPool->list) {
			if (!slot->closed && strcmp(slot->readerName, reader) == 0) {
				match = TRUE;
				slot->present = TRUE; /* this value is protected by the slot pool mutex */
				break;
			}
		}

		/* Skip the reader as we already have a slot for it */
		if (match) {
			continue;
		}

		slot = (struct p11Slot_t *)calloc(1, sizeof(struct p11Slot_t));

		if (slot == NULL) {
			SCardFreeMemory(hContext, readers);
			SCardReleaseContext(hContext);
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}

		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &slot->context);

#ifdef DEBUG
		debug("SCardEstablishContext: %s\n", pcsc_error_to_string(rc, str75));
#endif

		if (rc != SCARD_S_SUCCESS) {
			free(slot);
			SCardFreeMemory(hContext, readers);
			SCardReleaseContext(hContext);
			FUNC_FAILS(CKR_DEVICE_ERROR, "Cannot establish context to PC/SC manager");
		}

		slot->present = TRUE;
		slot->closed = FALSE;

		strbpcpy(slot->info.slotDescription,
				(char *)reader,
				sizeof(slot->info.slotDescription));

		strcpy(slot->readerName, (char *)reader);

		strbpcpy(slot->info.manufacturerID,
				"CardContact",
				sizeof(slot->info.manufacturerID));

		slot->info.hardwareVersion.minor = 0;
		slot->info.hardwareVersion.major = 0;

		slot->info.firmwareVersion.minor = 0;
		slot->info.firmwareVersion.major = 0;

		slot->info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
		
		addSlot(&context->slotPool, slot);

#ifdef DEBUG
		debug("Added slot (%lu, %s) - slot counter is %i\n", slot->id, slot->readerName, context->slotPool.count);
#endif
	}

	rc = SCardFreeMemory(hContext, readers);

#ifdef DEBUG
	debug("SCardFreeMemory: %s\n", pcsc_error_to_string(rc, str75));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error freeing memory");
	}

	rc = SCardReleaseContext(hContext);

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error release context");
	}

#ifdef DEBUG
	debug("SCardReleaseContext: %s\n", pcsc_error_to_string(rc, str75));
#endif

	FUNC_RETURNS(CKR_OK);
}



int closePCSCSlot(struct p11Slot_t *slot)
{
	LONG rc;
#ifdef DEBUG
	char str75[_75];
#endif

	FUNC_CALLED();

#ifdef DEBUG
	debug("Trying to close slot (%i, %s)\n", slot->id, slot->readerName);
#endif

	if (!slot->card) {
		FUNC_RETURNS(CKR_OK);
	}

	rc = SCardDisconnect(slot->card, SCARD_LEAVE_CARD);
	slot->card = 0;

#ifdef DEBUG
	debug("SCardDisconnect (%i, %s): %s\n", slot->id, slot->readerName, pcsc_error_to_string(rc, str75));
	debug("Releasing slot specific PC/SC context - slot counter is %i\n", context->slotPool.count);
#endif

	rc = SCardReleaseContext(slot->context);
	slot->context = 0;

#ifdef DEBUG
	debug("SCardReleaseContext (%i, %s): %s\n", slot->id, slot->readerName, pcsc_error_to_string(rc, str75));
#endif
	
	FUNC_RETURNS(CKR_OK);
}

#endif /* CTAPI */
