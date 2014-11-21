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
 * @file    slot.c
 * @author  Frank Thater
 * @brief   Slot implementation dispatching for PC/SC or CT-API reader
 */

#include <string.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#ifdef CTAPI
#include "slot-ctapi.h"
#else
#include "slot-pcsc.h"
#endif

/**
 * addToken adds a token to the specified slot.
 *
 * @param slot      Pointer to slot structure.
 * @param token     Pointer to token structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is already a token in the slot   </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
void addToken(struct p11Slot_t *slot, struct p11Token_t *token)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	assert(!slot->token && token);

	slot->token = token;                    /* Add token to slot                */
	slot->info.flags |= CKF_TOKEN_PRESENT;  /* indicate the presence of a token */
}



/**
 * removeToken removes a token from the specified slot.
 *
 * @param slot      Pointer to slot structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is no token in the slot          </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int removeToken(struct p11Slot_t *slot)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	if (slot->token == NULL) {
		return CKR_FUNCTION_FAILED;
	}

	slot->info.flags &= ~CKF_TOKEN_PRESENT;

	freeToken(slot);

	return CKR_TOKEN_NOT_PRESENT;
}



/**
 * Encode APDU using either short or extended notation
 *
 * @param CLA the instruction class
 * @param INS the instruction code
 * @param P1 the first parameter
 * @param P2 the second parameter
 * @param Nc number of outgoing bytes
 * @param OutData outgoing command data
 * @param Ne number of bytes expected from card,
 *           -1 for none,
 *           0 for all in short mode,
 *           > 255 in extended mode,
 *           >= 65536 all in extended mode
 * @param apdu buffer receiving the encoded APDU
 * @param apdu_len length of provided buffer
 * @return -1 for error or the length of the encoded APDU otherwise
 */
int encodeCommandAPDU(
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		size_t Nc, unsigned char *OutData, int Ne,
		unsigned char *apdu, size_t apdu_len)
{
	unsigned char *po;

	FUNC_CALLED();

	if (apdu == NULL)
		FUNC_FAILS(-1, "Output buffer not defined");

	if (Nc + 9 > apdu_len)
		FUNC_FAILS(-1, "Nc larger than output buffer");

	if (Nc && (OutData == NULL))
		FUNC_FAILS(-1, "OutData not defined for Nc > 0");

	apdu[0] = CLA;
	apdu[1] = INS;
	apdu[2] = P1;
	apdu[3] = P2;
	po = apdu + 4;

	if (OutData && Nc) {
		if ((Nc <= 255) && (Ne <= 255)) {		// Case 3s or 4s
			*po++ = (unsigned char)Nc;
		} else {
			*po++ = 0;							// Case 3e or 3e
			*po++ = (unsigned char)(Nc >> 8);
			*po++ = (unsigned char)(Nc & 0xFF);
		}
		memcpy(po, OutData, Nc);
		po += Nc;
	}

	if (Ne >= 0) {								// Case 2 or 4
		if ((Ne <= 255) && (Nc <= 255)) {		// Case 2s or 4s
			*po++ = (unsigned char)Ne;
		} else {
			if (Ne >= 65536)					// Request all for extended APDU
				Ne = 0;

			if (!OutData)						// Case 4e
				*po++ = 0;

			*po++ = (unsigned char)(Ne >> 8);
			*po++ = (unsigned char)(Ne & 0xFF);
		}
	}

	FUNC_RETURNS((CK_RV)(po - apdu));
}



/*
 *  Process an ISO 7816 APDU with the underlying terminal hardware.
 *
 *  CLA     : Class byte of instruction
 *  INS     : Instruction byte
 *  P1      : Parameter P1
 *  P2      : Parameter P2
 *  OutLen  : Length of outgoing data (Lc)
 *  OutData : Outgoing data or NULL if none
 *  InLen   : Length of incoming data (Le)
 *  InData  : Input buffer for incoming data
 *  InSize  : buffer size
 *  SW1SW2  : Address of short integer to receive SW1SW2
 *
 *  Returns : < 0 Error > 0 Bytes read
 */
int transmitAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)
{
	int rc;
	unsigned char apdu[4098];
#ifdef DEBUG
	char scr[4196], *po;
#endif

	FUNC_CALLED();

	VERIFY_MUTEXOWNER(&slot->mutex);

#ifdef DEBUG

	sprintf(scr, "C-APDU: %02X %02X %02X %02X ", CLA, INS, P1, P2);
	po = strchr(scr, '\0');

	if (INS != 0x20 && OutLen && OutData) {
		sprintf(po, "Lc=%02X(%d) ", OutLen, OutLen);
		po = strchr(scr, '\0');
		if (OutLen > 2048) {
			decodeBCDString(OutData, 2048, po);
			strcat(po, "..");
		} else {
			decodeBCDString(OutData, OutLen, po);
		}
		po = strchr(scr, '\0');
		strcpy(po, " ");
		po++;
	}

	if (InData && InSize)
		sprintf(po, "Le=%02X(%d)", InLen, InLen);

	debug("%s\n", scr);
#endif

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			OutLen, OutData, InData ? InLen : -1,
			apdu, sizeof(apdu));

	if (rc < 0)
		FUNC_FAILS(rc, "Encoding APDU failed");

#ifdef CTAPI
	rc = transmitAPDUviaCTAPI(slot, 0,
			apdu, rc,
			apdu, sizeof(apdu));
#else
	rc = transmitAPDUviaPCSC(slot,
			apdu, rc,
			apdu, sizeof(apdu));
#endif

	if (rc >= 2) {
		*SW1SW2 = (apdu[rc - 2] << 8) | apdu[rc - 1];
		rc -= 2;

		if (InData && InSize) {
			if (rc > InSize) {		// Never return more than caller allocated a buffer for
				rc = InSize;
			}
			memcpy(InData, apdu, rc);
		}
	} else {
		rc = -1;
	}

#ifdef DEBUG
	if (rc > 0) {
		sprintf(scr, "R-APDU: Lr=%02X(%d) ", rc, rc);
		po = strchr(scr, '\0');
		if (rc > 2048) {
			decodeBCDString(InData, 2048, po);
			strcat(scr, "..");
		} else if (InData) {
			decodeBCDString(InData, rc, po);
		}

		po = strchr(scr, '\0');
		sprintf(po, " SW1/SW2=%04X", *SW1SW2);
	} else
		sprintf(scr, "R-APDU: rc=%d SW1/SW2=%04X", rc, *SW1SW2);

	debug("%s\n", scr);
#endif
	return rc;
}



int transmitVerifyPinAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2, unsigned short *SW1SW2,
		unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
		unsigned char pinblockstring, unsigned char pinlengthformat)
{
	int rc;
	unsigned char apdu[4098];
#ifdef DEBUG
	char scr[4196], *po;
#endif

	FUNC_CALLED();

	VERIFY_MUTEXOWNER(&slot->mutex);

#ifdef DEBUG

	sprintf(scr, "C-APDU: %02X %02X %02X %02X ", CLA, INS, P1, P2);
	po = strchr(scr, '\0');

	debug("%s\n", scr);
#endif

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			0, NULL, -1,
			apdu, sizeof(apdu));

	if (rc < 0)
		FUNC_FAILS(rc, "Encoding APDU failed");

#ifdef CTAPI
	/*
	 * Not implemented yet
	 */
	rc = -1;

#else
	rc = transmitVerifyPinAPDUviaPCSC(slot,
			pinformat, minpinsize, maxpinsize,
			pinblockstring, pinlengthformat,
			apdu, rc,
			apdu, sizeof(apdu));
#endif

	if (rc >= 2) {
		*SW1SW2 = (apdu[rc - 2] << 8) | apdu[rc - 1];
		rc -= 2;
	}

#ifdef DEBUG
	sprintf(scr, "R-APDU: rc=%d SW1/SW2=%04X", rc, *SW1SW2);
	debug("%s\n", scr);
#endif
	return rc;
}



/**
 * safeFindAndLockSlot finds a slot in the slot-pool.
 * The slot is specified by its slotID.
 *
 * @param pool       Pointer to slot-pool structure.
 * @param slotID     The id of the slot.
 * @param slot       Pointer to pointer to slot structure.
 *                   If the slot is found, this pointer holds the specific slot structure - otherwise NULL.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>>CKR_OK                             </TD>
 *                   <TD>Success                             </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_SLOT_ID_INVALID                 </TD>
 *                   <TD>The specified slot was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int safeFindAndLockSlot(struct p11SlotPool_t *slotPool, CK_SLOT_ID slotID, struct p11Slot_t **ppSlot)
{
	int rc = CKR_SLOT_ID_INVALID;
	struct p11Slot_t *slot;

	FUNC_CALLED();

	MUTEX_LOCK(&slotPool->mutex);

	FOR_EACH(slot, slotPool->list) {
		VERIFY_NOT_MUTEXOWNER(&slot->mutex);
		if (slot->id == slotID) {
			if (slot->closed) {
				rc = CKR_DEVICE_ERROR;
				break;
			}
			*ppSlot = slot;
			/* prevent deletion of slot */
			InterlockedIncrement(&slot->queuing);
			MUTEX_UNLOCK(&slotPool->mutex);
			/* Unprotected area here. We must ensure that the slot pointer is still valid after
			   obtaining the slot mutex. This is handled by incrementing slot->queuing while
			   holding the slot pool mutex, and decrement after possessing the slot mutex.
			   The delete function must check slot->queuing when holding the slot pool mutex
			   and unlink the slot immediately. If slot->queuing > 0 deletion must be cancelled.
			   Otherwise another thread could get a slot pointer which points to freed memory.
			   Acquire the slot mutex while owning the slot pool mutex is a performace killer. */
			MUTEX_LOCK(&slot->mutex);
			InterlockedDecrement(&slot->queuing);
			FUNC_RETURNS(CKR_OK);
		}
	}

	MUTEX_UNLOCK(&slotPool->mutex);

	*ppSlot = NULL;
	FUNC_RETURNS(rc);
}



int getToken(struct p11Slot_t *slot, struct p11Token_t **ppToken)
{
	int rc;
	FUNC_CALLED();

	if (slot->closed) {
		return CKR_DEVICE_REMOVED;
	}

	VERIFY_MUTEXOWNER(&slot->mutex);

#ifdef CTAPI
	rc = getCTAPIToken(slot, ppToken);
#else
	rc = getPCSCToken(slot, ppToken);
#endif

	return rc;
}



/* caller must own slot->mutex */
int findSlotObject(struct p11Slot_t *slot, CK_OBJECT_HANDLE handle, struct p11Object_t **ppObject, int publicObject)
{
	int rc;
	struct p11Token_t *token;

	VERIFY_MUTEXOWNER(&slot->mutex);

	rc = getToken(slot, &token);
	if (rc != CKR_OK) {
		return rc;
	}

	rc = findTokenObject(token, handle, ppObject, publicObject);

	if (rc < 0) {
		return CKR_GENERAL_ERROR;
	}
	return CKR_OK;
}



int safeUpdateSlots(struct p11SlotPool_t *slotPool)
{
	static int BUSY;
	int wasBusy;
	int rc = CKR_OK;
	struct p11Slot_t *slot, **ppSlot;

	FUNC_CALLED();

	wasBusy = BUSY;
	MUTEX_LOCK(&slotPool->mutex);

	/* skip if another thread did the job while waiting */
	if (!wasBusy) {
		BUSY = 1;

		/* mark all slots for remove, updateXXXXSlots updates the values.
		   We need the flags remove and removed because remove is set here for all slots */
		FOR_EACH(slot, slotPool->list) {
			slot->present = FALSE;
		}
#ifdef CTAPI
		rc = updateCTAPISlots(slotPool);
#else
		rc = updatePCSCSlots(slotPool);
#endif
		/* check for slot removal, can't use FOR_EACH here */
		for (ppSlot = &slotPool->list; *ppSlot; ) {
			slot = *ppSlot; /* for convenience */
			if (!slot->present) {
				slot->closed = TRUE;
				MUTEX_LOCK(&slot->mutex);
				if (slot->queuing) {
					/* at least one thread is queued on the slot mutex */
					MUTEX_UNLOCK(&slot->mutex);
					continue;
				}
				freeToken(slot);
				MUTEX_UNLOCK(&slot->mutex);
				MUTEX_DESTROY(&slot->mutex);
				*ppSlot = slot->next; /* unlink */
				slotPool->count--;
				free(slot);
				continue;
			}
			ppSlot = &slot->next;
		}
		BUSY = 0;
	}

	MUTEX_UNLOCK(&slotPool->mutex);

	FUNC_RETURNS(rc);
}



int closeSlot(struct p11Slot_t *slot)
{
	int rc;

	FUNC_CALLED();

	VERIFY_MUTEXOWNER(&slot->mutex);

	slot->closed = TRUE;

#ifdef CTAPI
	rc = closeCTAPISlot(slot);
#else
	rc = closePCSCSlot(slot);
#endif

	FUNC_RETURNS(rc);
}
