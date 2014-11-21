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
 * @file    p11session.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Session management functions at the PKCS#11 interface
 */

#include <string.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/debug.h>

extern struct p11Context_t *context;



/*  C_OpenSession opens a session between an application and a
    token in a particular slot. */
CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(
		CK_SLOT_ID slotID,
		CK_FLAGS flags,
		CK_VOID_PTR pApplication,
		CK_NOTIFY Notify,
		CK_SESSION_HANDLE_PTR phSession
)
{
	int rv;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	struct p11Session_t *session;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!(flags & CKF_SERIAL_SESSION)) {
		FUNC_FAILS(CKR_SESSION_PARALLEL_NOT_SUPPORTED, "CKF_SERIAL_SESSION not set");
	}

	if (pApplication && !isValidPtr(pApplication)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(phSession)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_AND_LOCK_SLOT(slotID, &slot);

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (!(flags & CKF_RW_SESSION) && (token->userType == CKU_SO)) { /* there is already an active r/w session for SO */
		FUNC_FAILS(CKR_SESSION_READ_WRITE_SO_EXISTS, "Can not open an R/O session if SO is logged in");
	}

	session = (struct p11Session_t *)calloc(1, sizeof(struct p11Session_t));

	if (session == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	session->slotID = slot->id;
	session->flags = flags;
	session->activeObjectHandle = CK_INVALID_HANDLE;

	slot->sessionCount++;
	if (!(flags & CKF_RW_SESSION)) {
		slot->readOnlySessionCount++;
	}

	FUNC_UNLOCK(&slot->mutex);

	safeAddSession(&context->sessionPool, session);
	*phSession = session->handle; /* we got a valid handle by calling addSession() */

	FUNC_RETURNS(CKR_OK);
}



/*  C_CloseSession closes a session between an application and a token. */
CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(
		CK_SESSION_HANDLE hSession
)
{
	struct p11Session_t **ppSession, *session;
	struct p11Slot_t *slot;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_LOCK(&context->sessionPool.mutex);

	session = NULL;
	FOR_EACH_REF(ppSession, context->sessionPool.list) {
		if ((*ppSession)->handle == hSession) {
			session = *ppSession;
			break;
		}
	}

	if (session == NULL) {
		FUNC_RETURNS(CKR_SESSION_HANDLE_INVALID);
	}

	if (session->queuing) {
		/* another thread using this seesion is waiting for the slot mutex */
		FUNC_RETURNS(CKR_FUNCTION_FAILED);
	}

	/* remove seesion from session pool */
	*ppSession = session->next; /* unlink */
	context->sessionPool.count--;

	MUTEX_LOCK(&context->slotPool.mutex);
	FOR_EACH(slot, context->slotPool.list) {
		if (slot->id == session->slotID)
			break;
	}
	MUTEX_UNLOCK(&context->slotPool.mutex);

	/* Now we have exclusive access to the session and can give up the session pool mutex. */
	FUNC_UNLOCK(&context->sessionPool.mutex);

	if (slot == NULL) {
		FUNC_RETURNS(CKR_OK);
	}
	/* Wait for the owning thread and all already queued threads. We must hold the slot mutex
	   because we will update some slot data. */
	FUNC_LOCK(&slot->mutex);

	slot->sessionCount--;
	if (!(session->flags & CKF_RW_SESSION)) {
		slot->readOnlySessionCount--;
	}

	if (slot->sessionCount == 0
		&& slot->token
		&& (slot->token->userType == CKU_USER || slot->token->userType == CKU_SO))
	{
		slot->token->userType = 0xFF;
		logOut(slot);
	}

	freeSession(session);

	FUNC_RETURNS(CKR_OK);
}



/*  C_CloseAllSessions closes all sessions on the specifies slots. */
CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(
		CK_SLOT_ID slotID
)
{
	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	for (;;) {
		CK_SESSION_HANDLE hSession;
		if (safeFindFirstSessionBySlotID(&context->sessionPool, slotID, &hSession) != CKR_OK)
			break;
		C_CloseSession(hSession);
	}

	FUNC_RETURNS(CKR_OK);
}



/*  C_GetSessionInfo obtains information about a session. */
CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(
		CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO_PTR pInfo
)
{
	int rv;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pInfo)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	pInfo->slotID = slot->id;
	pInfo->flags = session->flags;
	pInfo->ulDeviceError = 0;
	pInfo->state = getSessionState(session, slot);

	FUNC_RETURNS(CKR_OK);
}



/*  C_GetOperationState obtains a copy of the cryptographic operations state of a session. */
CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_ULONG_PTR pulOperationStateLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_SetOperationState restores the cryptographic operations state of a session. */
CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_ULONG ulOperationStateLen,
		CK_OBJECT_HANDLE hEncryptionKey,
		CK_OBJECT_HANDLE hAuthenticationKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_Login logs a user into a token. */
CK_DECLARE_FUNCTION(CK_RV, C_Login)(
		CK_SESSION_HANDLE hSession,
		CK_USER_TYPE userType,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen
)
{
	int rv;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (userType != CKU_USER && userType != CKU_SO) {
		FUNC_RETURNS(CKR_USER_TYPE_INVALID);
	}

	if (ulPinLen != 0 && pPin == NULL) {
		FUNC_RETURNS(CKR_ARGUMENTS_BAD);
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (token->userType == CKU_USER || token->userType == CKU_SO) {
		FUNC_RETURNS(CKR_USER_ALREADY_LOGGED_IN);
	}

	if (userType == CKU_USER) {
		if (!(token->info.flags & CKF_USER_PIN_INITIALIZED)) {
			FUNC_RETURNS(CKR_USER_PIN_NOT_INITIALIZED);
		}
	} else { /* CKO_SO || 0xFF */
		if (!(session->flags & CKF_RW_SESSION)) {
			FUNC_RETURNS(CKR_SESSION_READ_ONLY);
		}
		if (slot->readOnlySessionCount) {
			FUNC_RETURNS(CKR_SESSION_READ_ONLY_EXISTS);
		}
	}

	rv = logIn(slot, userType, pPin, ulPinLen);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	token->userType = userType;

	FUNC_RETURNS(CKR_OK);
}



/*  C_Logout logs a user out from a token. */
CK_DECLARE_FUNCTION(CK_RV, C_Logout)(
		CK_SESSION_HANDLE hSession
)
{
	int rv;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (token->userType != CKU_USER && token->userType != CKU_SO) {
		FUNC_RETURNS(CKR_USER_NOT_LOGGED_IN);
	}

	slot->token->userType = 0xFF;

	rv = logOut(slot);

	FUNC_RETURNS(CKR_OK);
}
