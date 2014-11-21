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
 * @file    session.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Data types and functions for session management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <pkcs11/session.h>
#include <common/mutex.h>

/**
 * Initialize the session-pool structure
 *
 * @param pool       Pointer to session-pool structure.
 */
void initSessionPool(struct p11SessionPool_t *sessionPool)
{
	sessionPool->list = NULL;
	sessionPool->nextHandle = 1; /* Set initial value of session handles to 1 */
	                             /* Valid handles have a non-zero value       */
	sessionPool->count = 0;

	MUTEX_INIT(&sessionPool->mutex);
}



/**
 * Terminate the session pool, removing all objects and freeing allocated memory
 *
 * @param pool       Pointer to session-pool structure.
 */
void terminateSessionPool(struct p11SessionPool_t *sessionPool)
{
	struct p11Session_t *session, *next;
	
	FOR_EACH_WITH_NEXT(session, next, sessionPool->list) {
		freeSession(session);
	}

	mutex_destroy(&sessionPool->mutex);
}



/**
 * Add a session to the session-pool
 *
 * This function sets the handle of the session object to a valid value.
 *
 * @param pool      Pointer to session-pool structure
 * @param session   Pointer to session structure
 */
void safeAddSession(struct p11SessionPool_t *sessionPool, struct p11Session_t *session)
{
	struct p11Session_t **ppSession;

	session->next = NULL;
	
	MUTEX_LOCK(&sessionPool->mutex);

	FOR_EACH_REF(ppSession, sessionPool->list) {
		/* until points to the next field of the last element */
	}

	*ppSession = session;

	session->handle = sessionPool->nextHandle++;
	if (sessionPool->nextHandle == 0)
		sessionPool->nextHandle = 1;
	sessionPool->count++;

	MUTEX_UNLOCK(&sessionPool->mutex);
}



/**
 * This thread safe function must be called before operating on a session.
 * Finds the session pointer for the passed session handle, acquires the session and
 * acquires the slot mutex. If the function succeeds the caller must release
 * the slot mutex. For convenience the function should be called via the
 * FUNC_FIND_SESSION_AND_LOCK_SLOT(handle, &session) and afterwards use strictly FUNC_RETURNS
 * or FUNC_FAILS instead of return.
 *
 * @param sessionPool  Pointer to session-pool structure.
 * @param handle       The handle of the session.
 * @param ppSession    Pointer to a session structure pointer.
 *                     If the session is found, it is returned in this pointer.
 * @return CKR_OK or CKR_SESSION_HANDLE_INVALID or CKR_OPERATION_ACTIVE
 */
int safeFindSessionAndLockSlot(struct p11SessionPool_t *sessionPool, struct p11SlotPool_t *slotPool,
	CK_SESSION_HANDLE handle, struct p11Session_t **ppSession, struct p11Slot_t **ppSlot)
{
	struct p11Session_t *session;
	struct p11Slot_t *slot;

	*ppSession = NULL;
	*ppSlot = NULL;

	if (handle == CK_INVALID_HANDLE) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* lookup session */
	MUTEX_LOCK(&sessionPool->mutex);
	FOR_EACH(session, sessionPool->list) {
		if (session->handle == handle) {
			/* prevent deletion of session */
			InterlockedIncrement(&session->queuing);
			break;
		}
	}
	MUTEX_UNLOCK(&sessionPool->mutex);
	if (session == NULL) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* lookup slot */
	MUTEX_LOCK(&slotPool->mutex);
	FOR_EACH(slot, slotPool->list) {
		if (slot->id == session->slotID) {
			/* prevent deletion of slot */
			InterlockedIncrement(&slot->queuing);
			break;
		}
	}
	MUTEX_UNLOCK(&slotPool->mutex);
	if (slot == NULL) {
		InterlockedDecrement(&session->queuing);
		return CKR_DEVICE_REMOVED;
	}
	if (slot->closed) {
		InterlockedDecrement(&slot->queuing);
		InterlockedDecrement(&session->queuing);
		return CKR_DEVICE_REMOVED;
	}

	/* Unprotected area here. We must ensure that the session and slot pointer is still valid after
	   obtaining the slot mutex. This is handled by incrementing session->queuing while
	   holding the session pool mutex, and decrement after possessing the slot mutex.
	   The deletion function must check session->queuing when holding the session pool mutex
	   and unlink the session immediately. If session->queuing > 0 deletion must be cancelled.
	   Otherwise another thread could get a session pointer which points to freed memory.
	   Same applies to the slot.
	   Acquire the slot mutex while owning the slot pool mutex is a performace killer. */

	/* Acquire the slot mutex */
	MUTEX_LOCK(&slot->mutex);

	InterlockedDecrement(&slot->queuing);
	InterlockedDecrement(&session->queuing);

	if (slot->token == NULL) {
		MUTEX_UNLOCK(&slot->mutex);
		return CKR_TOKEN_NOT_PRESENT;
	}

	*ppSession = session;
	*ppSlot = slot;

	return CKR_OK;
}



/**
 * Find a slot in the slot-pool by it's related slot
 *
 * @param pool       Pointer to slot-pool structure
 * @param slotID     The slot identifier
 * @param ppSession  Pointer to a session structure pointer.
 *                   If the session is found, this pointer holds the specific session structure - otherwise NULL.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>>=0                                    </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>-1                                     </TD>
 *                   <TD>The specified session was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int safeFindFirstSessionBySlotID(struct p11SessionPool_t *sessionPool, CK_SLOT_ID slotID, CK_SESSION_HANDLE *phSession)
{
	struct p11Session_t *session;

	MUTEX_LOCK(&sessionPool->mutex);

	FOR_EACH(session, sessionPool->list) {
		if (session->slotID == slotID) {
			MUTEX_UNLOCK(&sessionPool->mutex);
			*phSession = session->handle;
			return CKR_OK;
		}
	}

	MUTEX_UNLOCK(&sessionPool->mutex);

	*phSession = CK_INVALID_HANDLE;
	return CKR_FUNCTION_FAILED;
}



void freeSession(struct p11Session_t *session)
{
	clearSearchList(session);

	while (session->objectList) {
		if (removeSessionObject(session, session->objectList->handle) != CKR_OK) {
			assert(0);
			return;
		}
	}

	if (session->cryptoBuffer) {
		free(session->cryptoBuffer);
		session->cryptoBuffer = NULL;
		session->cryptoBufferMax = 0;
		session->cryptoBufferSize = 0;
	}

	free(session);
}



/**
 * Return the current session state
 *
 * @param session    the session
 * @param token      the token this session is bound to (prevent duplicate slot lookup)
 * @return One of the CK_STATE values
 */
CK_STATE getSessionState(struct p11Session_t *session, struct p11Slot_t *slot)
{
	CK_STATE state;

	switch (slot->token->userType) {
	case CKU_USER:
		state = (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
		break;

	case CKU_SO:
		state = CKS_RW_SO_FUNCTIONS;
		break;

	default:
		state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
		break;
	}
	return state;
}



/**
 * Add an object to the list of session objects
 *
 * @param session   the session
 * @param object    the object to add
 */
void addSessionObject(struct p11Session_t *session, struct p11Object_t *object)
{
	if (session->nextSessionObjHandle == 0) {
		session->nextSessionObjHandle = 0xA000;
	}

	object->handle = session->nextSessionObjHandle++;
	object->dirtyFlag = 0;

	addObjectToList(&session->objectList, object);

	session->objectCount++;
}



/**
 * Find a session object by it's handle
 */
int findSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle, struct p11Object_t **ppObject)
{
	struct p11Object_t *object;
	int pos;  /* remember the current position in the list */

	pos = 0;
	FOR_EACH(object, session->objectList) {
		if (object->handle == handle) {
			*ppObject = object;
			return pos;
		}
		pos++;
	}

	*ppObject = NULL;
	return -1;
}



/**
 * Remove a session object
 */
int removeSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle)
{
	int rc;

	rc = removeObjectFromList(&session->objectList, handle);

	if (rc != CKR_OK)
		return rc;

	session->objectCount--;

	return CKR_OK;
}



/**
 * Add an object to the search list by make a shallow copy of the object
 */
int addObjectToSearchList(struct p11Session_t *session, struct p11Object_t *object)
{
	struct p11Object_t **ppObject;
	struct p11Object_t *pNewObject;

	pNewObject = (struct p11Object_t *)calloc(1, sizeof(struct p11Object_t));

	if (pNewObject == NULL) {
		return CKR_HOST_MEMORY;
	}

	*pNewObject = *object;
	pNewObject->next = NULL;

	FOR_EACH_REF(ppObject, session->searchObj.searchList) {
		/* until points to the next field of the last element */
	}

	*ppObject = pNewObject;
	session->searchObj.objectCount++;

	return CKR_OK;
}



/**
 * Clear the search results list
 */
void clearSearchList(struct p11Session_t *session)
{
	struct p11Object_t *object, *pNext;

	// Objects on the search list are not a deep copy of the actual object
	// thats why we don't use removeAllObjectsFromList() here
	FOR_EACH_WITH_NEXT(object, pNext, session->searchObj.searchList) {
		free(object);
	}

	session->searchObj.objectCount = 0;
	session->searchObj.objectCollected = 0;
	session->searchObj.searchList = NULL;
}



/**
 * Append data to an internal buffer for token that don not implement an update() function
 *
 * @param session   the session
 * @param data      the data to be added
 * @param length    length of the data to be added
 * @return CKR_OK or CKR_HOST_MEMORY
 */
int appendToCryptoBuffer(struct p11Session_t *session, CK_BYTE_PTR data, CK_ULONG length)
{
	CK_ULONG newSize = session->cryptoBufferSize + length;

	if (session->cryptoBufferMax < newSize) {
		if (session->cryptoBufferMax == 0) {
			session->cryptoBufferMax = 256;
		}

		while (session->cryptoBufferMax < newSize) {
			session->cryptoBufferMax *= 2; /* compiler does the << 1 */
		}

		session->cryptoBuffer = (CK_BYTE_PTR)realloc(session->cryptoBuffer, session->cryptoBufferMax);
		if (session->cryptoBuffer == NULL) {
			session->cryptoBufferMax = 0;
			return CKR_HOST_MEMORY;
		}
	}

	memcpy(session->cryptoBuffer + session->cryptoBufferSize, data, length);
	session->cryptoBufferSize += length;

	return CKR_OK;
}



/**
 * Clear crypto buffer used to collect input data
 *
 * @param session   the session
 */
void clearCryptoBuffer(struct p11Session_t *session)
{
	if (session->cryptoBuffer) {
		memset(session->cryptoBuffer, 0, session->cryptoBufferMax);
		session->cryptoBufferSize = 0;
	}
}
