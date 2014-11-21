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
 * @file    token.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for token authentication and token management
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pkcs11/strbpcpy.h>

#include <pkcs11/token.h>
#include <pkcs11/object.h>
#include <pkcs11/dataobject.h>

#include <pkcs11/token-sc-hsm.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif



/**
 * Add token object to list of public or private objects
 *
 * @param token    The token for which an object shell be added
 * @param object   The object
 * @param publicObject true to add as public object, false to add as private object
 *
 * @return          0 or -1 if error
 */
int addTokenObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject)
{
	VERIFY_MUTEXOWNER(&token->slot->mutex);

	object->token = token;

	if (!object->handle) {
		object->handle = token->nextObjectHandle++;
		if (token->nextObjectHandle == 0)
			token->nextObjectHandle = 1;
	}

	if (publicObject) {
		addObjectToList(&token->pubObjectList, object);
		token->pubObjectCount++;
	} else {
		addObjectToList(&token->privObjectList, object);
		token->privObjectCount++;
	}

	object->dirtyFlag = 1;

	return CKR_OK;
}



/**
 * Find public or private object in list of token objects
 *
 * @param token     The token whose object shall be removed
 * @param handle    The objects handle
 */
int findTokenObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **ppObject, int publicObject)
{
	struct p11Object_t *object;
	int pos;

	VERIFY_MUTEXOWNER(&token->slot->mutex);

	pos = 0;
	FOR_EACH(object, publicObject ? token->pubObjectList : token->privObjectList) {
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
 * Remove object from list of token objects
 *
 * @param token     The token whose object shall be removed
 * @param handle    The objects handle
 * @param publicObject true to remove public object, false to remove private object
 *
 * @return          0 or -1 if error
 */
int removeTokenObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)
{
	VERIFY_MUTEXOWNER(&token->slot->mutex);

	if (publicObject) {
		int rc = removeObjectFromList(&token->pubObjectList, handle);
		if (rc != CKR_OK)
			return rc;
		token->pubObjectCount--;
	} else {
		int rc = removeObjectFromList(&token->privObjectList, handle);
		if (rc != CKR_OK)
			return rc;
		token->privObjectCount--;
	}

	return CKR_OK;
}



/**
 * Remove all private objects for token from internal list
 *
 * @param token     The token whose objects shall be removed
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
static void removePrivateObjects(struct p11Token_t *token)
{
	VERIFY_MUTEXOWNER(&token->slot->mutex);

	removeAllObjectsFromList(&token->privObjectList);
	token->privObjectCount = 0;
}



/**
 * Remove all public objects for token from internal list
 *
 * @param token     The token whose objects shall be removed
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
static void removePublicObjects(struct p11Token_t *token)
{
	VERIFY_MUTEXOWNER(&token->slot->mutex);

	removeAllObjectsFromList(&token->pubObjectList);
	token->pubObjectCount = 0;
}



/**
 * Remove object from token but keep attributes as these are transfered into a new object
 */
int removeTokenObjectLeavingAttributes(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)
{
	struct p11Object_t *object;
	struct p11Object_t **ppObject;

	VERIFY_MUTEXOWNER(&token->slot->mutex);

	FOR_EACH_REF(ppObject, *(publicObject ? &token->pubObjectList : &token->privObjectList)) {
		if ((*ppObject)->handle == handle) {
			object = *ppObject;
			*ppObject = object->next;
			free(object);
			token->pubObjectCount--;
			return CKR_OK;
		}
	}

	return CKR_OBJECT_HANDLE_INVALID;
}



/**
 * Remove object from token
 *
 * @param slot      The slot in which the token is inserted
 * @param token     The token to update
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int destroyObject(struct p11Slot_t *slot, struct p11Object_t *pOobject)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	return CKR_OK;
}



/**
 * Synchronize a token objects that have been changed (e.g. have the dirty flag set)
 *
 * @param slot      The slot in which the token is inserted
 * @param token     The token to update
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int synchronizeToken(struct p11Slot_t *slot)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	return CKR_OK;
}



/**
 * Log into token
 *
 * This token method is called from the C_Login function at the PKCS#11 interface and
 * make all private objects visible at the PKCS#11 interface
 *
 * @param slot      The slot in which the token is inserted
 * @param userType  One of CKU_SO or CKU_USER
 * @param pPin      Pointer to PIN value or NULL is PIN shall be verified using PIN-Pad
 * @param ulPinLen  The length of the PIN supplied in pPin
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int logIn(struct p11Slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	return sc_hsm_login(slot, userType, pPin, ulPinLen);
}



/**
 * Log out from token, removing private objects from the list of visible token objects
 *
 * This token method is called from the C_Logout function at the PKCS#11 interface
 *
 * @param slot      The slot in which the token is inserted
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int logOut(struct p11Slot_t *slot)
{
	VERIFY_MUTEXOWNER(&slot->mutex);
	removePrivateObjects(slot->token);
	return sc_hsm_logout(slot);
}



/**
 * Detect a newly inserted token in the designated slot
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
int newToken(struct p11Slot_t *slot, struct p11Token_t **ppToken)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	return newSmartCardHSMToken(slot, ppToken);
}



/**
 * Release allow memory allocated for token
 *
 * @param slot      The slot in which the token is inserted
 */
void freeToken(struct p11Slot_t *slot)
{
	VERIFY_MUTEXOWNER(&slot->mutex);

	if (slot->token) {
		removePrivateObjects(slot->token);
		removePublicObjects(slot->token);
		free(slot->token);
		slot->token = NULL;
	}
}
