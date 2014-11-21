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
 * @file    p11objects.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Object management functions at the PKCS#11 interface
 */


#include <string.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/token.h>
#include <pkcs11/dataobject.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

extern struct p11Context_t *context;



/*  C_CreateObject creates a new object. */
CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phObject
)
{
	int rv = 0;
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	int pos;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(phObject)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	object = (struct p11Object_t *)calloc(1, sizeof(struct p11Object_t));

	if (object == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	pos = findAttributeInTemplate(CKA_CLASS, pTemplate, ulCount);

	if (pos < 0) {
		free(object);
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_CLASS not found in template");
	}

	if (!isValidPtr(pTemplate[pos].pValue) || pTemplate[pos].ulValueLen != sizeof(CK_LONG)) {
		free(object);
		FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_CLASS has invalid value");
	}

	switch (*(CK_LONG *)pTemplate[pos].pValue) {
	case CKO_DATA:
		rv = createDataObject(pTemplate, ulCount, object);
		break;

	default:
		rv = CKR_FUNCTION_FAILED;
		break;
	}

	if (rv != CKR_OK) {
		free(object);
		FUNC_RETURNS(rv);
	}

	/* Check if this is a session or a token object */

	FUNC_LOCK(&slot->mutex);

	if (slot->token == NULL) {
		free(object);
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	/* Token object */
	if (getSessionState(session, slot) == CKS_RW_USER_FUNCTIONS && object->tokenObj) {
		addTokenObject(slot->token, object, object->publicObj);

		rv = synchronizeToken(slot);

		if (rv != CKR_OK) {
			removeTokenObject(slot->token, object->handle, object->publicObj);
			FUNC_RETURNS(rv);
		}
	} else {
		if (object->tokenObj) {
			removeAllAttributes(object);
			free(object);
			FUNC_FAILS(CKR_SESSION_READ_ONLY, "Can not create token objects in read only session");
		}

		addSessionObject(session, object);
	}

	*phObject = object->handle;

	FUNC_RETURNS(rv);
}



/*  C_CopyObject copies an object. */
CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phNewObject
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DestroyObject destroys an object. */
CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject
)
{
	int rv;
	struct p11Session_t *session = NULL;
	struct p11Slot_t *slot;
	struct p11Object_t *object = NULL;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (slot->token == NULL) {
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	rv = findSessionObject(session, hObject, &object);

	if (rv < 0) {

		rv = findTokenObject(slot->token, hObject, &object, TRUE);

		if (rv < 0) {
			if (getSessionState(session, slot) == CKS_RW_USER_FUNCTIONS) {
				rv = findTokenObject(slot->token, hObject, &object, FALSE);
				if (rv < 0) {
					FUNC_RETURNS(CKR_OBJECT_HANDLE_INVALID);
				}
			} else {
				FUNC_RETURNS(CKR_OBJECT_HANDLE_INVALID);
			}
		}

		/* remove the object from the storage media */
		destroyObject(slot, object);

		/* remove the object from the list */
		removeTokenObject(slot->token, hObject, object->publicObj);

		rv = synchronizeToken(slot);

		if (rv < 0) {
			FUNC_RETURNS(CKR_FUNCTION_FAILED);
		}
	} else {
		removeSessionObject(session, hObject);
	}

	FUNC_RETURNS(CKR_OK);
}



/*  C_GetObjectSize gets the size of an object. */
CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ULONG_PTR pulSize
)
{
	int rv;
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	unsigned int size;
	unsigned char *tmp;
	CK_STATE state;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pulSize)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (slot->token == NULL) {
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	rv = findSessionObject(session, hObject, &object);

	if (rv < 0) {

		rv = findTokenObject(slot->token, hObject, &object, TRUE);
		
		if (rv < 0) {
			state = getSessionState(session, slot);
			if (state == CKS_RW_USER_FUNCTIONS || state == CKS_RO_USER_FUNCTIONS) {
				rv = findTokenObject(slot->token, hObject, &object, FALSE);
				if (rv < 0) {
					FUNC_RETURNS(CKR_OBJECT_HANDLE_INVALID);
				}
			} else {
				FUNC_RETURNS(CKR_OBJECT_HANDLE_INVALID);
			}
		}
	}

	serializeObject(object, &tmp, &size);
	free(tmp);

	*pulSize = size;

	FUNC_RETURNS(CKR_OK);
}



/*  C_GetAttributeValue obtains the value of one or more attributes of an object. */
CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount
)
{
	int rv;
	CK_ULONG i;
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Attribute_t *attribute;
	CK_STATE state;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (slot->token == NULL) {
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	rv = findSessionObject(session, hObject, &object);

	if (rv < 0) {

		rv = findTokenObject(slot->token, hObject, &object, TRUE);

		if (rv < 0) {
			state = getSessionState(session, slot);
			if (state == CKS_RW_USER_FUNCTIONS || state == CKS_RO_USER_FUNCTIONS) {
				rv = findTokenObject(slot->token, hObject, &object, FALSE);

				if (rv < 0) {
					FUNC_FAILS(CKR_OBJECT_HANDLE_INVALID, "Private token object not found with handle");
				}
			} else {
				FUNC_FAILS(CKR_OBJECT_HANDLE_INVALID, "Public token object not found with handle");
			}
		}
	}

#ifdef DEBUG
	debug("[C_GetAttributeValue] Trying to get %u attributes ...\n", ulCount);
#endif

	rv = CKR_OK;

	for (i = 0; i < ulCount; i++) {

		FOR_EACH(attribute, object->attrList) {
			if (attribute->attrData.type == pTemplate[i].type)
				break;
		}

		if (!attribute) {
			pTemplate[i].ulValueLen = (CK_LONG) -1;
			rv = CKR_ATTRIBUTE_TYPE_INVALID;
			continue;
		}

		if (attribute->attrData.type == CKA_VALUE && object->sensitiveObj) {
			pTemplate[i].ulValueLen = (CK_LONG) -1;
			rv = CKR_ATTRIBUTE_SENSITIVE;
			continue;
		}

		if (pTemplate[i].pValue == NULL_PTR) {
			pTemplate[i].ulValueLen = attribute->attrData.ulValueLen;
			continue;
		}

		if (pTemplate[i].ulValueLen >= attribute->attrData.ulValueLen) {
			memcpy(pTemplate[i].pValue, attribute->attrData.pValue, attribute->attrData.ulValueLen);
			pTemplate[i].ulValueLen = attribute->attrData.ulValueLen;
		} else {
			pTemplate[i].ulValueLen = attribute->attrData.ulValueLen;
			rv = CKR_BUFFER_TOO_SMALL;
		}
	}

	FUNC_RETURNS(rv);
}



/*  C_SetAttributeValue modifies the value of one or more attributes of an object. */
CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount
)
{
	int rv;
	CK_ULONG i;
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Attribute_t *attribute;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (slot->token == NULL) {
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	rv = findSessionObject(session, hObject, &object);

	/* only session objects can be modified without user authentication */

	if (rv < 0) {
		if (getSessionState(session, slot) != CKS_RW_USER_FUNCTIONS) {
			FUNC_FAILS(CKR_OBJECT_HANDLE_INVALID, "Object not found as session object");
		}

		/* public token objects */
		rv = findTokenObject(slot->token, hObject, &object, TRUE);

		if (rv < 0) {
			/* private token objects */
			rv = findTokenObject(slot->token, hObject, &object, FALSE);

			if (rv < 0) {
				FUNC_FAILS(CKR_OBJECT_HANDLE_INVALID, "Object not found as token object");
			}
		}
	}

	for (i = 0; i < ulCount; i++) {

		FOR_EACH(attribute, object->attrList) {
			if (attribute->attrData.type == pTemplate[i].type)
				break;
		}

		if (!attribute) {
			FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "We do not allow manufacturer specific attributes");
		}

		/* Check if the value of CKA_PRIVATE changes */
		if (pTemplate[i].type == CKA_PRIVATE) {
			/* changed from TRUE to FALSE */
			if (*(CK_BBOOL *)pTemplate[i].pValue == CK_FALSE && *(CK_BBOOL *)attribute->attrData.pValue == CK_TRUE) {
				FUNC_RETURNS(CKR_TEMPLATE_INCONSISTENT);
			}

			/* changed from FALSE to TRUE */
			if (*(CK_BBOOL *)pTemplate[i].pValue == CK_TRUE && *(CK_BBOOL *)attribute->attrData.pValue == CK_FALSE) {
				struct p11Object_t *newobject;

				memcpy(attribute->attrData.pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);

				newobject = (struct p11Object_t *)calloc(1, sizeof(struct p11Object_t));
				if (newobject == NULL) {
					FUNC_FAILS(CKR_HOST_MEMORY,"Out of memory");
				}

				*newobject = *object;
				newobject->next = NULL;
				newobject->publicObj = FALSE;
				newobject->dirtyFlag = 1;

				/* remove the public object */
				destroyObject(slot, object);
				removeTokenObjectLeavingAttributes(slot->token, object->handle, TRUE);

				/* insert new private object */
				addTokenObject(slot->token, newobject, FALSE);

				rv = synchronizeToken(slot);

				if (rv < 0) {
					FUNC_RETURNS(rv);
				}
			}
		} else {
			if (pTemplate[i].ulValueLen > attribute->attrData.ulValueLen) {
				free(attribute->attrData.pValue);
				attribute->attrData.pValue = malloc(pTemplate[i].ulValueLen);
			}

			attribute->attrData.ulValueLen = pTemplate[i].ulValueLen;
			memcpy(attribute->attrData.pValue, pTemplate[i].pValue, pTemplate[i].ulValueLen);

			object->dirtyFlag = 1;

			rv = synchronizeToken(slot);

			if (rv < 0) {
				FUNC_RETURNS(rv);
			}
		}
	}

	FUNC_RETURNS(rv);
}



static int isMatchingObject(struct p11Object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct p11Attribute_t *attribute;
	int i, rv;

	for (i = 0; i < ulCount; i++) {
		rv = findAttribute(object, pTemplate + i, &attribute);

		if (rv < 0) {
			return CK_FALSE;
		}
		if (pTemplate[i].ulValueLen != attribute->attrData.ulValueLen) {
			return CK_FALSE;
		}
		if (memcmp(attribute->attrData.pValue, pTemplate[i].pValue, attribute->attrData.ulValueLen)) {
			return CK_FALSE;
		}
	}
	return CK_TRUE;
}



/*  C_FindObjectsInit initializes a search for token and session objects
    that match a template. */
CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)(
		CK_SESSION_HANDLE hSession,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount
)
{
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	CK_STATE state;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (ulCount && !isValidPtr(pTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (session->searchObj.searchList != NULL) {
		C_FindObjectsFinal(hSession);
	}

	if (slot->token == NULL) {
		FUNC_FAILS(CKR_DEVICE_REMOVED, "device removed");
	}

	/* session objects */
	FOR_EACH(object, session->objectList) {
		if (isMatchingObject(object, pTemplate, ulCount)) {
			addObjectToSearchList(session, object);
		}
	}

	/* public token objects */
	FOR_EACH(object, slot->token->pubObjectList) {
		if (isMatchingObject(object, pTemplate, ulCount)) {
			addObjectToSearchList(session, object);
		}
	}

	/* private token objects */
	state = getSessionState(session, slot);
	if (state == CKS_RW_USER_FUNCTIONS || state == CKS_RO_USER_FUNCTIONS) {
		FOR_EACH(object, slot->token->privObjectList) {
			if (isMatchingObject(object, pTemplate, ulCount)) {
				addObjectToSearchList(session, object);
			}
		}
	}

	FUNC_RETURNS(CKR_OK);
}



/*  C_FindObjects continues a search for token and session objects that match a template, */
CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE_PTR phObject,
		CK_ULONG ulMaxObjectCount,
		CK_ULONG_PTR pulObjectCount
)
{
	struct p11Object_t *object;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	int i = 0, cnt;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (phObject && !isValidPtr(phObject)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulObjectCount)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	if (session->searchObj.objectCollected == session->searchObj.objectCount) {
		*pulObjectCount = 0;
		FUNC_RETURNS(CKR_OK);
	}

	/* Move object to the first uncollected element */
	object = session->searchObj.searchList;
	/* canonical reverse loop */
	for (i = session->searchObj.objectCollected; --i >= 0; ) {
		object = object->next;
		assert(object);
	}

	cnt = session->searchObj.objectCount - session->searchObj.objectCollected;
	if (cnt > ulMaxObjectCount) {
		cnt = ulMaxObjectCount;
	}

	for (i = 0; i < cnt; i++) {
		*phObject++ = object->handle;
		object = object->next;
	}

	*pulObjectCount = cnt;
	session->searchObj.objectCollected += cnt;

	FUNC_RETURNS(CKR_OK);
}



/*  C_FindObjectsFinal terminates a search for token and session objects. */
CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)(
		CK_SESSION_HANDLE hSession
)
{
	struct p11Session_t *session;
	struct p11Slot_t *slot;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_FIND_SESSION_AND_LOCK_SLOT(hSession, &session, &slot);

	clearSearchList(session);

	FUNC_RETURNS(CKR_OK);
}
