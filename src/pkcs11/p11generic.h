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
 * @file    p11generic.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   General module functions at the PKCS#11 interface
 */

#ifndef ___P11GENERIC_H_INC___
#define ___P11GENERIC_H_INC___

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <common/mutex.h>

#include <pkcs11/cryptoki.h>
#include <pkcs11/object.h>

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif


#ifndef CTAPI
#ifndef _WIN32
#include <pcsclite.h>
#include <winscard.h>
#else /* _WIN32 */
#include <winscard.h>
#define usleep(us) Sleep((us) / 1000)
#define  MAX_READERNAME   128
#endif /* _WIN32 */
#endif /* CTAPI */

#ifdef DEBUG

#define FUNC_CALLED() MUTEX *_pmutex_ = 0; \
do { \
	debug("Function %s called.\n", __FUNCTION__); \
} while (0)


#define FUNC_RETURNS(rc) do { \
	CK_RV _rc_ = rc; \
	debug("Function %s completes with rc=%d.\n", __FUNCTION__, _rc_); \
	if (_pmutex_) MUTEX_UNLOCK(_pmutex_); \
	return _rc_; \
} while (0)


#define FUNC_FAILS(rc, msg) do { \
	CK_RV _rc_ = rc; \
	debug("Function %s fails with rc=%d \"%s\"\n", __FUNCTION__, _rc_, (msg)); \
	if (_pmutex_) MUTEX_UNLOCK(_pmutex_); \
	return _rc_; \
} while (0)


#else /* no debug */


#define FUNC_CALLED() MUTEX *_pmutex_ = 0 

#define FUNC_RETURNS(rc) do { \
	if (_pmutex_) MUTEX_UNLOCK(_pmutex_); \
	return (rc); \
} while (0)

#define FUNC_FAILS(rc, msg) do { \
	if (_pmutex_) MUTEX_UNLOCK(_pmutex_); \
	return (rc); \
} while (0)

#endif

/**
 * Gets ownership of the mutex *pmutex. Further it sets the stack variable
 * _pmutex_ (implicit defined with FUNC_CALLED) to pmutex. The purpose of this macro is
 * that the 2 macros FUNC_RETURNS and FUNC_FAILS automatically releases the sepcified mutex.
 * It is convenient to use the macro instead of tracking all returnd and release the mutex
 * manually. As a consequence you must use FUNC_RETURNS or FUNC_FAILS if you to want exit
 * the function (never return directly -- the epilog will not be called).
 * On call FUNC_CALLED must be called before (defining _pmutex_) and
 * _pmutex_ == NULL <=> you can call FUNC_LOCK only once (except you call
 * FUNC_UNLOCK before the next call of FUNC_LOCK).
 *
 * @param pmutex       The pointer to the mutex.
 */
#define FUNC_LOCK(pmutex) do { \
	assert(!_pmutex_); \
	_pmutex_ = pmutex; \
	MUTEX_LOCK(pmutex); \
} while (0)

/**
 * Releases the mutex *pmutex and sets the auto variable _pmutex_ to NULL.
 * On call FUNC_CALLED must be called before (defining _pmutex_) and
 * _pmutex_ == pmutex <=> you must have called FUNC_LOCK before.
 * Purpose of this macro: If you know you do not later access the data protected
 * by the mutex you can release the mutex earlier.
 *
 * @param pmutex      The pointer to the mutex.
 */
#define FUNC_UNLOCK(pmutex) do { \
	assert(_pmutex_ && _pmutex_ == pmutex); \
	MUTEX_UNLOCK(pmutex); \
	_pmutex_ = 0; \
} while (0)


/**
 * Finds a session pointer for the provided session handle.
 * The slot mutex is aquired and remebered in _pmutex_ (= &session->slot->mutex).
 * Purpose of this macro: Each session function shall call the macro immediately after parameter checking.
 * Like all other FUNC_ macros the FUNC_RETURN and FUNC_FAILS handle the reverse operation
 * automatically, specifically releasing the slot mutex.
 * On call FUNC_CALLED must be called before, and later FUNC_RETURNS or FUNC_FAILS must be used instead
 * of return.
 *
 * @param handle       The handle of the session.
 * @param ppSession    Pointer the the session pointer which receives the found session.
 */
#define FUNC_FIND_SESSION_AND_LOCK_SLOT(handle, ppSession, ppSlot) { \
	int rc; \
	assert(!_pmutex_); \
	rc = safeFindSessionAndLockSlot(&context->sessionPool, &context->slotPool, handle, ppSession, ppSlot); \
	if (rc) FUNC_RETURNS(rc); \
	_pmutex_ = &(*ppSlot)->mutex; \
} while (0);
	

/**
 * Finds a slot pointer for the provided slot handle.
 * The slot mutex is aquired and remebered in _pmutex_ (= &slot->mutex).
 * Purpose of this macro: Each slot function shall call the macro immediately after parameter checking.
 * Like all other FUNC_ macros the FUNC_RETURN and FUNC_FAILS handle the reverse operation
 * automatically, specifically releasing the slot mutex.
 * On call FUNC_CALLED must be called before, and later FUNC_RETURNS or FUNC_FAILS must be used instead
 * of return.
 *
 * @param slotID       self explaining
 * @param ppSlot       Pointer the the slot pointer which receives the found slot.
 */
#define FUNC_FIND_AND_LOCK_SLOT(slotID, ppSlot) { \
	int rc; \
	assert(!_pmutex_); \
	rc = safeFindAndLockSlot(&context->slotPool, slotID, ppSlot); \
	if (rc) FUNC_RETURNS(rc); \
	_pmutex_ = &(*ppSlot)->mutex; \
} while (0);


/**
 * Mutex macros. All of them are protected by assert. If the system runs out of mutexes we have
 * a serious problem and the only option is to terminate the process.
 *
 * @param pmutex    Pointer to a mutex structure.
 */
#define MUTEX_INIT(pmutex) assert(!mutex_init(pmutex))
#define MUTEX_DESTROY(pmutex) assert(!mutex_destroy(pmutex))
#define MUTEX_LOCK(pmutex) assert(!mutex_lock(pmutex))
#define MUTEX_UNLOCK(pmutex) assert(!mutex_unlock(pmutex))

#ifdef mutex_owner
#define VERIFY_MUTEXOWNER(pmutex) assert(mutex_owner(pmutex) == GetCurrentThreadId())
#define VERIFY_NOT_MUTEXOWNER(pmutex) assert(mutex_owner(pmutex) != GetCurrentThreadId())
#else
#define VERIFY_MUTEXOWNER(pmutex)
#define VERIFY_NOT_MUTEXOWNER(pmutex)
#endif

/**
 * Walks through a single linked NULL terminated list.
 * The listType must have a field: listType* next.
 *
 * @param p    iteration pointer, must not be altered in the loop.
 * @param list pointer to the first element.
 */
#define FOR_EACH(p, list) \
		for ((p) = (list); p; (p) = (p)->next)

/**
 * Walks through a single linked NULL terminated list.
 * The listType must have a field: listType* next.
 *
 * @param p    iteration pointer, can be altered in the loop.
 * @param n    pointer which holds the next element, must not be altered in the loop.
 * @param list pointer to the first element.
 */
#define FOR_EACH_WITH_NEXT(p, n, list) \
		for ((p) = (list); (p) && ((n) = (p)->next, 1) ; (p) = (n))

/**
 * Walks through a single linked NULL terminated list. 
 * The listType must have a field: listType* next.
 * Initially pp points to the variable which represents the list. Later it points to next field of the
 * previous element. A typical use case is to remove/insert elements.
 * e.g.: insert: pNew->next = *pp; *pp = pNew (inserts pNew before the current element)
 *       unlink: *pp = (*pp)->next (removes the current element)
 * @param pp   iteration double pointer, *pp points to the current element, must not be altered in the loop.
 * @param list pointer to the first element.
 */
#define FOR_EACH_REF(pp, list) \
		for ((pp) = &(list); *(pp); (pp) = &(*(pp))->next)


/**
 * Internal structure to store information about a slot.
 *
 */
struct p11Slot_t
{
	CK_SLOT_ID id;                         /**< The id of the slot                           */
	CK_SLOT_INFO info;                     /**< General information about the slot           */
	unsigned long hasFeatureVerifyPINDirect;
#ifndef CTAPI
	char readerName[MAX_READERNAME];       /**< The slot name                                */
	SCARDCONTEXT context;                  /**< Card manager context for slot                */
	SCARDHANDLE card;                      /**< Handle to card                               */
#endif
	unsigned queuing;                      /**< Used to preventing slot deletion             */
	MUTEX mutex;                           /**< mutex used for slot synchronisation          */
	int sessionCount;                      /**< Number of sessions                           */
	int readOnlySessionCount;              /**< Number of read only sessions                 */
	int present;                           /**< Used in saveUpdateSlots                      */
	int closed;                            /**< Slot ready for delete                        */
	struct p11Token_t *token;              /**< Pointer to token in the slot                 */
	struct p11Slot_t *next;                /**< Pointer to next slot, NULL if last           */
};

/**
 * Internal structure to store information about a token.
 *
 */
struct p11Token_t
{
	CK_TOKEN_INFO info;                    /**< General information about the token          */
	struct p11Slot_t *slot;                /**< The slot where the token is inserted         */
	CK_USER_TYPE userType;                 /**< The user type of this session                */
	CK_ULONG nextObjectHandle;             /**< Value of next assigned object handle         */
	CK_MECHANISM_TYPE mechanism;           /**< Mechanisms supported by token                */
	CK_ULONG pubObjectCount;               /**< The number of public objects in this token   */
	struct p11Object_t *pubObjectList;     /**< Pointer to first object in pool              */
	CK_ULONG privObjectCount;              /**< The number of private objects in this token  */
	struct p11Object_t *privObjectList;    /**< Pointer to the first object in pool          */
};

/**
 * Internal structure to store information for session management and a list
 * of all active sessions.
 *
 */
struct p11SessionPool_t
{
	CK_SESSION_HANDLE nextHandle;          /**< Value of next assigned session handle        */
	MUTEX mutex;                           /**< mutex for thread safe access                 */
	CK_ULONG count;                        /**< Number of active sessions                    */
	struct p11Session_t *list;             /**< Pointer to first session in pool             */
};


/**
 * Internal structure to store information about all available slots.
 *
 */
struct p11SlotPool_t
{
	CK_SLOT_ID nextID;                     /**< The next assigned slot ID value              */
	MUTEX mutex;                           /**< mutex for thread safe access                 */
	CK_ULONG count;                        /**< Number of slots in the pool                  */
	struct p11Slot_t *list;                /**< Pointer to first slot in pool                */
};


/**
 * Internal context structure of the cryptoki.
 *
 */
struct p11Context_t
{
	CK_VERSION version;                    /**< Information about cryptoki version           */
	CK_INFO info;                          /**< General information about cryptoki           */
	CK_HW_FEATURE_TYPE HardwareFeatures;   /**< Hardware feature type of device              */
	struct p11SessionPool_t sessionPool;   /**< open sessions                                */
	struct p11SlotPool_t slotPool;         /**< available slots                              */
#ifdef DEBUG
	FILE *debugFileHandle;
#endif
};

#endif /* ___P11GENERIC_H_INC___ */
