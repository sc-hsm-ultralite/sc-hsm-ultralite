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
 * @file    pmutex.h
 * @author  Christoph Brunhuber
 * @brief   Provides an interface to pthread or windows (native pmutex or CRITICAL_SECTION) mutexes.
 */

#ifndef ___MUTEX_H_INC___
#define ___MUTEX_H_INC___

/* for tests and systems which do not support mutexes/threads */
// #define DUMMY_MUTEX

#ifndef DUMMY_MUTEX
	#ifndef _WIN32
		#include <pthread.h>
		#ifndef EOWNERTERM
		#define EOWNERTERM 3462
		#endif
		typedef struct {
			pthread_mutex_t mutex;
			pthread_t owner;
			unsigned refcnt;
		} MUTEX;
		#ifdef HAVE_SYNC_ADD_AND_FETCH
			#define InterlockedIncrement(ptr) __sync_add_and_fetch((ptr), 1)
			#define InterlockedDecrement(ptr) __sync_add_and_fetch((ptr), -1)
		#else /* not thread-safe */
			#error "Must implement InterlockedXXcrement macros"
/*
	The following 2 macros provide the same semantics, but not thread-safe.
	If you use them the whole thing is NOT thread-safe.
*/
			#define InterlockedIncrement(ptr) (++*(ptr))
			#define InterlockedDecrement(ptr) (--*(ptr))
		#endif
		#define GetCurrentThreadId() pthread_self()
	#else /* _WIN32 */
		#include <Windows.h>
		typedef struct {
			HANDLE handle;
			DWORD owner;
			unsigned refcnt;
		} MUTEX;
	#endif
#else
	typedef int MUTEX;
#endif /* DUMMY_MUTEX */

int mutex_init(MUTEX *pmutex);
int mutex_destroy(MUTEX *pmutex);
int mutex_lock(MUTEX *pmutex);
int mutex_unlock(MUTEX *pmutex);
#define mutex_owner(pmutex) ((pmutex)->owner)

#endif /* ___MUTEX_H_INC___ */
