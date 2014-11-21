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
 * @file    p11mutex.c
 * @author  Christoph Brunhuber
 * @brief   Provides an interface to pthread or windows (native pmutex or CRITICAL_SECTION) mutexes.
 */

#include <errno.h>
#include <assert.h>
#include "mutex.h"

/*
	All mutexes defined here have the recursive semantics:
	After a thread has ownership of a pmutex, it can make additional calls to mutex_lock
	without blocking its execution. This prevents a thread from deadlocking itself while
	waiting for a pmutex that it already owns. The thread enters the protected section each time
	mutex_lock is called. A thread must call mutex_unlock once for each time that it entered
	the protected section.	
*/

#ifndef DUMMY_MUTEX

#ifndef _WIN32

int mutex_init(MUTEX *pmutex)
{
	int rc;
	pthread_mutexattr_t mutexAttr;
	if (pmutex == NULL)
		return ENOMEM;
	rc = pthread_mutexattr_init(&mutexAttr);
	if (rc)
		return  rc;
	rc = pthread_mutexattr_settype(&mutexAttr, PTHREAD_MUTEX_RECURSIVE_NP);
	if (rc)
		return rc;
	rc = pthread_mutex_init(&pmutex->mutex, &mutexAttr);
	pmutex->owner = 0;
	pmutex->refcnt = 0;
	pthread_mutexattr_destroy(&mutexAttr);
	return rc;
}

int mutex_destroy(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return EINVAL;
	return pthread_mutex_destroy(&pmutex->mutex);
}

int mutex_lock(MUTEX *pmutex)
{
	int rc;
	if (pmutex == NULL)
		return EINVAL;
	rc = pthread_mutex_lock(&pmutex->mutex);
	if (rc == EOWNERTERM) { /* the thread which owned the mutex died */
		rc = 0;
	}
	if (pmutex->refcnt++ == 0)
		pmutex->owner = pthread_self();
	return rc;
}

int mutex_unlock(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return EINVAL;
	assert(pmutex->refcnt > 0 && pmutex->owner == pthread_self());
	if (--pmutex->refcnt == 0)
		pmutex->owner = 0;
	return pthread_mutex_unlock(&pmutex->mutex);
}

#else /* _WIN32 */
#include <windows.h>

int mutex_init(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return E_POINTER;
	pmutex->owner = 0;
	pmutex->refcnt = 0;
	pmutex->handle = CreateMutex(NULL, 0, NULL);
	if (pmutex->handle == NULL)
		return GetLastError();
	return 0;
}

int mutex_destroy(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return E_POINTER;
	if (!CloseHandle(pmutex->handle))
		return GetLastError();
	return 0;
}

int mutex_lock(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return E_POINTER;
	switch (WaitForSingleObject(pmutex->handle, INFINITE)) {
	case WAIT_ABANDONED:
	case WAIT_OBJECT_0:
		if (pmutex->refcnt++ == 0)
			pmutex->owner = GetCurrentThreadId();
		return 0;
	case WAIT_TIMEOUT:
		return WAIT_TIMEOUT;
	default:
		return GetLastError();
	}
}

int mutex_unlock(MUTEX *pmutex)
{
	if (pmutex == NULL)
		return E_POINTER;
	assert(pmutex->refcnt > 0 && pmutex->owner == GetCurrentThreadId());
	if (--pmutex->refcnt == 0)
		pmutex->owner = 0;
	if (!ReleaseMutex(pmutex->handle))
		return GetLastError();
	return 0;
}

#endif /* _WIN32 */
#else /* DUMMY_MUTEX */

/* dummy functions */
int mutex_init(MUTEX *pmutex)    { return !pmutex; }
int mutex_destroy(MUTEX *pmutex) { return !pmutex; }
int mutex_lock(MUTEX *pmutex)    { return !pmutex; }
int mutex_unlock(MUTEX *pmutex)  { return !pmutex; }

#endif /* DUMMY_MUTEX */
