/* -*- Mode: C++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: MPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Netscape Portable Runtime (NSPR).
 *
 * The Initial Developer of the Original Code is
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998-2000
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the MPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the MPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

#include "primpl.h"

#include <sys/time.h>
/*
 * Make sure _PRSockLen_t is 32-bit, because we will cast a PRUint32* or
 * PRInt32* pointer to a _PRSockLen_t* pointer.
 */
#define _PRSockLen_t int


#ifndef BONE_VERSION
PRLock *_connectLock = NULL;

/* Workaround for nonblocking connects under net_server */
PRUint32 connectCount = 0;
ConnectListNode connectList[64];

void
_MD_final_init_netserver(void)
{
    _connectLock = PR_NewLock();
    PR_ASSERT(NULL != _connectLock); 
    /* Workaround for nonblocking connects under net_server */
    connectCount = 0;
}
#endif /* !BONE_VERSION */


#ifdef __powerpc__
static PRLock *monitor = NULL;

void
_MD_AtomicInit(void)
{
    if (monitor == NULL) {
        monitor = PR_NewLock();
    }
}
#endif /* __powerpc__ */

/*
** This is exceedingly messy.  atomic_add returns the last value, NSPR
** expects the new value. We just add or subtract 1 from the result.
** The actual memory update is atomic.
 */

PRInt32
_MD_AtomicAdd( PRInt32 *ptr, PRInt32 val )
{
    return atomic_add( (long *)ptr, val ) + val;
}

PRInt32
_MD_AtomicIncrement( PRInt32 *val )
{
    return atomic_add( (long *)val, 1 ) + 1;
}

PRInt32
_MD_AtomicDecrement( PRInt32 *val )
{
    return atomic_add( (long *)val, -1 ) - 1;
}

PRInt32
_MD_AtomicSet( PRInt32 *val, PRInt32 newval )
{
    PRInt32 result;
#ifdef __powerpc__
    if (!_pr_initialized) {
        _PR_ImplicitInitialization();
    }
    PR_Lock(monitor);
    result = *val;
    *val = newval;
    PR_Unlock(monitor);
#else
    asm volatile ("xchgl %0, %1" 
                : "=r"(result), "=m"(*val)
                : "0"(newval), "m"(*val));

#endif /* __powerpc__ */
  return result;
}

/*
 *-----------------------------------------------------------------------
 *
 * PR_Now --
 *
 *     Returns the current time in microseconds since the epoch.
 *     The epoch is midnight January 1, 1970 GMT.
 *     The implementation is machine dependent.  
 *
 *-----------------------------------------------------------------------
 */

PR_IMPLEMENT(PRTime)
PR_Now(void)
{
    return (PRTime) real_time_clock_usecs();
}

PRIntervalTime
_MD_get_interval(void)
{
    return (PRIntervalTime) real_time_clock_usecs() / 10;
}

PRIntervalTime
_MD_interval_per_sec(void)
{
    return 100000L;
}

PRSize
_PR_MD_GetRandomNoise( void *buf, PRSize size )
{
    struct timeval tv;
    int n = 0;
    int s;

    GETTIMEOFDAY(&tv);

    if ( size >= 0 ) {
        s = _pr_CopyLowBits((char*)buf+n, size, &tv.tv_usec, sizeof(tv.tv_usec));
        size -= s;
        n += s;
}
    if ( size >= 0 ) {
        s = _pr_CopyLowBits((char*)buf+n, size, &tv.tv_sec, sizeof(tv.tv_sec));
        size -= s;
        n += s;
}
    return n;
} /* end _PR_MD_GetRandomNoise() */


/* Needed by prinit.c:612 */
void
_PR_MD_QUERY_FD_INHERITABLE(PRFileDesc *fd)
{
    int flags;

    PR_ASSERT(_PR_TRI_UNKNOWN == fd->secret->inheritable);
    flags = fcntl(fd->secret->md.osfd, F_GETFD, 0);
    PR_ASSERT(-1 != flags);
    fd->secret->inheritable = (flags & FD_CLOEXEC) ?
        _PR_TRI_FALSE : _PR_TRI_TRUE;
}

PRStatus
_MD_gethostname(char *name, PRUint32 namelen)
{
    PRInt32 rv, err;

    rv = gethostname(name, namelen);
	if (rv == 0)
{
        err = _MD_ERRNO();
        switch (err) {
            case EFAULT:
                PR_SetError(PR_ACCESS_FAULT_ERROR, err);
                break;
            default:
                PR_SetError(PR_UNKNOWN_ERROR, err);
                break;
}
	return PR_FAILURE;
}
		return PR_SUCCESS;
    }
