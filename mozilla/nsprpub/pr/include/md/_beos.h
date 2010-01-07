/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
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
 * Fredrik Holmqvist <thesuckiestemail@yahoo.se>
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

#ifndef nspr_beos_defs_h___
#define nspr_beos_defs_h___

#include <errno.h>
#include <dirent.h>
#include <OS.h>

/*
 * Hack for Cross compile
 */
#define FD_SETSIZE 1024

#undef bool

/*
 * Internal configuration macros
 */

#ifdef BONE_VERSION
#define _PR_HAVE_SOCKADDR_LEN
#endif

#define PR_LINKER_ARCH	"beos"
#define _PR_SI_SYSNAME  "BEOS"
#ifdef __powerpc__
#define _PR_SI_ARCHITECTURE "ppc"
#else
#define _PR_SI_ARCHITECTURE "x86"
#endif
#define PR_DLL_SUFFIX		".so"

#define _MD_DEFAULT_STACK_SIZE	65536L

#undef	HAVE_STACK_GROWING_UP
#define HAVE_DLL

/*
 * The Atomic operations
 */

#define _PR_HAVE_ATOMIC_OPS
#ifdef __powerpc__
#define _MD_INIT_ATOMIC _MD_AtomicInit
#else
#define _MD_INIT_ATOMIC()
#endif
#define _MD_ATOMIC_INCREMENT _MD_AtomicIncrement
#define _MD_ATOMIC_ADD _MD_AtomicAdd
#define _MD_ATOMIC_DECREMENT _MD_AtomicDecrement
#define _MD_ATOMIC_SET _MD_AtomicSet

/* Makes sure to don't create cvar when creating sem */
#define HAVE_CVAR_BUILT_ON_SEM

/* Not sure this is needed, but no harm. */
#define _PR_GLOBAL_THREADS_ONLY

#define _PR_BTHREADS

#define _PR_HAVE_O_APPEND

/* Define threading functions and objects as native BeOS 
   Used by bthreads. */

struct _MDThread {
    thread_id	tid;	/* BeOS thread handle */
	sem_id		joinSem;	/* sems used to synchronzie joining */
	PRBool	is_joining;	/* TRUE if someone is currently waiting to
						   join this thread */
};

/*
** Process-related definitions
*/
struct _MDProcess {
    pid_t pid;
};

/*
** File- and directory-related definitions
*/
struct _MDFileDesc {
    PRInt32	osfd;
    PRInt32	sock_state;
    PRBool	accepted_socket;
    PRNetAddr	peer_addr;
#ifndef BONE_VERSION
    PRBool	connectValueValid;
    int		connectReturnValue;
    int		connectReturnError;
#endif
};

struct _MDDir {
    DIR		*d;
};

#define PR_DIRECTORY_SEPARATOR		'/'
#define PR_DIRECTORY_SEPARATOR_STR	"/"
#define PR_PATH_SEPARATOR		':'
#define PR_PATH_SEPARATOR_STR		":"

#define GETTIMEOFDAY(tp)	gettimeofday((tp), NULL)


/*
 * Network related definitions.
 */

#ifndef BONE_VERSION
#define BE_SOCK_SHUTDOWN_READ	0x01
#define BE_SOCK_SHUTDOWN_WRITE	0x02

#define IPPROTO_IP 0
#define AF_UNIX 2
#define TCP_NODELAY SO_NONBLOCK
#define SO_LINGER -1
#define SO_ERROR 4

/* these aren't actually used. if they are, we're screwed */
struct  protoent {
    char    *p_name;        /* official protocol name */
    char    **p_aliases;    /* alias list */
    int     p_proto;        /* protocol # */
};

struct protoent* getprotobyname(const char* name);
struct protoent* getprotobynumber(int number);
#endif

/* Used by bnet.c */
#define _PR_INTERRUPT_CHECK_INTERVAL_SECS 5

/*
 * malloc() related definitions.
 * Avoids prmalloc.c's and prmem's code
 */
#undef _PR_OVERRIDE_MALLOC

/* Miscellaneous */

#define _MD_ERRNO()             (errno)

#define _MD_CLEANUP_BEFORE_EXIT()
#define _MD_EXIT exit

#define _MD_GET_ENV getenv
#define _MD_PUT_ENV putenv

#define _MD_EARLY_INIT()
#ifdef BONE_VERSION
#define _MD_FINAL_INIT()
#else 
#define _MD_FINAL_INIT _MD_final_init_netserver
#endif

/* Thread stuff */

#define _MD_CURRENT_THREAD() PR_GetCurrentThread()


/* File I/O */

#define _PR_MD_WRITE 

/*
These are defined in primpl.h so that they are avail for all, but we
have no calls, and pthreads doesn't either.
#define _MD_LSEEK _MD_lseek
#define _MD_LSEEK64 _MD_lseek64

#define _MD_GETFILEINFO _MD_getfileinfo
#define _MD_GETFILEINFO64 _MD_getfileinfo64
#define _MD_GETOPENFILEINFO _MD_getopenfileinfo
#define _MD_GETOPENFILEINFO64 _MD_getopenfileinfo64
*/

/* Network I/O */

#define _MD_GET_SOCKET_ERROR()	(errno)
#define _MD_GETHOSTNAME _MD_gethostname

/* Process management */

#define _MD_CREATE_PROCESS _MD_create_process
#define _MD_DETACH_PROCESS _MD_detach_process
#define _MD_WAIT_PROCESS _MD_wait_process
#define _MD_KILL_PROCESS _MD_kill_process

/* Memory mapped file I/O */

#define _MD_CREATE_FILE_MAP _MD_create_file_map
#define _MD_GET_MEM_MAP_ALIGNMENT _MD_get_mem_map_alignment
#define _MD_MEM_MAP _MD_mem_map
#define _MD_MEM_UNMAP _MD_mem_unmap
#define _MD_CLOSE_FILE_MAP _MD_close_file_map

/* Time related */

#define _MD_INTERVAL_INIT()
#define _MD_GET_INTERVAL _MD_get_interval
#define _MD_INTERVAL_PER_SEC _MD_interval_per_sec

/* File locking */

#define _MD_LOCKFILE _MD_lockfile
#define _MD_TLOCKFILE _MD_tlockfile
#define _MD_UNLOCKFILE _MD_unlockfile

#endif /* _nspr_beos_defs_h___*/
