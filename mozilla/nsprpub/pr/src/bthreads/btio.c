/* -*- Mode: C++; c-basic-offset: 4 -*- */
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
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#define READ_FD     1
#define WRITE_FD    2

#ifdef BONE_VERSION
inline int closesocket(int socket) {
    return close(socket);
}
#endif


inline void 
set_stat_error(int err)
{
    PR_SetError(err == ETIMEDOUT ? PR_REMOTE_FILE_ERROR : map_default_error(err), err);
}

inline void 
set_access_error(int err)
{
    PR_SetError(err == ETIMEDOUT ? PR_REMOTE_FILE_ERROR : map_default_error(err), err);
}

inline void 
set_select_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void
set_writev_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void
set_connect_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EACCES:
        case ELOOP:
        case ENOENT:
            prError = PR_ADDRESS_NOT_SUPPORTED_ERROR;        
            break;
        case ENXIO:
            prError = PR_IO_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);

}

inline void 
set_accept_error(int err)
{
    PR_SetError(err == ENODEV ? PR_NOT_TCP_SOCKET_ERROR : map_default_error(err), err);
}


inline void 
set_bind_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_SOCKET_ADDRESS_IS_BOUND_ERROR;
            break;
        case EIO:
        case EISDIR:
        case ELOOP:
        case ENOENT:
        case ENOTDIR:
        case EROFS:
            prError = PR_ADDRESS_NOT_SUPPORTED_ERROR;
            break;
        case ENXIO:
            prError = PR_IO_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}

inline void
set_listen_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void 
set_shutdown_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void 
set_socketpair_error(int err)
{
    PR_SetError(err == ENOMEM ? PR_INSUFFICIENT_RESOURCES_ERROR : map_default_error(err), err);
}

inline void
set_recv_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void
set_recvfrom_error(int err)
{
    PR_SetError(map_default_error(err), err);
}


inline void 
set_send_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void 
set_sendto_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void
set_getsockname_error(int err)
{
    PR_SetError(err == ENOMEM ? PR_INSUFFICIENT_RESOURCES_ERROR : map_default_error(err), err);
}


inline void
set_getpeername_error(int err)
{
    PR_SetError(err == ENOMEM ? PR_INSUFFICIENT_RESOURCES_ERROR : map_default_error(err), err);
}


inline void 
set_getsockopt_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_BUFFER_OVERFLOW_ERROR;
            break;
        case ENOMEM:
            prError = PR_INSUFFICIENT_RESOURCES_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}

inline void 
set_setsockopt_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_BUFFER_OVERFLOW_ERROR;
            break;
        case ENOMEM:
            prError = PR_INSUFFICIENT_RESOURCES_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void 
set_socket_error(int err)
{
    PR_SetError( err == ENOMEM ? PR_INSUFFICIENT_RESOURCES_ERROR : map_default_error(err), err);
}


PR_IMPLEMENT(PRStatus) PR_GetFileInfo(const char *fn, PRFileInfo *info)
{
    struct stat sb;
    PRInt32 rv, err;
    PRInt64 s, s2us;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    rv = stat(fn, &sb);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_stat_error(err);
        return PR_FAILURE;
    }
    if (info) {
        if (S_IFREG & sb.st_mode)
            info->type = PR_FILE_FILE;
        else if (S_IFDIR & sb.st_mode)
            info->type = PR_FILE_DIRECTORY;
        else
            info->type = PR_FILE_OTHER;

        /* Use lower 32 bits of file size */
        info->size = sb.st_size  & 0xffffffff;
        LL_I2L(s, sb.st_mtime);
        LL_I2L(s2us, PR_USEC_PER_SEC);
        LL_MUL(s, s, s2us);
        info->modifyTime = s;
        LL_I2L(s, sb.st_ctime);
        LL_MUL(s, s, s2us);
        info->creationTime = s;
    }

    return PR_SUCCESS;
}


PR_IMPLEMENT(PRStatus) PR_GetFileInfo64(const char *fn, PRFileInfo64 *info)
{
    struct stat sb;
    PRInt32 rv, err;
    PRInt64 s, s2us;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    rv = stat(fn, &sb);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_stat_error(err);
        return PR_FAILURE;
    }
    if (info) {
        if (S_IFREG & sb.st_mode)
            info->type = PR_FILE_FILE;
        else if (S_IFDIR & sb.st_mode)
            info->type = PR_FILE_DIRECTORY;
        else
            info->type = PR_FILE_OTHER;

        /* For the 64 bit version we can use
         * the native st_size without modification
         */
        info->size = sb.st_size;
        LL_I2L(s, sb.st_mtime);
        LL_I2L(s2us, PR_USEC_PER_SEC);
        LL_MUL(s, s, s2us);
        info->modifyTime = s;
        LL_I2L(s, sb.st_ctime);
        LL_MUL(s, s, s2us);
        info->creationTime = s;
    }

    return PR_SUCCESS;
}

PR_IMPLEMENT(PRStatus) PR_Access(const char *name, PRAccessHow how)
{
    PRInt32 rv, err;
    int checkFlags;
    struct stat buf;

    switch (how) {
        case PR_ACCESS_WRITE_OK:
            checkFlags = S_IWUSR | S_IWGRP | S_IWOTH;
            break;
        
        case PR_ACCESS_READ_OK:
            checkFlags = S_IRUSR | S_IRGRP | S_IROTH;
            break;
        
        case PR_ACCESS_EXISTS:
            /* we don't need to examine st_mode. */
            break;
        
        default: {
            PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
            return PR_FAILURE;
        }
    }

    rv = stat(name, &buf);
    if (rv == 0 && how != PR_ACCESS_EXISTS && (!(buf.st_mode & checkFlags))) {
        PR_SetError(PR_NO_ACCESS_RIGHTS_ERROR, 0);
        return PR_FAILURE;
    }

    if (rv < 0) {
        err = _MD_ERRNO();
        set_access_error(err);
        return PR_FAILURE;
    } else
        return PR_SUCCESS;
}


PRInt32
_bt_socketavailable (PRFileDesc *fd)
{
#ifdef BONE_VERSION
    PRInt32 result;

    if (ioctl(fd->secret->md.osfd, FIONREAD, &result) < 0) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, _MD_ERRNO());
        return -1;
    }
    return result;
#else
    return PR_NOT_IMPLEMENTED_ERROR;
#endif
}


#if defined(DEBUG)

PRBool IsValidNetAddr(const PRNetAddr *addr)
{
    if ((addr != NULL)
        && (addr->raw.family != PR_AF_INET6)
        && (addr->raw.family != PR_AF_INET)) {
        return PR_FALSE;
    }
    return PR_TRUE;
}

static PRBool IsValidNetAddrLen(const PRNetAddr *addr, PRInt32 addr_len)
{
    /*
     * The definition of the length of a Unix domain socket address
     * is not uniform, so we don't check it.
     */
    if ((addr != NULL)
            && (PR_NETADDR_SIZE(addr) != addr_len)) {
         return PR_FALSE;
    }
    return PR_TRUE;
}

#endif /* DEBUG */

static PRInt32 socket_io_wait(PRInt32 osfd, PRInt32 fd_type,
                              PRIntervalTime timeout)
{
    PRInt32 rv = -1;
    struct timeval tv;
    PRIntervalTime epoch, now, elapsed, remaining;
    PRBool wait_for_remaining;
    PRInt32 syserror;
    fd_set rd_wr;

    switch (timeout) {
    case PR_INTERVAL_NO_WAIT:
        PR_SetError(PR_IO_TIMEOUT_ERROR, 0);
        break;
    case PR_INTERVAL_NO_TIMEOUT:
        /*
         * This is a special case of the 'default' case below.
         * Please see the comments there.
         */
        tv.tv_sec = _PR_INTERRUPT_CHECK_INTERVAL_SECS;
        tv.tv_usec = 0;
        FD_ZERO(&rd_wr);
        do {
            FD_SET(osfd, &rd_wr);
            if (fd_type == READ_FD)
                rv = select(osfd + 1, &rd_wr, NULL, NULL, &tv);
            else
                rv = select(osfd + 1, NULL, &rd_wr, NULL, &tv);
            if (rv == -1 && (syserror = _MD_ERRNO()) != EINTR) {
#ifdef BONE_VERSION
                set_select_error(syserror);
#else
                if (syserror == EBADF) {
                    PR_SetError(PR_BAD_DESCRIPTOR_ERROR, EBADF);
                } else {
                    PR_SetError(PR_UNKNOWN_ERROR, syserror);
                }
#endif
                break;
            }
        } while (rv == 0 || (rv == -1 && syserror == EINTR));
        break;
    default:
        now = epoch = PR_IntervalNow();
        remaining = timeout;
        FD_ZERO(&rd_wr);
        do {
            /*
             * We block in select for at most
             * _PR_INTERRUPT_CHECK_INTERVAL_SECS seconds,
             * so that there is an upper limit on the delay
             * before the interrupt bit is checked.
             */
            wait_for_remaining = PR_TRUE;
            tv.tv_sec = PR_IntervalToSeconds(remaining);
            if (tv.tv_sec > _PR_INTERRUPT_CHECK_INTERVAL_SECS) {
                wait_for_remaining = PR_FALSE;
                tv.tv_sec = _PR_INTERRUPT_CHECK_INTERVAL_SECS;
                tv.tv_usec = 0;
            } else {
                tv.tv_usec = PR_IntervalToMicroseconds(
                                 remaining -
                                 PR_SecondsToInterval(tv.tv_sec));
            }
            FD_SET(osfd, &rd_wr);
            if (fd_type == READ_FD)
                rv = select(osfd + 1, &rd_wr, NULL, NULL, &tv);
            else
                rv = select(osfd + 1, NULL, &rd_wr, NULL, &tv);
            /*
             * we don't consider EINTR a real error
             */
            if (rv == -1 && (syserror = _MD_ERRNO()) != EINTR) {
#ifdef BONE_VERSION
                set_select_error(syserror);
#else
                if (syserror == EBADF) {
                    PR_SetError(PR_BAD_DESCRIPTOR_ERROR, EBADF);
                } else {
                    PR_SetError(PR_UNKNOWN_ERROR, syserror);
                }
#endif
                break;
            }
            /*
             * We loop again if select timed out or got interrupted
             * by a signal, and the timeout deadline has not passed yet.
             */
            if (rv == 0 || (rv == -1 && syserror == EINTR)) {
                /*
                 * If select timed out, we know how much time
                 * we spent in blocking, so we can avoid a
                 * PR_IntervalNow() call.
                 */
                if (rv == 0) {
                    if (wait_for_remaining) {
                        now += remaining;
                    } else {
                        now += PR_SecondsToInterval(tv.tv_sec)
                               + PR_MicrosecondsToInterval(tv.tv_usec);
                    }
                } else {
                    now = PR_IntervalNow();
                }
                elapsed = (PRIntervalTime) (now - epoch);
                if (elapsed >= timeout) {
                    PR_SetError(PR_IO_TIMEOUT_ERROR, 0);
                    rv = -1;
                    break;
                } else {
                    remaining = timeout - elapsed;
                }
            }
        } while (rv == 0 || (rv == -1 && syserror == EINTR));
        break;
    }
    return(rv);
}


static PRInt32 PR_CALLBACK SocketWritev(PRFileDesc *fd, const PRIOVec *iov,
PRInt32 iov_size, PRIntervalTime timeout)
{
#ifdef BONE_VERSION
    int w, err = 0;
    const PRIOVec *tmp_iov;
#define LOCAL_MAXIOV    8
    PRIOVec local_iov[LOCAL_MAXIOV];
    PRIOVec *iov_copy = NULL;
    int tmp_out;
    int index, iov_cnt;
    int count=0, sz = 0;    /* 'count' is the return value. */
    int i, amount = 0;

    /*
     * Assume the first writev will succeed.  Copy iov's only on
     * failure.
     */
    tmp_iov = iov;
    for (index = 0; index < iov_size; index++)
        sz += iov[index].iov_len;

    iov_cnt = iov_size;

    while (sz > 0) {
/*
    /*
     * Calculate the total number of bytes to be sent; needed for
     * optimization later.
     * We could avoid this if this number was passed in; but it is
     * probably not a big deal because iov_size is usually small (less than
     * 3)
     */
    if (!fd->secret->nonblocking) {
        for (i=0; i<iov_cnt; i++) {
            amount += tmp_iov[i].iov_len;
        }
    }

    while ((w = writev(fd->secret->md.osfd, (const struct iovec*)tmp_iov, iov_size)) == -1) {
        err = _MD_ERRNO();
        if ((err == EAGAIN) || (err == EWOULDBLOCK))    {
            if (fd->secret->nonblocking) {
                break;
            }
            if ((w = socket_io_wait(fd->secret->md.osfd, WRITE_FD, timeout))<0)
                goto done;

        } else if (err == EINTR) {
            continue;
        } else {
            break;
        }
    }
    /*
     * optimization; if bytes sent is less than "amount" call
     * select before returning. This is because it is likely that
     * the next writev() call will return EWOULDBLOCK.
     */
    if ((!fd->secret->nonblocking) && (w > 0) && (w < amount)
        && (timeout != PR_INTERVAL_NO_WAIT)) {
        if (socket_io_wait(fd->secret->md.osfd, WRITE_FD, timeout) < 0) {
            w = -1;
            goto done;
        }
    }

    if (w < 0) {
        set_writev_error(err);
    }
done:


        if (w < 0) {
            count = -1;
            break;
        }
        count += w;
        if (fd->secret->nonblocking) {
            break;
        }
        sz -= w;

        if (sz > 0) {
            /* find the next unwritten vector */
            for ( index = 0, tmp_out = count;
                tmp_out >= iov[index].iov_len;
                tmp_out -= iov[index].iov_len, index++){;} /* nothing to execute */

            if (tmp_iov == iov) {
                /*
                 * The first writev failed so we
                 * must copy iov's around.
                 * Avoid calloc/free if there
                 * are few enough iov's.
                 */
                if (iov_size - index <= LOCAL_MAXIOV)
                    iov_copy = local_iov;
                else if ((iov_copy = (PRIOVec *) PR_CALLOC((iov_size - index) *
                    sizeof *iov_copy)) == NULL) {
                    PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
                    return -1;
                }
                tmp_iov = iov_copy;
            }

            PR_ASSERT(tmp_iov == iov_copy);

            /* fill in the first partial read */
            iov_copy[0].iov_base = &(((char *)iov[index].iov_base)[tmp_out]);
            iov_copy[0].iov_len = iov[index].iov_len - tmp_out;
            index++;

            /* copy the remaining vectors */
            for (iov_cnt=1; index<iov_size; iov_cnt++, index++) {
                iov_copy[iov_cnt].iov_base = iov[index].iov_base;
                iov_copy[iov_cnt].iov_len = iov[index].iov_len;
            }
        }
    }

    if (iov_copy != local_iov)
        PR_DELETE(iov_copy);
    return count;
#else
    return PR_NOT_IMPLEMENTED_ERROR;
#endif    
}

PRInt32
_bt_CONNECT (PRFileDesc *fd, const PRNetAddr *addr, PRUint32 addrlen,
             PRIntervalTime timeout)
{
    PRInt32 rv, err;
    PRInt32 osfd = fd->secret->md.osfd;

#ifndef BONE_VERSION
    fd->secret->md.connectValueValid = PR_FALSE;
#endif
#ifdef _PR_HAVE_SOCKADDR_LEN
    PRNetAddr addrCopy;

    addrCopy = *addr;
    ((struct sockaddr *) &addrCopy)->sa_len = addrlen;
    ((struct sockaddr *) &addrCopy)->sa_family = addr->raw.family;
#endif

    /* (Copied from unix.c)
     * We initiate the connection setup by making a nonblocking connect()
     * call.  If the connect() call fails, there are two cases we handle
     * specially:
     * 1. The connect() call was interrupted by a signal.  In this case
     *    we simply retry connect().
     * 2. The NSPR socket is nonblocking and connect() fails with
     *    EINPROGRESS.  We first wait until the socket becomes writable.
     *    Then we try to find out whether the connection setup succeeded
     *    or failed.
     */

retry:
#ifdef _PR_HAVE_SOCKADDR_LEN
    if ((rv = connect(osfd, (struct sockaddr *)&addrCopy, addrlen)) == -1) {
#else
    if ((rv = connect(osfd, (struct sockaddr *)addr, addrlen)) == -1) {
#endif
        err = _MD_ERRNO();
#ifndef BONE_VERSION
        fd->secret->md.connectReturnValue = rv;
        fd->secret->md.connectReturnError = err;
        fd->secret->md.connectValueValid = PR_TRUE;
#endif
        if( err == EINTR ) {
#ifndef BONE_VERSION
            snooze( 100000L );
#endif
            goto retry;
        }

#ifndef BONE_VERSION
        if(!fd->secret->nonblocking && ((err == EINPROGRESS) || (err==EAGAIN) || (err==EALREADY))) {

            /*
            ** There's no timeout on this connect, but that's not
            ** a big deal, since the connect times out anyways
            ** after 30 seconds.   Just sleep for 1/10th of a second
            ** and retry until we go through or die.
            */
            goto retry;
        }

        if( fd->secret->nonblocking && ((err == EAGAIN) || (err == EINPROGRESS))) {
            PR_Lock(_connectLock);
            if (connectCount < sizeof(connectList)/sizeof(connectList[0])) {
                connectList[connectCount].osfd = osfd;
                memcpy(&connectList[connectCount].addr, addr, addrlen);
                connectList[connectCount].addrlen = addrlen;
                connectList[connectCount].timeout = timeout;
                connectCount++;
                PR_Unlock(_connectLock);
                set_connect_error(err);
            } else {
                PR_Unlock(_connectLock);
                PR_SetError(PR_INSUFFICIENT_RESOURCES_ERROR, 0);
            }
            return rv;
        }
#else /* BONE_VERSION */
        if(!fd->secret->nonblocking && (err == EINTR)) {

            rv = socket_io_wait(osfd, WRITE_FD, timeout);
            if (rv == -1) {
                return -1;
            }

            PR_ASSERT(rv == 1);
/* _MD_beos_get_nonblocking_connect_error always return PR_NOT_IMPLEMENTED..
            err = _MD_beos_get_nonblocking_connect_error(osfd);
            if (err != 0) {
                set_connect_error(err);
                return -1;
            }
*/
            return 0;
        }
#endif

        set_connect_error(err);
    }

    return rv;
}


static PRStatus PR_CALLBACK SocketConnect(
    PRFileDesc *fd, const PRNetAddr *addr, PRIntervalTime timeout)
{
    PRInt32 rv;    /* Return value of _PR_MD_CONNECT */
    const PRNetAddr *addrp = addr;
#if defined(_PR_INET6)
    PRNetAddr addrCopy;
    if (addr->raw.family == PR_AF_INET6) {
        addrCopy = *addr;
        addrCopy.raw.family = AF_INET6;
        addrp = &addrCopy;
    }
#endif

    rv = _bt_CONNECT(fd, addrp, PR_NETADDR_SIZE(addr), timeout);
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("connect -> %d", rv));
    if (rv == 0)
        return PR_SUCCESS;
    else
        return PR_FAILURE;
}

static PRStatus PR_CALLBACK SocketConnectContinue(
    PRFileDesc *fd, PRInt16 out_flags)
{
    PRInt32 osfd;
    int err;
    int rv;

    if (out_flags & PR_POLL_NVAL) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }
    if ((out_flags & (PR_POLL_WRITE | PR_POLL_EXCEPT | PR_POLL_ERR)) == 0) {
        PR_ASSERT(out_flags == 0);
        PR_SetError(PR_IN_PROGRESS_ERROR, 0);
        return PR_FAILURE;
    }

    osfd = fd->secret->md.osfd;


#ifdef BONE_VERSION  /* bug 122364 */
    /* temporary workaround until getsockopt(SO_ERROR) works in BONE */
    if (out_flags & PR_POLL_EXCEPT) {
        PR_SetError(PR_CONNECT_REFUSED_ERROR, 0);
        return PR_FAILURE;
    }
    PR_ASSERT(out_flags & PR_POLL_WRITE);
    return PR_SUCCESS;
#else
    rv = recv(fd->secret->md.osfd, NULL, 0, 0);
    PR_ASSERT(-1 == rv || 0 == rv);

    if (-1 == rv && 0 != errno && errno != EAGAIN && errno != EWOULDBLOCK ) {
        set_connect_error(errno);
        return PR_FAILURE;
    }
    else
        return PR_SUCCESS;
#endif
}

PRInt32
_bt_accept (PRFileDesc *fd, PRNetAddr *addr, PRUint32 *addrlen,
            PRIntervalTime timeout)
{
    PRInt32 osfd = fd->secret->md.osfd;
    PRInt32 rv, err;

    while ((rv = accept(osfd, (struct sockaddr *) addr,
                        (int *)addrlen)) == -1) {
        err = _MD_ERRNO();

        if ((err == EAGAIN) || (err == EWOULDBLOCK)) {
            if (fd->secret->nonblocking) {
                break;
            }
            /* If it's SUPPOSED to be a blocking thread, wait
             * a while to see if the triggering condition gets
             * satisfied.
             */
            /* Assume that we're always using a native thread */
            if ((rv = socket_io_wait(osfd, READ_FD, timeout)) < 0)
                goto done;
        } else if (err == EINTR) {
            continue;
        } else {
            break;
        }
    }
    if (rv < 0) {
        set_accept_error(err);
    } else if (addr != NULL) {
        /* bug 134099 */
        err = getpeername(rv, (struct sockaddr *) addr, (int *)addrlen);
    }
done:
#ifdef _PR_HAVE_SOCKADDR_LEN
    if (rv != -1) {
        /* Mask off the first byte of struct sockaddr (the length field) */
        if (addr) {
            addr->raw.family = ((struct sockaddr *) addr)->sa_family;
        }
    }
#endif /* _PR_HAVE_SOCKADDR_LEN */
    return(rv);
}



static PRFileDesc* PR_CALLBACK SocketAccept(PRFileDesc *fd, PRNetAddr *addr,
PRIntervalTime timeout)
{
    PRInt32 osfd;
    PRFileDesc *fd2;
    PRUint32 al;

    al = sizeof(PRNetAddr);
    osfd = _bt_accept(fd, addr, &al, timeout);
    if (osfd == -1)
        return 0;
    fd2 = bt_CreateFileDesc(osfd, PR_GetTCPMethods(), _PR_TRI_TRUE, true);
    if (!fd2) {
        closesocket(osfd);

        return NULL;
    }

    fd2->secret->nonblocking = fd->secret->nonblocking;
    fd2->secret->inheritable = fd->secret->inheritable;

#ifdef _PR_INET6
    if (addr && (AF_INET6 == addr->raw.family))
        addr->raw.family = PR_AF_INET6;
#endif
    PR_ASSERT(IsValidNetAddr(addr) == PR_TRUE);
    PR_ASSERT(IsValidNetAddrLen(addr, al) == PR_TRUE);

    return fd2;
}


static PRStatus PR_CALLBACK SocketBind(PRFileDesc *fd, const PRNetAddr *addr)
{
    PRInt32 result, err;
    const PRNetAddr *addrp = addr;
#if defined(_PR_INET6) || defined(_PR_HAVE_SOCKADDR_LEN)
    PRNetAddr addrCopy;
#endif

    PR_ASSERT(IsValidNetAddr(addr) == PR_TRUE);
#if defined(_PR_INET6)
    if (addr->raw.family == PR_AF_INET6) {
        addrCopy = *addr;
        addrCopy.raw.family = AF_INET6;
        addrp = &addrCopy;
    }
#endif

#ifdef _PR_HAVE_SOCKADDR_LEN
    addrCopy = *addrp;
    ((struct sockaddr *) &addrCopy)->sa_len = PR_NETADDR_SIZE(addrp);
    ((struct sockaddr *) &addrCopy)->sa_family = addr->raw.family;
    result = bind(fd->secret->md.osfd, (struct sockaddr *) &addrCopy, PR_NETADDR_SIZE(addrp));
#else
    result = bind(fd->secret->md.osfd, (struct sockaddr *) addrp, PR_NETADDR_SIZE(addrp));
#endif


    if (result < 0) {
        err = _MD_ERRNO();
        set_bind_error(err);
        return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK SocketListen(PRFileDesc *fd, PRIntn backlog)
{
    PRInt32 result,err;
#ifndef BONE_VERSION
    /* Bug workaround!  Setting listen to 0 on Be accepts no connections.
    ** On most UN*Xes this sets the default.
    */

    if( backlog == 0 ) backlog = 5;
#endif
    result = listen(fd->secret->md.osfd, backlog);
    if (result < 0) {
        err = _MD_ERRNO();
                set_listen_error(err);
        return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK SocketShutdown(PRFileDesc *fd, PRIntn how)
{
    PRInt32 result,err;
#ifndef BONE_VERSION
    if (how == PR_SHUTDOWN_SEND)
        fd->secret->md.sock_state = BE_SOCK_SHUTDOWN_WRITE;
    else if (how == PR_SHUTDOWN_RCV)
        fd->secret->md.sock_state = BE_SOCK_SHUTDOWN_READ;
    else if (how == PR_SHUTDOWN_BOTH) {
        fd->secret->md.sock_state = (BE_SOCK_SHUTDOWN_WRITE | BE_SOCK_SHUTDOWN_READ);
    }
#else /* BONE_VERSION */
    result = shutdown(fd->secret->md.osfd, how);
    if (result < 0) {
        err = _MD_ERRNO();
        set_shutdown_error(err);
        return PR_FAILURE;
    }
#endif
    return PR_SUCCESS;
}

PRInt32
_bt_recv (PRFileDesc *fd, void *buf, PRInt32 amount, PRInt32 flags,
          PRIntervalTime timeout)
{
    PRInt32 osfd = fd->secret->md.osfd;
    PRInt32 rv, err;

#ifndef BONE_VERSION
    if (fd->secret->md.sock_state & BE_SOCK_SHUTDOWN_READ) {
        set_recv_error(EPIPE);
        return -1;
    }
#endif

#ifdef BONE_VERSION
    /*
    ** Gah, stupid hack.  If reading a zero amount, instantly return success.
    ** BONE beta 6 returns EINVAL for reads of zero bytes, which parts of
    ** mozilla use to check for socket availability.
    */

    if( 0 == amount ) return(0);
#endif

    while ((rv = recv(osfd, buf, amount, flags)) == -1) {
        err = _MD_ERRNO();

        if ((err == EAGAIN) || (err == EWOULDBLOCK)) {
            if (fd->secret->nonblocking) {
                break;
            }
            /* If socket was supposed to be blocking,
            wait a while for the condition to be
            satisfied. */
            if ((rv = socket_io_wait(osfd, READ_FD, timeout)) < 0)
                goto done;
        } else if (err == EINTR) {
            continue;
        } else
            break;
    }

    if (rv < 0) {
        set_recv_error(err);
    }

done:
    return(rv);
}

static PRInt32 PR_CALLBACK SocketRecv(PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags,
PRIntervalTime timeout)
{
    PRInt32 rv;

    if ((flags != 0) && (flags != PR_MSG_PEEK)) {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return -1;
    }

    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("recv: fd=%p osfd=%d buf=%p amount=%d flags=%d",
                                    fd, fd->secret->md.osfd, buf, amount, flags));


    rv = _bt_recv(fd, buf, amount, flags, timeout);
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("recv -> %d, error = %d, os error = %d",
        rv, PR_GetError(), PR_GetOSError()));

    return rv;
}

static PRInt32 PR_CALLBACK SocketRead(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    return SocketRecv(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

PRInt32
_bt_send (PRFileDesc *fd, const void *buf, PRInt32 amount, PRInt32 flags,
          PRIntervalTime timeout)
{
    PRInt32 osfd = fd->secret->md.osfd;
    PRInt32 rv, err;

#ifndef BONE_VERSION
    if (fd->secret->md.sock_state & BE_SOCK_SHUTDOWN_WRITE)
    {
        set_send_error(EPIPE);
        return -1;
    }
#endif

    while ((rv = send(osfd, buf, amount, flags)) == -1) {
        err = _MD_ERRNO();

        if ((err == EAGAIN) || (err == EWOULDBLOCK)) {
            if (fd->secret->nonblocking) {
                break;
            }

#ifndef BONE_VERSION

            /* in UNIX implementations, you could do a socket_io_wait here.
             * but since BeOS doesn't yet support WRITE notification in select,
             * you're spanked.
             */
            snooze( 10000L );
            continue;
#else /* BONE_VERSION */
            if ((rv = socket_io_wait(osfd, WRITE_FD, timeout))< 0)
                goto done;
#endif

        } else if (err == EINTR) {
            continue;
        } else {
            break;
        }
    }

#ifdef BONE_VERSION
    /*
     * optimization; if bytes sent is less than "amount" call
     * select before returning. This is because it is likely that
     * the next writev() call will return EWOULDBLOCK.
     */
    if ((!fd->secret->nonblocking) && (rv > 0) && (rv < amount)
        && (timeout != PR_INTERVAL_NO_WAIT)) {
        if (socket_io_wait(osfd, WRITE_FD, timeout) < 0) {
            rv = -1;
            goto done;
        }
    }
#endif /* BONE_VERSION */
    
    if (rv < 0) {
        set_send_error(err);
    }

#ifdef BONE_VERSION
done:
#endif
    return(rv);
}


static PRInt32 PR_CALLBACK SocketSend(PRFileDesc *fd, const void *buf, PRInt32 amount,
PRIntn flags, PRIntervalTime timeout)
{
    PRInt32 temp, count;

    count = 0;
    while (amount > 0) {
        PR_LOG(_pr_io_lm, PR_LOG_MAX,
            ("send: fd=%p osfd=%d buf=%p amount=%d",
            fd, fd->secret->md.osfd, buf, amount));
        temp = _bt_send(fd, buf, amount, flags, timeout);
        if (temp < 0) {
                    count = -1;
                    break;
                }

        count += temp;
        if (fd->secret->nonblocking) {
            break;
        }
        buf = (const void*) ((const char*)buf + temp);

        amount -= temp;
    }
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("send -> %d", count));
    return count;
}

static PRInt32 PR_CALLBACK SocketWrite(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    return SocketSend(fd, buf, amount, 0, PR_INTERVAL_NO_TIMEOUT);
}

static PRStatus PR_CALLBACK SocketClose(PRFileDesc *fd)
{
    if (!fd || !fd->secret
            || (fd->secret->state != _PR_FILEDESC_OPEN
            && fd->secret->state != _PR_FILEDESC_CLOSED)) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }

    if (fd->secret->state == _PR_FILEDESC_OPEN) {
        if (closesocket(fd->secret->md.osfd) < 0) {
            return PR_FAILURE;
        }

        fd->secret->state = _PR_FILEDESC_CLOSED;
    }

    PR_ASSERT(fd);
    _PR_Putfd(fd);
    return PR_SUCCESS;
}

static PRInt32 PR_CALLBACK SocketAvailable(PRFileDesc *fd)
{
    PRInt32 rv;
    rv =  _bt_socketavailable(fd);
    return rv;        
}

static PRInt64 PR_CALLBACK SocketAvailable64(PRFileDesc *fd)
{
    PRInt64 rv;
    LL_I2L(rv, _bt_socketavailable(fd));
    return rv;        
}

static PRStatus PR_CALLBACK SocketSync(PRFileDesc *fd)
{
    return PR_SUCCESS;
}

PRInt32
_bt_sendto (PRFileDesc *fd, const void *buf, PRInt32 amount, PRIntn flags,
            const PRNetAddr *addr, PRUint32 addrlen, PRIntervalTime timeout)
{
    PRInt32 osfd = fd->secret->md.osfd;
    PRInt32 rv, err;

#ifdef _PR_HAVE_SOCKADDR_LEN
    PRNetAddr addrCopy;

    addrCopy = *addr;
    ((struct sockaddr *) &addrCopy)->sa_len = addrlen;
    ((struct sockaddr *) &addrCopy)->sa_family = addr->raw.family;

    while ((rv = sendto(osfd, buf, amount, flags,
                        (struct sockaddr *) &addrCopy, addrlen)) == -1) {
#else
    while ((rv = sendto(osfd, buf, amount, flags,
                        (struct sockaddr *) addr, addrlen)) == -1) {
#endif
        err = _MD_ERRNO();

        if ((err == EAGAIN) || (err == EWOULDBLOCK)) {
            if (fd->secret->nonblocking) {
                break;
            }

#ifdef BONE_VERSION
            if ((rv = socket_io_wait(osfd, WRITE_FD, timeout))< 0)
                goto done;
#endif
        } else if (err == EINTR) {
            continue;

        } else {
            break;
        }
    }

    if (rv < 0) {
        set_sendto_error(err);
    }

#ifdef BONE_VERSION
done:
#endif
    return(rv);
}


static PRInt32 PR_CALLBACK SocketSendTo(
    PRFileDesc *fd, const void *buf, PRInt32 amount,
    PRIntn flags, const PRNetAddr *addr, PRIntervalTime timeout)
{
    PRInt32 temp, count;
    const PRNetAddr *addrp = addr;
#if defined(_PR_INET6)
    PRNetAddr addrCopy;
#endif

    PR_ASSERT(IsValidNetAddr(addr) == PR_TRUE);
#if defined(_PR_INET6)
    if (addr->raw.family == PR_AF_INET6) {
        addrCopy = *addr;
        addrCopy.raw.family = AF_INET6;
        addrp = &addrCopy;
    }
#endif

    count = 0;
    while (amount > 0) {
        temp = _bt_sendto(fd, buf, amount, flags,
            addrp, PR_NETADDR_SIZE(addr), timeout);
        if (temp < 0) {
                    count = -1;
                    break;
                }
        count += temp;
        if (fd->secret->nonblocking) {
            break;
        }
        buf = (const void*) ((const char*)buf + temp);
        amount -= temp;
    }
    return count;
}

PRInt32
_bt_recvfrom (PRFileDesc *fd, void *buf, PRInt32 amount, PRIntn flags,
              PRNetAddr *addr, PRUint32 *addrlen, PRIntervalTime timeout)
{
    PRInt32 osfd = fd->secret->md.osfd;
    PRInt32 rv, err;

    while ((*addrlen = PR_NETADDR_SIZE(addr)),
            ((rv = recvfrom(osfd, buf, amount, flags,
                            (struct sockaddr *) addr,
                            (int *)addrlen)) == -1)) {
        err = _MD_ERRNO();

        if ((err == EAGAIN) || (err == EWOULDBLOCK)) {
            if (fd->secret->nonblocking) {
                break;
            }
            if ((rv = socket_io_wait(osfd, READ_FD, timeout)) < 0)
                goto done;

        } else if (err == EINTR) {
            continue;
        } else {
            break;
        }
    }

    if (rv < 0) {
        set_recvfrom_error(err);
    }

done:
#ifdef _PR_HAVE_SOCKADDR_LEN
    if (rv != -1) {
        /* ignore the sa_len field of struct sockaddr */
        if (addr) {
            addr->raw.family = ((struct sockaddr *) addr)->sa_family;
        }
    }
#endif /* _PR_HAVE_SOCKADDR_LEN */
    return(rv);
}



static PRInt32 PR_CALLBACK SocketRecvFrom(PRFileDesc *fd, void *buf, PRInt32 amount,
PRIntn flags, PRNetAddr *addr, PRIntervalTime timeout)
{
    PRInt32 rv;
    PRUint32 al;

    al = sizeof(PRNetAddr);
    rv = _bt_recvfrom(fd, buf, amount, flags, addr, &al, timeout);
#ifdef _PR_INET6
    if (addr && (AF_INET6 == addr->raw.family))
        addr->raw.family = PR_AF_INET6;
#endif
    return rv;
}

static PRInt32 PR_CALLBACK SocketAcceptRead(PRFileDesc *sd, PRFileDesc **nd, 
PRNetAddr **raddr, void *buf, PRInt32 amount,
PRIntervalTime timeout)
{
    /* The socket must be in blocking mode. */
    if (sd->secret->nonblocking) {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return -1;
    }
    *nd = NULL;

    return PR_EmulateAcceptRead(sd, nd, raddr, buf, amount, timeout);
}


static PRInt32 PR_CALLBACK SocketSendFile(
    PRFileDesc *sd, PRSendFileData *sfd,
    PRTransmitFileFlags flags, PRIntervalTime timeout)
{
    /* The socket must be in blocking mode. */
    if (sd->secret->nonblocking) {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return -1;
    }
    return PR_EmulateSendFile(sd, sfd, flags, timeout);
}

static PRInt32 PR_CALLBACK SocketTransmitFile(PRFileDesc *sd, PRFileDesc *fd, 
const void *headers, PRInt32 hlen, PRTransmitFileFlags flags,
PRIntervalTime timeout)
{
    PRSendFileData sfd;

    sfd.fd = fd;
    sfd.file_offset = 0;
    sfd.file_nbytes = 0;
    sfd.header = headers;
    sfd.hlen = hlen;
    sfd.trailer = NULL;
    sfd.tlen = 0;

    return(SocketSendFile(sd, &sfd, flags, timeout));
}

static PRStatus PR_CALLBACK SocketGetName(PRFileDesc *fd, PRNetAddr *addr)
{
    PRInt32 result, err;
    PRUint32 addrlen;

    addrlen = sizeof(PRNetAddr);
    result = getsockname(fd->secret->md.osfd, (struct sockaddr *) addr, &addrlen);
    if (result < 0) {
        err = _MD_ERRNO();
               set_getsockname_error(err);
        return PR_FAILURE;
    }
#ifdef _PR_HAVE_SOCKADDR_LEN
    if (result == 0) {
        /* ignore the sa_len field of struct sockaddr */
        if (addr) {
            addr->raw.family = ((struct sockaddr *) addr)->sa_family;
        }
    }
#endif /* _PR_HAVE_SOCKADDR_LEN */

#ifdef _PR_INET6
    if (AF_INET6 == addr->raw.family)
        addr->raw.family = PR_AF_INET6;
#endif
    PR_ASSERT(IsValidNetAddr(addr) == PR_TRUE);
    PR_ASSERT(IsValidNetAddrLen(addr, addrlen) == PR_TRUE);
    return PR_SUCCESS;
}

static PRStatus PR_CALLBACK SocketGetPeerName(PRFileDesc *fd, PRNetAddr *addr)
{
    PRInt32 result, err;
    PRUint32 addrlen;

    addrlen = sizeof(PRNetAddr);
    result = getpeername(fd->secret->md.osfd, (struct sockaddr *) addr, &addrlen);
    if (result < 0) {
        err = _MD_ERRNO();
        set_getpeername_error(err);
        return PR_FAILURE;
    }
#ifdef _PR_HAVE_SOCKADDR_LEN
    if (result == 0) {
        /* ignore the sa_len field of struct sockaddr */
        if (addr) {
            addr->raw.family = ((struct sockaddr *) addr)->sa_family;
        }
    }
#endif /* _PR_HAVE_SOCKADDR_LEN */
    
#ifdef _PR_INET6
    if (AF_INET6 == addr->raw.family)
        addr->raw.family = PR_AF_INET6;
#endif
    PR_ASSERT(IsValidNetAddr(addr) == PR_TRUE);
    PR_ASSERT(IsValidNetAddrLen(addr, addrlen) == PR_TRUE);
    return PR_SUCCESS;
}

static PRInt16 PR_CALLBACK SocketPoll(
    PRFileDesc *fd, PRInt16 in_flags, PRInt16 *out_flags)
{
    *out_flags = 0;
    return in_flags;
}  /* SocketPoll */


PRStatus PR_CALLBACK SocketGetOption(PRFileDesc *fd, PRSocketOptionData *data)
{
    PRStatus rv;
    PRInt32 level, name, length, err;

    /*
     * PR_SockOpt_Nonblocking is a special case that does not
     * translate to a getsockopt() call
     */
    if (PR_SockOpt_Nonblocking == data->option)
    {
        data->value.non_blocking = fd->secret->nonblocking;
        return PR_SUCCESS;
    }

    rv = _PR_MapOptionName(data->option, &level, &name);
    if (PR_SUCCESS != rv) return rv;
    
    switch (data->option)
    {
        case PR_SockOpt_Linger:
        {
#ifdef BONE_VERSION
            struct linger linger;
            length = sizeof(linger);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char *) &linger, &length))
            {
                PR_ASSERT(sizeof(linger) == length);
                data->value.linger.polarity =
                    (linger.l_onoff) ? PR_TRUE : PR_FALSE;
                data->value.linger.linger =
                    PR_SecondsToInterval(linger.l_linger);
                return PR_SUCCESS;
            }
            break;
#else
                PR_SetError( PR_NOT_IMPLEMENTED_ERROR, 0 );
                return PR_FAILURE;
#endif
        }
        case PR_SockOpt_Reuseaddr:
        case PR_SockOpt_Keepalive:
        case PR_SockOpt_NoDelay:
        case PR_SockOpt_Broadcast:
        {
            PRIntn value;
            length = sizeof(value);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char *) &value, &length))
            {
                data->value.reuse_addr = (0 == value) ? PR_FALSE : PR_TRUE;
                return PR_SUCCESS;
            }        
            break;
        }
        case PR_SockOpt_McastLoopback:
        {
            PRUint8 bool;
            length = sizeof(bool);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char*)&bool, &length))
            {
                data->value.mcast_loopback = (0 == bool) ? PR_FALSE : PR_TRUE;
                return PR_SUCCESS;
            }
            break;
        }
        case PR_SockOpt_RecvBufferSize:
        case PR_SockOpt_SendBufferSize:
        case PR_SockOpt_MaxSegment:
        {
            PRIntn value;
            length = sizeof(value);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char*)&value, &length))
            {
                data->value.recv_buffer_size = value;
                return PR_SUCCESS;
            }
            break;
        }
        case PR_SockOpt_IpTimeToLive:
        case PR_SockOpt_IpTypeOfService:
        {
            /* These options should really be an int (or PRIntn). */
            length = sizeof(PRUintn);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char*)&data->value.ip_ttl, &length))
                return PR_SUCCESS;
            break;
        }
        case PR_SockOpt_McastTimeToLive:
        {
            PRUint8 ttl;
            length = sizeof(ttl);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char*)&ttl, &length))
            {
                data->value.mcast_ttl = ttl;
                return PR_SUCCESS;
            }
            break;
        }
#ifdef IP_ADD_MEMBERSHIP
        case PR_SockOpt_AddMember:
        case PR_SockOpt_DropMember:
        {
            struct ip_mreq mreq;
            length = sizeof(mreq);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name, (char*)&mreq, &length))
            {
                data->value.add_member.mcaddr.inet.ip =
                    mreq.imr_multiaddr.s_addr;
                data->value.add_member.ifaddr.inet.ip =
                    mreq.imr_interface.s_addr;
                return PR_SUCCESS;
            }
            break;
        }
#endif /* IP_ADD_MEMBERSHIP */
        case PR_SockOpt_McastInterface:
        {
            /* This option is a struct in_addr. */
            length = sizeof(data->value.mcast_if.inet.ip);
            if (0 == getsockopt(
                fd->secret->md.osfd, level, name,
                (char*)&data->value.mcast_if.inet.ip, &length))
                return PR_SUCCESS;
            break;
        }
        default:
            PR_NOT_REACHED("Unknown socket option");
            break;
    }  
    err = _MD_ERRNO();
    set_getsockopt_error(err);
    return PR_FAILURE;
}  /* SocketGetOption */

PRStatus PR_CALLBACK SocketSetOption(PRFileDesc *fd, const PRSocketOptionData *data)
{
    PRStatus rv;
    PRInt32 level, name, result, err;

    /*
     * PR_SockOpt_Nonblocking is a special case that does not
     * translate to a setsockopt call.
     */
    if (PR_SockOpt_Nonblocking == data->option)
    {
        fd->secret->nonblocking = data->value.non_blocking;
        return PR_SUCCESS;
    }
    
    rv = _PR_MapOptionName(data->option, &level, &name);
    if (PR_SUCCESS != rv) return rv;

    switch (data->option)
    {
        case PR_SockOpt_Linger:
        {
#ifdef BONE_VERSION
            struct linger linger;
            linger.l_onoff = data->value.linger.polarity;
            linger.l_linger = PR_IntervalToSeconds(data->value.linger.linger);
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&linger, sizeof(linger));
            break;
#else
            PR_SetError( PR_NOT_IMPLEMENTED_ERROR, 0 );
            return PR_FAILURE;
#endif
        }
        case PR_SockOpt_Reuseaddr:
        case PR_SockOpt_Keepalive:
        case PR_SockOpt_NoDelay:
        case PR_SockOpt_Broadcast:
        {
            PRIntn value;
            value = (data->value.reuse_addr) ? 1 : 0;
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&value, sizeof(value));
            break;
        }
        case PR_SockOpt_McastLoopback:
        {
            PRUint8 bool;
            bool = data->value.mcast_loopback ? 1 : 0;
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&bool, sizeof(bool));
            break;
        }
        case PR_SockOpt_RecvBufferSize:
        case PR_SockOpt_SendBufferSize:
        case PR_SockOpt_MaxSegment:
        {
            PRIntn value = data->value.recv_buffer_size;
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&value, sizeof(value));
            break;
        }
        case PR_SockOpt_IpTimeToLive:
        case PR_SockOpt_IpTypeOfService:
        {
            /* These options should really be an int (or PRIntn). */
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&data->value.ip_ttl, sizeof(PRUintn));
            break;
        }
        case PR_SockOpt_McastTimeToLive:
        {
            PRUint8 ttl;
            ttl = data->value.mcast_ttl;
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&ttl, sizeof(ttl));
            break;
        }
#ifdef IP_ADD_MEMBERSHIP
        case PR_SockOpt_AddMember:
        case PR_SockOpt_DropMember:
        {
            struct ip_mreq mreq;
            mreq.imr_multiaddr.s_addr =
                data->value.add_member.mcaddr.inet.ip;
            mreq.imr_interface.s_addr =
                data->value.add_member.ifaddr.inet.ip;
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&mreq, sizeof(mreq));
            break;
        }
#endif /* IP_ADD_MEMBERSHIP */
        case PR_SockOpt_McastInterface:
        {
            /* This option is a struct in_addr. */
            result = setsockopt(
                fd->secret->md.osfd, level, name, (char*)&data->value.mcast_if.inet.ip,
                sizeof(data->value.mcast_if.inet.ip));
            break;
        }
        default:
            PR_NOT_REACHED("Unknown socket option");
            break;
    }
    if (0 == result)
        return PR_SUCCESS;
    err = _MD_ERRNO();
    set_setsockopt_error(err);
    return PR_FAILURE;
}  /* SocketSetOption */



static PRIOMethods tcpMethods = {
    PR_DESC_SOCKET_TCP,
    SocketClose,
    SocketRead,
    SocketWrite,
    SocketAvailable,
    SocketAvailable64,
    SocketSync,
    (PRSeekFN)_PR_InvalidInt,
    (PRSeek64FN)_PR_InvalidInt64,
    (PRFileInfoFN)_PR_InvalidStatus,
    (PRFileInfo64FN)_PR_InvalidStatus,
    SocketWritev,
    SocketConnect,
    SocketAccept,
    SocketBind,
    SocketListen,
    SocketShutdown,
    SocketRecv,
    SocketSend,
    (PRRecvfromFN)_PR_InvalidInt,
    (PRSendtoFN)_PR_InvalidInt,
    SocketPoll,
    SocketAcceptRead,
    SocketTransmitFile,
    SocketGetName,
    SocketGetPeerName,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    SocketGetOption,
    SocketSetOption,
    SocketSendFile, 
    SocketConnectContinue,
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt
};

static PRIOMethods udpMethods = {
    PR_DESC_SOCKET_UDP,
    SocketClose,
    SocketRead,
    SocketWrite,
    SocketAvailable,
    SocketAvailable64,
    SocketSync,
    (PRSeekFN)_PR_InvalidInt,
    (PRSeek64FN)_PR_InvalidInt64,
    (PRFileInfoFN)_PR_InvalidStatus,
    (PRFileInfo64FN)_PR_InvalidStatus,
    SocketWritev,
    SocketConnect,
    (PRAcceptFN)_PR_InvalidDesc,
    SocketBind,
    SocketListen,
    SocketShutdown,
    SocketRecv,
    SocketSend,
    SocketRecvFrom,
    SocketSendTo,
    SocketPoll,
    (PRAcceptreadFN)_PR_InvalidInt,
    (PRTransmitfileFN)_PR_InvalidInt,
    SocketGetName,
    SocketGetPeerName,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    SocketGetOption,
    SocketSetOption,
    (PRSendfileFN)_PR_InvalidInt, 
    (PRConnectcontinueFN)_PR_InvalidStatus, 
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt, 
    (PRReservedFN)_PR_InvalidInt
};


static PRIOMethods socketpollfdMethods = {
    (PRDescType) 0,
    (PRCloseFN)_PR_InvalidStatus,
    (PRReadFN)_PR_InvalidInt,
    (PRWriteFN)_PR_InvalidInt,
    (PRAvailableFN)_PR_InvalidInt,
    (PRAvailable64FN)_PR_InvalidInt64,
    (PRFsyncFN)_PR_InvalidStatus,
    (PRSeekFN)_PR_InvalidInt,
    (PRSeek64FN)_PR_InvalidInt64,
    (PRFileInfoFN)_PR_InvalidStatus,
    (PRFileInfo64FN)_PR_InvalidStatus,
    (PRWritevFN)_PR_InvalidInt,
    (PRConnectFN)_PR_InvalidStatus,
    (PRAcceptFN)_PR_InvalidDesc,
    (PRBindFN)_PR_InvalidStatus,
    (PRListenFN)_PR_InvalidStatus,
    (PRShutdownFN)_PR_InvalidStatus,
    (PRRecvFN)_PR_InvalidInt,
    (PRSendFN)_PR_InvalidInt,
    (PRRecvfromFN)_PR_InvalidInt,
    (PRSendtoFN)_PR_InvalidInt,
    SocketPoll,
    (PRAcceptreadFN)_PR_InvalidInt,
    (PRTransmitfileFN)_PR_InvalidInt,
    (PRGetsocknameFN)_PR_InvalidStatus,
    (PRGetpeernameFN)_PR_InvalidStatus,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRGetsocketoptionFN)_PR_InvalidStatus,
    (PRSetsocketoptionFN)_PR_InvalidStatus,
    (PRSendfileFN)_PR_InvalidInt,
    (PRConnectcontinueFN)_PR_InvalidStatus,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt
};

static PRIOMethods _pr_socketpollfd_methods = {
    (PRDescType) 0,
    (PRCloseFN)_PR_InvalidStatus,
    (PRReadFN)_PR_InvalidInt,
    (PRWriteFN)_PR_InvalidInt,
    (PRAvailableFN)_PR_InvalidInt,
    (PRAvailable64FN)_PR_InvalidInt64,
    (PRFsyncFN)_PR_InvalidStatus,
    (PRSeekFN)_PR_InvalidInt,
    (PRSeek64FN)_PR_InvalidInt64,
    (PRFileInfoFN)_PR_InvalidStatus,
    (PRFileInfo64FN)_PR_InvalidStatus,
    (PRWritevFN)_PR_InvalidInt,
    (PRConnectFN)_PR_InvalidStatus,
    (PRAcceptFN)_PR_InvalidDesc,
    (PRBindFN)_PR_InvalidStatus,
    (PRListenFN)_PR_InvalidStatus,
    (PRShutdownFN)_PR_InvalidStatus,
    (PRRecvFN)_PR_InvalidInt,
    (PRSendFN)_PR_InvalidInt,
    (PRRecvfromFN)_PR_InvalidInt,
    (PRSendtoFN)_PR_InvalidInt,
    SocketPoll,
    (PRAcceptreadFN)_PR_InvalidInt,
    (PRTransmitfileFN)_PR_InvalidInt,
    (PRGetsocknameFN)_PR_InvalidStatus,
    (PRGetpeernameFN)_PR_InvalidStatus,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRGetsocketoptionFN)_PR_InvalidStatus,
    (PRSetsocketoptionFN)_PR_InvalidStatus,
    (PRSendfileFN)_PR_InvalidInt,
    (PRConnectcontinueFN)_PR_InvalidStatus,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt,
    (PRReservedFN)_PR_InvalidInt
};

PR_IMPLEMENT(const PRIOMethods*) PR_GetTCPMethods()
{
    return &tcpMethods;
}

PR_IMPLEMENT(const PRIOMethods*) PR_GetUDPMethods()
{
    return &udpMethods;
}

static const PRIOMethods* PR_GetSocketPollFdMethods(void)
{
    return &_pr_socketpollfd_methods;
}  /* PR_GetSocketPollFdMethods */

PR_IMPLEMENT(PRInt32) PR_Poll(PRPollDesc *pds, PRIntn npds, PRIntervalTime timeout)
{
    PRInt32 rv = 0;
    /*
     * This code is almost a duplicate of w32poll.c's _PR_MD_PR_POLL().
     */
    fd_set rd, wt, ex;
    PRFileDesc *bottom;
    PRPollDesc *pd, *epd;
    PRInt32 maxfd = -1, ready, err;
    PRIntervalTime remaining, elapsed, start;

    struct timeval tv, *tvp = NULL;

    if (0 == npds) {
        PR_Sleep(timeout);
        return rv;
    }

    FD_ZERO(&rd);
    FD_ZERO(&wt);
    FD_ZERO(&ex);

    ready = 0;
    for (pd = pds, epd = pd + npds; pd < epd; pd++)
    {
        PRInt16 in_flags_read = 0, in_flags_write = 0;
        PRInt16 out_flags_read = 0, out_flags_write = 0; 
        
        if ((NULL != pd->fd) && (0 != pd->in_flags))
        {
            if (pd->in_flags & PR_POLL_READ)
            {
                in_flags_read = (pd->fd->methods->poll)(pd->fd, pd->in_flags & ~PR_POLL_WRITE, &out_flags_read);
            }
            if (pd->in_flags & PR_POLL_WRITE)
            {
                in_flags_write = (pd->fd->methods->poll)(pd->fd, pd->in_flags & ~PR_POLL_READ, &out_flags_write);
            }
            if ((0 != (in_flags_read & out_flags_read))
                || (0 != (in_flags_write & out_flags_write)))
            {
                /* this one's ready right now */
                if (0 == ready)
                {
                    /*
                     * We will have to return without calling the
                     * system poll/select function.  So zero the
                     * out_flags fields of all the poll descriptors
                     * before this one. 
                     */
                    PRPollDesc *prev;
                    for (prev = pds; prev < pd; prev++)
                    {
                        prev->out_flags = 0;
                    }
                }
                ready += 1;
                pd->out_flags = out_flags_read | out_flags_write;
            }
            else
            {
                pd->out_flags = 0;  /* pre-condition */
                
                /* make sure this is an NSPR supported stack */
                bottom = PR_GetIdentitiesLayer(pd->fd, PR_NSPR_IO_LAYER);
                PR_ASSERT(NULL != bottom);  /* what to do about that? */
                if ((NULL != bottom)
                    && (_PR_FILEDESC_OPEN == bottom->secret->state))
                {
                    if (0 == ready)
                    {
                        PRInt32 osfd = bottom->secret->md.osfd; 
                        if (osfd > maxfd) maxfd = osfd;
                        if (in_flags_read & PR_POLL_READ)
                        {
                            pd->out_flags |= _PR_POLL_READ_SYS_READ;
                            FD_SET(osfd, &rd);
                        }
                        if (in_flags_read & PR_POLL_WRITE)
                        {
                            pd->out_flags |= _PR_POLL_READ_SYS_WRITE;
                            FD_SET(osfd, &wt);
                        }
                        if (in_flags_write & PR_POLL_READ)
                        {
                            pd->out_flags |= _PR_POLL_WRITE_SYS_READ;
                            FD_SET(osfd, &rd);
                        }
                        if (in_flags_write & PR_POLL_WRITE)
                        {
                            pd->out_flags |= _PR_POLL_WRITE_SYS_WRITE;
                            FD_SET(osfd, &wt);
                        }
                        if (pd->in_flags & PR_POLL_EXCEPT) FD_SET(osfd, &ex);
                    }
                }
                else
                {
                    if (0 == ready)
                    {
                        PRPollDesc *prev;
                        for (prev = pds; prev < pd; prev++)
                        {
                            prev->out_flags = 0;
                        }
                    }
                    ready += 1;  /* this will cause an abrupt return */
                    pd->out_flags = PR_POLL_NVAL;  /* bogii */
                }
            }
        }
        else
        {
            pd->out_flags = 0;
        }
    }

    if (0 != ready) return ready;  /* no need to block */

    remaining = timeout;
    start = PR_IntervalNow(); 

 retry:
    if (timeout != PR_INTERVAL_NO_TIMEOUT)
    {
        PRInt32 ticksPerSecond = PR_TicksPerSecond();
        tv.tv_sec = remaining / ticksPerSecond;
        tv.tv_usec = PR_IntervalToMicroseconds( remaining % ticksPerSecond );
        tvp = &tv;
    }
    
    ready = select(maxfd + 1, &rd, &wt, &ex, tvp);
    
    if (ready == -1 && errno == EINTR)
    {
        if (timeout == PR_INTERVAL_NO_TIMEOUT) goto retry;
        else
        {
            elapsed = (PRIntervalTime) (PR_IntervalNow() - start);
            if (elapsed > timeout) ready = 0;  /* timed out */
            else
            {
                remaining = timeout - elapsed;
                goto retry; 
            }
        }
    } 

    /*
    ** Now to unravel the select sets back into the client's poll
    ** descriptor list. Is this possibly an area for pissing away
    ** a few cycles or what?
    */
    if (ready > 0)
    {
        ready = 0;
        for (pd = pds, epd = pd + npds; pd < epd; pd++)
        {
            PRInt16 out_flags = 0;
            if ((NULL != pd->fd) && (0 != pd->in_flags))
            {
                PRInt32 osfd;
                bottom = PR_GetIdentitiesLayer(pd->fd, PR_NSPR_IO_LAYER);
                PR_ASSERT(NULL != bottom);
                
                osfd = bottom->secret->md.osfd; 
                
                if (FD_ISSET(osfd, &rd))
                {
                    if (pd->out_flags & _PR_POLL_READ_SYS_READ)
                        out_flags |= PR_POLL_READ;
                    if (pd->out_flags & _PR_POLL_WRITE_SYS_READ)
                        out_flags |= PR_POLL_WRITE;
                }
                if (FD_ISSET(osfd, &wt))
                {
                    if (pd->out_flags & _PR_POLL_READ_SYS_WRITE)
                        out_flags |= PR_POLL_READ;
                    if (pd->out_flags & _PR_POLL_WRITE_SYS_WRITE)
                        out_flags |= PR_POLL_WRITE;
                }
                if (FD_ISSET(osfd, &ex)) out_flags |= PR_POLL_EXCEPT;

/* Workaround for nonblocking connects under net_server */
#ifndef BONE_VERSION         
                if (out_flags)
                {
                    /* check if it is a pending connect */
                    int i = 0, j = 0;
                    PR_Lock( _connectLock );
                    for( i = 0; i < connectCount; i++ ) 
                    {
                        if(connectList[i].osfd == osfd)
                        {
                            int connectError;
                            int connectResult;

                            connectResult = connect(connectList[i].osfd,
                                                    &connectList[i].addr,
                                                    connectList[i].addrlen);
                            connectError = errno;

                            if(connectResult < 0 ) 
                            {
                                if(connectError == EINTR || connectError == EWOULDBLOCK ||
                                 connectError == EINPROGRESS || connectError == EALREADY)
                                {
                                    break;
                                }
                            }

                            if(i == (connectCount - 1))
                            {
                                connectList[i].osfd = -1;
                            } else {
                                for(j = i; j < connectCount; j++ )
                                {
                                    memcpy( &connectList[j], &connectList[j+1],
                                            sizeof(connectList[j]));
                                }
                            }
                            connectCount--;

                            bottom->secret->md.connectReturnValue = connectResult;
                            bottom->secret->md.connectReturnError = connectError;
                            bottom->secret->md.connectValueValid = PR_TRUE;
                            break;
                        }
                    }
                    PR_Unlock( _connectLock );
                }
#endif
            }
            pd->out_flags = out_flags;
            if (out_flags) ready++;
        }
        PR_ASSERT(ready > 0);
    }
    else if (ready < 0)
    { 
        err = _MD_ERRNO();
        if (err == EBADF)
        {
            /* Find the bad fds */
            ready = 0;
            for (pd = pds, epd = pd + npds; pd < epd; pd++)
            {
                pd->out_flags = 0;
                if ((NULL != pd->fd) && (0 != pd->in_flags))
                {
                    bottom = PR_GetIdentitiesLayer(pd->fd, PR_NSPR_IO_LAYER);
                    if (fcntl(bottom->secret->md.osfd, F_GETFL, 0) == -1)
                    {
                        pd->out_flags = PR_POLL_NVAL;
                        ready++;
                    }
                }
            }
            PR_ASSERT(ready > 0);
        }
        else set_select_error(err);
    }
    
    return ready;
}  /* PR_POLL */

PR_IMPLEMENT(PRFileDesc*) PR_CreateSocketPollFd(PRInt32 osfd)
{
    PRFileDesc *fd;

    if (!_pr_initialized) _PR_ImplicitInitialization();

    fd = _PR_Getfd();

    if (fd == NULL) PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
    else
    {
        fd->secret->md.osfd = osfd;
        fd->secret->inheritable = _PR_TRI_FALSE;
        fd->secret->state = _PR_FILEDESC_OPEN;
        fd->methods = PR_GetSocketPollFdMethods();
    }

    return fd;
}  /* PR_CreateSocketPollFD */

PR_IMPLEMENT(PRStatus) PR_DestroySocketPollFd(PRFileDesc *fd)
{
    if (NULL == fd)
    {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }
    fd->secret->state = _PR_FILEDESC_CLOSED;
    _PR_Putfd(fd);
    return PR_SUCCESS;
}  /* PR_DestroySocketPollFd */


PR_IMPLEMENT(PRFileDesc *) PR_ImportTCPSocket(PRInt32 osfd)
{
    PRFileDesc *fd;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    fd = bt_CreateFileDesc(osfd, PR_GetTCPMethods(), _PR_TRI_UNKNOWN, true);
    if (fd == NULL)
        closesocket(osfd);
    return(fd);
}

PR_IMPLEMENT(PRFileDesc *) PR_ImportUDPSocket(PRInt32 osfd)
{
    PRFileDesc *fd;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    fd = bt_CreateFileDesc(osfd, PR_GetUDPMethods(), _PR_TRI_UNKNOWN, true);
    if (fd == NULL)
        closesocket(osfd);
    return(fd);
}


#ifndef XP_HAIKU
int socketpair (int family, int type, int protocol, int sv[2])
{
    int insock, outsock, acceptedsock;
    struct sockaddr_in addrs[2];
    int alen;
    /* that's really only so we can build... */
    /*fprintf(stderr, "socketpair(%d, %d, %d)\n", family, type, protocol);*/
    if (family != AF_INET) {
        /*fatal*/fprintf(stderr, "socketpair(%d, %d, %d): family not supported\n", family, type, protocol);
        errno = EPFNOSUPPORT;
        return -1;
    }
    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        errno = EPROTONOSUPPORT;
        return -1;
    }
    addrs[0].sin_family = AF_INET;
    addrs[0].sin_port = 0;
    addrs[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addrs[1].sin_family = AF_INET;
    addrs[1].sin_port = 0;
    addrs[1].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    alen = sizeof(struct sockaddr_in);

    insock = socket(family, type, protocol);
    if (insock < 0)
        goto err1;
    if (bind(insock, (struct sockaddr *)&addrs[0], alen) < 0)
        goto err2;
    if (getsockname(insock, (struct sockaddr *)&addrs[0], &alen) < 0)
        goto err2;
    if (type == SOCK_STREAM)
        listen(insock, 2);

    outsock = socket(family, type, protocol);
    if (outsock < 0)
        goto err2;
    alen = sizeof(struct sockaddr_in);
    if (bind(outsock, (struct sockaddr *)&addrs[1], alen) < 0)
        goto err2;
    if (getsockname(outsock, (struct sockaddr *)&addrs[1], &alen) < 0)
        goto err3;
    addrs[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addrs[1].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    /*fprintf(stderr, "socketpair: %08lx:%d <-> %08lx:%d\n", 
        ((struct sockaddr_in *)&addrs[0])->sin_addr.s_addr,
        ((struct sockaddr_in *)&addrs[0])->sin_port,
        ((struct sockaddr_in *)&addrs[1])->sin_addr.s_addr,
        ((struct sockaddr_in *)&addrs[1])->sin_port);*/

    if (connect(outsock, (struct sockaddr *)&addrs[0], alen) < 0)
        goto err3;
    if (type == SOCK_DGRAM) {
        if (connect(insock, (struct sockaddr *)&addrs[1], alen) < 0)
            goto err3;
        sv[0] = insock;
    } else {
        acceptedsock = accept(insock, (struct sockaddr *)&addrs[1], &alen);
        if (acceptedsock < 0)
            goto err3;
        closesocket(insock);
        sv[0] = acceptedsock;
    }
    sv[1] = outsock;
    return 0;
err3:
    closesocket(outsock);
err2:
    closesocket(insock);
err1:
    fprintf(stderr,"socketpair: error 0x%08x\n", errno);
    return -1;
}
#endif

PR_IMPLEMENT(PRStatus) PR_NewTCPSocketPair(PRFileDesc *f[])
{
    PRInt32 rv, osfd[2];

    if (!_pr_initialized) _PR_ImplicitInitialization();
#ifdef XP_HAIKU
    rv = socketpair(AF_UNIX, SOCK_STREAM, 0, osfd);
#else
    rv = socketpair(AF_INET, SOCK_STREAM, 0, osfd);
#endif
    if (rv == -1) {
        return PR_FAILURE;
    }
    f[0] = bt_CreateFileDesc(osfd[0], PR_GetTCPMethods(), _PR_TRI_TRUE, true);
    if (NULL == f[0]) {
        closesocket(osfd[0]);
        closesocket(osfd[1]);
        /* PR_AllocFileDesc() has invoked PR_SetError(). */
        return PR_FAILURE;
    }
    f[1] = bt_CreateFileDesc(osfd[1], PR_GetTCPMethods(), _PR_TRI_TRUE, true);
    if (NULL == f[1]) {
        PR_Close(f[0]);
        closesocket(osfd[1]);
        /* PR_AllocFileDesc() has invoked PR_SetError(). */
        return PR_FAILURE;
    }
    return PR_SUCCESS;
}


PR_IMPLEMENT(PRStatus) PR_GetConnectStatus(const PRPollDesc *pd) {
    PRInt32 osfd;
#ifndef BONE_VERSION
    int rv;
#endif
    PRFileDesc *bottom;

    if (pd->out_flags & PR_POLL_NVAL) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }

    if ((pd->out_flags & (PR_POLL_WRITE | PR_POLL_EXCEPT | PR_POLL_ERR)) == 0) {
        PR_ASSERT(pd->out_flags == 0);
        PR_SetError(PR_IN_PROGRESS_ERROR, 0);
        return PR_FAILURE;
    }


    /* Find the NSPR layer and invoke its connectcontinue method */
    bottom = PR_GetIdentitiesLayer(pd->fd, PR_NSPR_IO_LAYER);
    if (NULL == bottom) 
    {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return PR_FAILURE;
    }

    osfd = bottom->secret->md.osfd;
#ifdef BONE_VERSION  /* bug 122364 */
    /* temporary workaround until getsockopt(SO_ERROR) works in BONE */
    if (pd->out_flags & PR_POLL_EXCEPT) {
        PR_SetError(PR_CONNECT_REFUSED_ERROR, 0);
        return PR_FAILURE;
    }
    PR_ASSERT(pd->out_flags & PR_POLL_WRITE);
    return PR_SUCCESS;
#else
    rv = recv(bottom->secret->md.osfd, NULL, 0, 0);
    PR_ASSERT(-1 == rv || 0 == rv);

    if (-1 == rv && 0 != errno && errno != EAGAIN && errno != EWOULDBLOCK ) {
        set_connect_error(errno);
        return PR_FAILURE;
    }
    else
        return PR_SUCCESS;
#endif /* BONE_VERSION */
}

PR_IMPLEMENT(PRFileDesc*) PR_Socket(PRInt32 domain, PRInt32 type, PRInt32 proto)
{
    PRInt32 osfd, err;
    PRFileDesc *fd;
    PRInt32 tmp_domain = domain;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    if (PR_AF_INET != domain
        && PR_AF_INET6 != domain
    ) {
        PR_SetError(PR_ADDRESS_NOT_SUPPORTED_ERROR, 0);
        return NULL;
    }
    if( type != SOCK_STREAM && type != SOCK_DGRAM )
    {
        PR_SetError(PR_ADDRESS_NOT_SUPPORTED_ERROR, 0);
        return NULL;
    }

#if defined(_PR_INET6_PROBE)
    if (PR_AF_INET6 == domain) {
        if (_pr_ipv6_is_present == PR_FALSE) 
            domain = AF_INET;
        else
            domain = AF_INET6;
    }
#elif defined(_PR_INET6)
    if (PR_AF_INET6 == domain)
        domain = AF_INET6;
#else
    if (PR_AF_INET6 == domain)
        domain = AF_INET;
#endif    /* _PR_INET6 */
#ifndef BONE_VERSION
    osfd = socket(domain, type, 0);
#else
    osfd = socket(domain, type, proto);
#endif
    if (osfd == -1) {
        err = _MD_ERRNO();
        set_socket_error(err);
        return 0;
    }
    fd = bt_CreateFileDesc(osfd, SOCK_STREAM == type?PR_GetTCPMethods() : PR_GetUDPMethods(), _PR_TRI_TRUE, true);

    if (fd != NULL) {
#if defined(_PR_INET6_PROBE) || !defined(_PR_INET6)
        /*
         * For platforms with no support for IPv6 
         * create layered socket for IPv4-mapped IPv6 addresses
         */
        if (PR_AF_INET6 == tmp_domain && PR_AF_INET == domain) {
            if (PR_FAILURE == _pr_push_ipv6toipv4_layer(fd)) {
                PR_Close(fd);
                fd = NULL;
            }
        }
#endif
    } else
        closesocket(osfd);

    return fd;
}


PR_IMPLEMENT(PRFileDesc *) PR_NewTCPSocket(void)
{
    return PR_Socket(AF_INET, SOCK_STREAM, 0);
}

PR_IMPLEMENT(PRFileDesc*) PR_NewUDPSocket(void)
{
    return PR_Socket(AF_INET, SOCK_DGRAM, 0);
}

PR_IMPLEMENT(PRFileDesc *) PR_OpenTCPSocket(PRIntn af)
{
    return PR_Socket(af, SOCK_STREAM, 0);
}

PR_IMPLEMENT(PRFileDesc*) PR_OpenUDPSocket(PRIntn af)
{
    return PR_Socket(af, SOCK_DGRAM, 0);
}

