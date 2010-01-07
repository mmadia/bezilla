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
 *   Roy Yokoyama <yokoyama@netscape.com>
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

static PRLock *_pr_flock_lock;  /* For PR_LockFile() etc. */
static PRCondVar *_pr_flock_cv;  /* For PR_LockFile() etc. */

PRErrorCode
map_default_error(int err)
{
    switch (err) {
        case EACCES:
            return PR_NO_ACCESS_RIGHTS_ERROR;
        case EADDRINUSE:
            return PR_ADDRESS_IN_USE_ERROR;
        case EADDRNOTAVAIL:
            return PR_ADDRESS_NOT_AVAILABLE_ERROR;
        case EAFNOSUPPORT:
            return PR_ADDRESS_NOT_SUPPORTED_ERROR;
        /*Same as EWOULDBLOCK*/
        case EAGAIN:
            return PR_WOULD_BLOCK_ERROR;
#if EALREADY != EBUSY
        case EALREADY:
            return PR_ALREADY_INITIATED_ERROR;
#endif
        case EBADF:
            return PR_BAD_DESCRIPTOR_ERROR;
        case EBUSY:
            return PR_FILESYSTEM_MOUNTED_ERROR;
        case ECONNABORTED:
            return PR_CONNECT_ABORTED_ERROR;
        case ECONNREFUSED:
            return PR_CONNECT_REFUSED_ERROR;
        case EDEADLK:
            return PR_DEADLOCK_ERROR;
        case EEXIST:
            return PR_FILE_EXISTS_ERROR;
        case EFAULT:
            return PR_ACCESS_FAULT_ERROR;
        case EFBIG:
            return PR_FILE_TOO_BIG_ERROR;
        case EHOSTUNREACH:
            return PR_HOST_UNREACHABLE_ERROR;
        case EINPROGRESS:
            return PR_IN_PROGRESS_ERROR;
        case EINTR:
            return PR_PENDING_INTERRUPT_ERROR;
        case EINVAL:
            return PR_INVALID_ARGUMENT_ERROR;
        case EIO:
            return PR_IO_ERROR;
        case EISCONN:
            return PR_IS_CONNECTED_ERROR;
        case EISDIR:
            return PR_IS_DIRECTORY_ERROR;
        case ELOOP:
            return PR_LOOP_ERROR;
        case EMFILE:
            return PR_PROC_DESC_TABLE_FULL_ERROR;
        case EMLINK:
            return PR_MAX_DIRECTORY_ENTRIES_ERROR;
        case EMSGSIZE:
            return PR_INVALID_ARGUMENT_ERROR;
        case ENAMETOOLONG:
            return PR_NAME_TOO_LONG_ERROR;
        case ENETUNREACH:
            return PR_NETWORK_UNREACHABLE_ERROR;
        case ENFILE:
            return PR_SYS_DESC_TABLE_FULL_ERROR;
        case ENOBUFS:
            return PR_INSUFFICIENT_RESOURCES_ERROR;
        case ENODEV:
        case ENOENT:
            return PR_FILE_NOT_FOUND_ERROR;
        case ENOLCK:
            return PR_FILE_IS_LOCKED_ERROR;
#if 0
        case ENOLINK:
            return PR_REMOTE_FILE_ERROR;
#endif
        case ENOMEM:
            return PR_OUT_OF_MEMORY_ERROR;
        case ENOPROTOOPT:
            return PR_INVALID_ARGUMENT_ERROR;
        case ENOSPC:
            return PR_NO_DEVICE_SPACE_ERROR;
        case ENOTCONN:
            return PR_NOT_CONNECTED_ERROR;
        case ENOTDIR:
            return PR_NOT_DIRECTORY_ERROR;
        case ENOTSOCK:
            return PR_NOT_SOCKET_ERROR;
        case ENXIO:
            return PR_FILE_NOT_FOUND_ERROR;
        case EOPNOTSUPP:
            return PR_NOT_TCP_SOCKET_ERROR;
        case EOVERFLOW:
            return PR_BUFFER_OVERFLOW_ERROR;
        case EPERM:
            return PR_NO_ACCESS_RIGHTS_ERROR;
        case EPIPE:
            return PR_CONNECT_RESET_ERROR;
        case EPROTONOSUPPORT:
            return PR_PROTOCOL_NOT_SUPPORTED_ERROR;
        case EPROTOTYPE:
            return PR_ADDRESS_NOT_SUPPORTED_ERROR;
        case ERANGE:
            return PR_INVALID_METHOD_ERROR;
        case EROFS:
            return PR_READ_ONLY_FILESYSTEM_ERROR;
        case ESPIPE:
            return PR_INVALID_METHOD_ERROR;
        case ETIMEDOUT:
            return PR_IO_TIMEOUT_ERROR;
        case EXDEV:
            return PR_NOT_SAME_DEVICE_ERROR;
        default:
            return PR_UNKNOWN_ERROR;
    }
}


inline void
set_open_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EAGAIN:
        case ENOMEM:
            prError = PR_INSUFFICIENT_RESOURCES_ERROR;
            break;
        case EBUSY:
            prError = PR_IO_ERROR;
            break;
        case ENODEV:
            prError = PR_FILE_NOT_FOUND_ERROR;
            break;
        case EOVERFLOW:
            prError = PR_FILE_TOO_BIG_ERROR;
            break;
        case ETIMEDOUT:
            prError = PR_REMOTE_FILE_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void
set_rename_error(int err)
{
    PR_SetError(err == EEXIST ? PR_DIRECTORY_NOT_EMPTY_ERROR : map_default_error(err), err);
}


inline void
set_unlink_error(int err)
{
    PR_SetError(err == EPERM ? PR_IS_DIRECTORY_ERROR : map_default_error(err), err);
}


inline void 
set_opendir_error(int err)
{
    PR_SetError(map_default_error(err), err);
}

inline void
set_closedir_error(int err)
{
    PR_SetError( err == EINVAL ? PR_BAD_DESCRIPTOR_ERROR : map_default_error(err), err);
}

inline void 
set_readdir_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case 0:
        case ENOENT:
            prError = PR_NO_MORE_FILES_ERROR;
            break;
        case EOVERFLOW:
        case EINVAL:
        case ENXIO:
            prError = PR_IO_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void
set_mkdir_error(int err)
{
    PR_SetError(map_default_error(err), err);
}


inline void
set_rmdir_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case ENOTEMPTY:
        case EEXIST:
        case EINVAL:
            prError = PR_DIRECTORY_NOT_EMPTY_ERROR;
            break;
        case ETIMEDOUT:
            prError = PR_REMOTE_FILE_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void
set_close_error(int err)
{
    PR_SetError( err == ETIMEDOUT ? PR_REMOTE_FILE_ERROR : map_default_error(err), err);
}


inline void
set_read_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_INVALID_METHOD_ERROR;
            break;
        case ENXIO:
            prError = PR_INVALID_ARGUMENT_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void
set_write_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_INVALID_METHOD_ERROR;
            break;
        case ENXIO:
            prError = PR_INVALID_ARGUMENT_ERROR;
            break;
        case ETIMEDOUT:
            prError = PR_REMOTE_FILE_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void 
set_lseek_error(int err)
{
    PR_SetError(map_default_error(err), err);
}


inline void
set_fsync_error(int err)
{
    PRErrorCode prError;
    switch (err) {
        case EINVAL:
            prError = PR_INVALID_METHOD_ERROR;
            break;
        case ETIMEDOUT:
            prError = PR_REMOTE_FILE_ERROR;
            break;
        default:
            prError = map_default_error(err);
    }
    PR_SetError(prError, err);
}


inline void
set_fstat_error(int err)
{
    PR_SetError(err == ETIMEDOUT ? PR_REMOTE_FILE_ERROR : map_default_error(err), err);
}

/* TODO: using uint8 instead of bool due to code that uses bool as var name in hard to change places
   therefore we had to undef it. Or we need to change Haiku's headers around so we can include
   everything we need except the bool decl. */
PRFileDesc * bt_CreateFileDesc(PRIntn osfd, const PRIOMethods * methods, _PRTriStateBool inheritable, uint8 nonblocking) {
    const int blocking = 1;
    PRFileDesc *fd = _PR_Getfd();
    if (fd == NULL)
    {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
        return NULL;
    }
    fd->secret->md.osfd = osfd;
    fd->secret->state = _PR_FILEDESC_OPEN;
    fd->secret->inheritable = inheritable;
    fd->methods = methods;
    if (nonblocking)
        setsockopt(osfd, SOL_SOCKET, SO_NONBLOCK, &blocking, sizeof(blocking));
    return fd;
}


PR_IMPLEMENT(PRFileDesc*) PR_GetSpecialFD(PRSpecialFD osfd)
{
    PR_ASSERT(osfd >= PR_StandardInput && osfd <= PR_StandardError);

    if (!_pr_initialized) _PR_ImplicitInitialization();

    switch (osfd)
    {
        case PR_StandardInput: return _pr_stdin;
        case PR_StandardOutput: return _pr_stdout;
        case PR_StandardError: return _pr_stderr;
        default:
            PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
    }
    return NULL;
}  /* PR_GetSpecialFD */


PR_IMPLEMENT(PRFileDesc*) PR_Open(const char *name, PRIntn flags, PRIntn mode)
{
    return PR_OpenFile(name, flags, mode);
}  /* PR_Open */

PR_IMPLEMENT(PRFileDesc*) PR_OpenFile(const char *name, PRIntn flags, PRIntn mode)
{
    PRFileDesc *fd = NULL;
    PRInt32 osflags;
    PRInt32 osfd, err;

    if (flags & PR_RDWR) {
        osflags = O_RDWR;
    } else if (flags & PR_WRONLY) {
        osflags = O_WRONLY;
    } else {
        osflags = O_RDONLY;
    }

    if (flags & PR_EXCL)
        osflags |= O_EXCL;
    if (flags & PR_APPEND)
        osflags |= O_APPEND;
    if (flags & PR_TRUNCATE)
        osflags |= O_TRUNC;
    if (flags & PR_SYNC) {
/* Ummmm.  BeOS doesn't appear to
   support sync in any way shape or
   form. */
        return PR_NOT_IMPLEMENTED_ERROR;
    }

    if (flags & PR_CREATE_FILE)
    {
        osflags |= O_CREAT;
    }
    
    osfd = open(name, osflags, mode);
    if (osfd < 0) {
        err = _MD_ERRNO();
        set_open_error(err);
    }

    if(osfd>=0) {
        fd = bt_CreateFileDesc(osfd, PR_GetFileMethods(), _PR_TRI_TRUE, false);
        if (fd == NULL) close(osfd);  /* $$$ whoops! this is bad $$$ */
    }
    return fd;
} /* PR_OpenFile */

/*
** Import an existing OS file to NSPR
*/
PR_IMPLEMENT(PRFileDesc*) PR_ImportFile(PRInt32 osfd)
{
    PRFileDesc *fd = NULL;

    if (!_pr_initialized) _PR_ImplicitInitialization();

    fd = bt_CreateFileDesc(osfd, PR_GetFileMethods(), _PR_TRI_UNKNOWN, false);
    if (NULL == fd) close(osfd);
    return fd;
}

/*
** Import an existing OS pipe to NSPR 
*/
PR_IMPLEMENT(PRFileDesc*) PR_ImportPipe(PRInt32 osfd)
{
    PRFileDesc *fd = NULL;

    if (!_pr_initialized) _PR_ImplicitInitialization();
    fd = bt_CreateFileDesc(osfd, PR_GetPipeMethods(), _PR_TRI_UNKNOWN, true);

    if (NULL == fd) close(osfd);
    return fd;
}


PR_IMPLEMENT(PRStatus) PR_Rename(const char *from, const char *to)
{
    PRInt32 rv = -1, err;

    if (0 == access(to, F_OK))
        PR_SetError(PR_FILE_EXISTS_ERROR, 0);
    else
    {
        rv = rename(from, to);
        if (rv < 0) {
            err = _MD_ERRNO();
            set_rename_error(err);
        }
    }
    if (rv < 0) {
        return PR_FAILURE;
    } else {
        return PR_SUCCESS;
    }
}

PR_IMPLEMENT(PRStatus) PR_Delete(const char *name)
{
    PRInt32 rv, err;

    rv = unlink(name);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_unlink_error(err);
        return PR_FAILURE;
    } else
        return PR_SUCCESS;
}


PR_IMPLEMENT(PRDir*) PR_OpenDir(const char *name)
{
    PRDir *dir;
    PRInt32 err;

    dir = PR_NEW(PRDir);
    if (dir) {
        dir->md.d = opendir(name);
        if (NULL == dir->md.d) {
            err = _MD_ERRNO();
            set_opendir_error(err);
            PR_DELETE(dir);
            return NULL;
        }
    } else {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
    }
    return dir;
}

PR_IMPLEMENT(PRDirEntry*) PR_ReadDir(PRDir *dir, PRDirFlags flags)
{
    PRInt32 err;
    struct dirent *de;
    for (;;) {
        /*
         * XXX: readdir() is not MT-safe
         */
        _MD_ERRNO() = 0;
        de = readdir(dir->md.d);

        if (!de) {
            err = _MD_ERRNO();
            set_readdir_error(err);
            return 0;
        }

        if ((flags & PR_SKIP_DOT) &&
            (de->d_name[0] == '.') && (de->d_name[1] == 0))
            continue;

        if ((flags & PR_SKIP_DOT_DOT) &&
            (de->d_name[0] == '.') && (de->d_name[1] == '.') &&
            (de->d_name[2] == 0))
            continue;

        if ((flags & PR_SKIP_HIDDEN) && (de->d_name[1] == '.'))
            continue;

        break;
    }

    dir->d.name = de->d_name;
    return de->d_name ? &dir->d : NULL;
}

PR_IMPLEMENT(PRStatus) PR_CloseDir(PRDir *dir)
{
    PRInt32 rv, err;

    if (dir && dir->md.d) {
        rv = closedir(dir->md.d);
        PR_DELETE(dir);
        if (rv < 0) {
            err = _MD_ERRNO();
            set_closedir_error(err);
            return PR_FAILURE;
        } 
    }
    return PR_SUCCESS;
}

PR_IMPLEMENT(PRStatus) PR_MkDir(const char *name, PRIntn mode)
{
    status_t rv;
    int err;

    rv = mkdir(name, mode);

    if (rv < 0) {
        err = _MD_ERRNO();
        set_mkdir_error(err);
        return PR_FAILURE;
    }
    return PR_SUCCESS; 
}

PR_IMPLEMENT(PRStatus) PR_MakeDir(const char *name, PRIntn mode)
{
    if (!_pr_initialized) _PR_ImplicitInitialization();
    return PR_MkDir(name, mode);
}

PR_IMPLEMENT(PRStatus) PR_RmDir(const char *name)
{
    PRInt32 rv, err;

    rv = rmdir(name);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_rmdir_error(err);
        return PR_FAILURE;
    } else
        return PR_SUCCESS;
}

PR_IMPLEMENT(PRInt32)
PR_FileDesc2NativeHandle(PRFileDesc *fd)
{
    if (fd) {
        fd = PR_GetIdentitiesLayer(fd, PR_NSPR_IO_LAYER);
    }
    if (!fd) {
        PR_SetError(PR_INVALID_ARGUMENT_ERROR, 0);
        return -1;
    }

    return fd->secret->md.osfd;
}

#ifdef MOZ_UNICODE
/*
 *  UTF16 Interface
 */
PR_IMPLEMENT(PRDirUTF16*) PR_OpenDirUTF16(const PRUnichar *name)
{
    PRDirUTF16 *dir;
    PRStatus sts;

    dir = PR_NEW(PRDirUTF16);
    if (dir) {
        sts = _PR_MD_OPEN_DIR_UTF16(&dir->md,name);
        if (sts != PR_SUCCESS) {
            PR_DELETE(dir);
            return NULL;
        }
    } else {
        PR_SetError(PR_OUT_OF_MEMORY_ERROR, 0);
    }
    return dir;
}

PR_IMPLEMENT(PRDirEntryUTF16*) PR_ReadDirUTF16(PRDirUTF16 *dir, PRDirFlags flags)
{
    /*
     * _MD_READ_DIR_UTF16 return a PRUnichar* to the name; allocation in
     * machine-dependent code
     */
    PRUnichar* name = _PR_MD_READ_DIR_UTF16(&dir->md, flags);
    dir->d.name = name;
    return name ? &dir->d : NULL;
}
 
PR_IMPLEMENT(PRStatus) PR_CloseDirUTF16(PRDirUTF16 *dir)
{
    PRInt32 rv;

    if (dir) {
        rv = _PR_MD_CLOSE_DIR_UTF16(&dir->md);
        PR_DELETE(dir);
        if (rv < 0)
            return PR_FAILURE;
        else
            return PR_SUCCESS;
    } 
    return PR_SUCCESS;
}

#endif /* MOZ_UNICODE */


static PRStatus PR_CALLBACK FileClose(PRFileDesc *fd)
{
    PRInt32 err;
    if (!fd || !fd->secret
            || (fd->secret->state != _PR_FILEDESC_OPEN
            && fd->secret->state != _PR_FILEDESC_CLOSED)) {
        PR_SetError(PR_BAD_DESCRIPTOR_ERROR, 0);
        return PR_FAILURE;
    }

    if (fd->secret->state == _PR_FILEDESC_OPEN) {
        if (close(fd->secret->md.osfd) < 0) {
            err = _MD_ERRNO();
            set_close_error(err);
            return PR_FAILURE;
        }
        fd->secret->state = _PR_FILEDESC_CLOSED;
    }
    PR_ASSERT(fd);
    _PR_Putfd(fd);
    return PR_SUCCESS;
}

static PRInt32 PR_CALLBACK FileRead(PRFileDesc *fd, void *buf, PRInt32 amount)
{
    PRInt32 rv,err = 0;

    rv = read(fd->secret->md.osfd, buf, amount);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_read_error(err);
        PR_ASSERT(rv == -1);
    }
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("read -> %d", rv));
    return rv;
}

static PRInt32 PR_CALLBACK FileWrite(PRFileDesc *fd, const void *buf, PRInt32 amount)
{
    PRInt32 rv,err = 0;
    PRInt32 temp, count;

    count = 0;
    while (amount > 0) {
        temp = write(fd->secret->md.osfd, buf, amount);
        if (temp < 0) {
            err = _MD_ERRNO();
            set_write_error(err);
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
    PR_LOG(_pr_io_lm, PR_LOG_MAX, ("write -> %d", count));
    return count;
}

static PRInt32 PR_CALLBACK FileAvailable(PRFileDesc *fd)
{
    PRInt32 result, cur, end, err;

    cur = lseek(fd->secret->md.osfd, 0, PR_SEEK_CUR);

    if (cur >= 0)
        end = lseek(fd->secret->md.osfd, 0, PR_SEEK_END);

    if ((cur < 0) || (end < 0)) {
        err = _MD_ERRNO();
        set_lseek_error(err);
        return -1;
    }

    result = end - cur;
    lseek(fd->secret->md.osfd, cur, PR_SEEK_SET);
    
    return result;
}

static PRInt64 PR_CALLBACK FileAvailable64(PRFileDesc *fd)
{
    PRInt64 result, cur, end;
    PRInt64 minus_one;
    PRInt32 err;

    cur = lseek(fd->secret->md.osfd, LL_ZERO, PR_SEEK_CUR);

    if (LL_GE_ZERO(cur))
        end = lseek(fd->secret->md.osfd, LL_ZERO, PR_SEEK_END);

    if (!LL_GE_ZERO(cur) || !LL_GE_ZERO(end)) {
        LL_I2L(minus_one, -1);
        err = _MD_ERRNO();
        set_lseek_error(err);
        return minus_one;
    }
    LL_SUB(result, end, cur);
    lseek(fd->secret->md.osfd, cur, PR_SEEK_SET);
    return result;
}

static PRStatus PR_CALLBACK FileSync(PRFileDesc *fd)
{
    PRInt32 result, err;
    result = fsync(fd->secret->md.osfd);
    if (result < 0) {
        err = _MD_ERRNO();
        set_fsync_error(err);
        return PR_FAILURE;
    }
    return PR_SUCCESS;
}

static PROffset32 PR_CALLBACK FileSeek(PRFileDesc *fd, PROffset32 offset, PRSeekWhence whence)
{
    PROffset32 result;
    PRInt32 err;
    result = lseek(fd->secret->md.osfd, offset, whence);
    if(result<0) {
        err = _MD_ERRNO();
        set_lseek_error(err);
    }
    return result;
}

static PROffset64 PR_CALLBACK FileSeek64(PRFileDesc *fd, PROffset64 offset, PRSeekWhence whence)
{
    PROffset64 result;
    PRInt32 err;
    
    result = lseek(fd->secret->md.osfd, offset, whence);
    if(!LL_GE_ZERO(result)) {
        err = _MD_ERRNO();
        set_lseek_error(err);
    }    
    return result;
}

static PRStatus PR_CALLBACK FileGetInfo(PRFileDesc *fd, PRFileInfo *info)
{
    struct stat sb;
    PRInt64 s, s2us;
    PRInt32 rv, err;
        
    rv = fstat(fd->secret->md.osfd, &sb);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_fstat_error(err);
        return PR_FAILURE;
    }
    if(info) {
        if (S_IFREG & sb.st_mode)
            info->type = PR_FILE_FILE ;
        else if (S_IFDIR & sb.st_mode)
            info->type = PR_FILE_DIRECTORY;
        else
            info->type = PR_FILE_OTHER;
        /* Use lower 32 bits of file size */
        info->size = ( sb.st_size & 0xffffffff);
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

static PRStatus PR_CALLBACK FileGetInfo64(PRFileDesc *fd, PRFileInfo64 *info)
{
    struct stat sb;
    PRInt64 s, s2us;
    PRInt32 rv, err;

    rv = fstat(fd->secret->md.osfd, &sb);
    if (rv < 0) {
        err = _MD_ERRNO();
        set_fstat_error(err);
        return PR_FAILURE;
    }
    if(info) {
        if (S_IFREG & sb.st_mode)
            info->type = PR_FILE_FILE ;
        else if (S_IFDIR & sb.st_mode)
            info->type = PR_FILE_DIRECTORY;
        else
            info->type = PR_FILE_OTHER;
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

static PRInt16 PR_CALLBACK FilePoll(
    PRFileDesc *fd, PRInt16 in_flags, PRInt16 *out_flags)
{
    *out_flags = 0;
    return in_flags;
}  /* FilePoll */


static PRIOMethods _pr_fileMethods = {
    PR_DESC_FILE,
    FileClose,
    FileRead,
    FileWrite,
    FileAvailable,
    FileAvailable64,
    FileSync,
    FileSeek,
    FileSeek64,
    FileGetInfo,
    FileGetInfo64,
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
    FilePoll,
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

PR_IMPLEMENT(const PRIOMethods*) PR_GetFileMethods(void)
{
    return &_pr_fileMethods;
}


static PRInt32 PR_CALLBACK PipeAvailable(PRFileDesc *fd)
{
    PRInt32 rv;
    rv =  _bt_socketavailable(fd);
    return rv;
}

static PRInt64 PR_CALLBACK PipeAvailable64(PRFileDesc *fd)
{
    PRInt64 rv;
    LL_I2L(rv, _bt_socketavailable(fd));
    return rv;
}

static PRStatus PR_CALLBACK PipeSync(PRFileDesc *fd)
{
    return PR_SUCCESS;
}


static PRIOMethods _pr_pipeMethods = {
    PR_DESC_PIPE,
    FileClose,
    FileRead,
    FileWrite,
    PipeAvailable,
    PipeAvailable64,
    PipeSync,
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
    FilePoll,
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

PR_IMPLEMENT(const PRIOMethods*) PR_GetPipeMethods(void)
{
    return &_pr_pipeMethods;
}

void _PR_InitIO(void) {
    const PRIOMethods *methods = PR_GetFileMethods();
    _PR_InitFdCache();
    _pr_flock_lock = PR_NewLock();
    _pr_flock_cv = PR_NewCondVar(_pr_flock_lock);
    _pr_stdin = bt_CreateFileDesc(0, PR_GetFileMethods(), _PR_TRI_UNKNOWN, false);
    _pr_stdout = bt_CreateFileDesc(1, PR_GetFileMethods(), _PR_TRI_UNKNOWN, false);
    _pr_stderr = bt_CreateFileDesc(2, PR_GetFileMethods(), _PR_TRI_UNKNOWN, false);
}

