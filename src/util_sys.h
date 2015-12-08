/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2010 Sebastien Vincent <sebastien.vincent@turnserver.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

/*
 * Copyright (C) 2006-2010 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * \file util_sys.h
 * \brief Some helper system functions.
 * \author Sebastien Vincent
 * \date 2008-2010
 */

#ifndef UTIL_SYS_H
#define UTIL_SYS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/uio.h>
#include <sys/select.h>
#else
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef _MSC_VER
#include <stdint.h>
#include <sys/types.h>
#else
/* replace stdint.h types for MS Windows */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
typedef int mode_t;
typedef int ssize_t;
typedef int pid_t;
#define inline __inline
#endif

#if defined(_WIN32) || defined(_WIN64)
/**
 * \struct iovec
 * \brief iovector structure for win32.
 */
typedef struct iovec
{
  void* iov_base; /**< Pointer on data */
  size_t iov_len; /**< Size of data */
}iovec;

/* some unix types are not defined for Windows
 * (even with MinGW) so declare it here
 */
typedef int socklen_t;
typedef int uid_t;
typedef int gid_t;
#endif

/**
 * \def MAX
 * \brief Maximum number of the two arguments.
 */
#define	MAX(a, b) ((a) > (b) ? (a) : (b))

/**
 * \def MIN
 * \brief Minimum number of the two arguments.
 */
#define	MIN(a, b) ((a) < (b) ? (a) : (b))

#ifdef _POSIX_C_SOURCE
/**
 * \brief Definition of fd_mask for select() operations.
 */
typedef long int fd_mask;
#endif

/* to specify a user-defined FD_SETSIZE */
#ifndef SFD_SETSIZE
/**
 * \def SFD_SETSIZE
 * \brief User defined FD_SETSIZE.
 */
#define SFD_SETSIZE FD_SETSIZE
#endif

/**
 * \struct sfd_set
 * \brief An fd_set-like structure.
 *
 * Replacement for the classic fd_set.
 * Ensure that select() can manage the maximum open files
 * on a system.
 */
typedef struct sfd_set
{
#if !defined(_WIN32) && !defined(_WIN64)
  fd_mask fds_bits[SFD_SETSIZE / (8 * sizeof(fd_mask)) + 1]; /**< Bitmask */

  /**
   * \def __fds_bits
   * \brief Definition of __fds_bits for *BSD.
   */
#define __fds_bits fds_bits
#else
  SOCKET fd_array[SFD_SETSIZE]; /**< Bitmask */
#define fd_mask
#endif
}sfd_set;

/**
 * \def SFD_ZERO
 * \brief FD_ZERO wrapper.
 */
#define SFD_ZERO(set) memset((set), 0x00, sizeof(sfd_set))

/**
 * \def SFD_SET
 * \brief FD_SET wrapper.
 */
#define SFD_SET(fd, set) FD_SET((fd), (set))

/**
 * \def SFD_ISSET
 * \brief FD_ISSET wrapper.
 */
#define SFD_ISSET(fd, set) FD_ISSET((fd), (set))

/**
 * \def SFD_CLR
 * \brief FD_CLR wrapper.
 */
#define SFD_CLR(fd, set) FD_CLR((fd), (set))

/**
 * \brief Test if socket has data to read.
 *
 * It is a convenient function to test if socket is valid, can be tested in
 * select and if it has data to read.
 * \param sock socket to read
 * \param nsock parameter of (p)select() function
 * \param fdsr set of descriptor (see select())
 * \return 1 if socket has data, 0 otherwise
 */
static inline int sfd_has_data(int sock, int nsock, sfd_set* fdsr)
{
  if(sock > 0 && sock < nsock && SFD_ISSET(sock, fdsr))
  {
    return 1;
  }
  else
  {
    return 0;
  }
}

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

/**
 * \brief Sleep for usec microseconds.
 * \param usec number of microseconds
 * \return 0 if success, -1 otherwise
 */
int msleep(unsigned long usec);

/**
 * \brief The getdtablesize() function from glibc does not compile in ANSI.
 * \return max open files for a process
 */
long get_dtablesize(void);

/**
 * \brief Return if host machine is big endian.
 * \return 1 if big endian
 */
int is_big_endian(void);

/**
 * \brief Return if host machine is little endian.
 * \return 1 if little endian, 0 otherwise
 */
int is_little_endian(void);

/**
 * \brief Return the error which correspond to errnum.
 * \param errnum error number (i.e errno)
 * \param buf a buffer
 * \param buflen size of buffer
 * \return pointer on buf
 * \note This function use strerror_r if available, and assume strerror() is
 * reentrant on systems which do not have strerror_r().
 * \warning If you do a multithreaded program, be sure strerror_r() is available
 * or strerror() is reentrant on your system.
 */
char* get_error(int errnum, char* buf, size_t buflen);

/**
 * \brief Go in daemon mode.
 * \param dir change directory to this, default is /.
 * \param mask to fix permission: mask & 0777, default is 0.
 * \param cleanup cleanup function, if not NULL it is executed before father
 * _exit()
 * \param arg argument of cleanup function
 * \return -1 if error\n
 * In case of father, this function never returns (_exit)\n
 * If success 0 is returned in case of child
 */
int go_daemon(const char* dir, mode_t mask, void (*cleanup)(void* arg),
    void* arg);

/**
 * \brief Free elements of an iovec array.
 * It does not freed the array (if allocated).
 * \param iov the iovec array
 * \param nb number of elements
 */
void iovec_free_data(struct iovec* iov, uint32_t nb);

/**
 * \brief Drop privileges.
 *
 * If the program is executed by setuid-root and the user_name
 * is NULL, change privileges to the real UID / GID.
 * Otherwise change privileges to the user_name account
 * \param uid_real the real UID of the user
 * \param gid_real the real GID of the user
 * \param uid_eff the effective UID of the user
 * \param gid_eff the effective GID of the user
 * \param user_name user name of the account to switch
 * \return 0 if success, -1 otherwise
 * \note Should work on POSIX and *BSD systems.
 */
int uid_drop_privileges(uid_t uid_real, gid_t gid_real, uid_t uid_eff,
    gid_t gid_eff, const char* user_name);

/**
 * \brief Gain lost privileges.
 * \param uid_eff the effective UID of the user
 * \param gid_eff the effective GID of the user
 * \return 0 if success, -1 otherwise
 * \note Should work on POSIX and *BSD systems.
 */
int uid_gain_privileges(uid_t uid_eff, gid_t gid_eff);

/**
 * \brief Encode string for HTTP request.
 * \param str string to encode.
 * \return encoding string or NULL if problem.
 * \warning The caller must free the return value.
 */
char* encode_http_string(const char* str);

#if __STDC_VERSION__ >= 199901L /* C99 */
/**
 * \brief Secure version of strncpy.
 * \param dest destination buffer
 * \param src source buffer to copy
 * \param n maximum size to copy
 * \return pointer on dest
 */
static inline char* s_strncpy(char* dest, const char* src, size_t n)
{
  char* ret = NULL;

  ret = strncpy(dest, src, n - 1);
  dest[n - 1] = 0x00; /* add the final NULL character */

  return ret;
}

/**
 * \brief Secure version of snprintf.
 * \param str buffer to copy
 * \param size maximum size to copy
 * \param format the format (see printf)
 * \param ... a list of arguments
 * \return number of character written
 */
static inline int s_snprintf(char* str, size_t size, const char* format, ...)
{
  va_list args;
  int ret = 0;

  va_start(args, format);
  ret = snprintf(str, size - 1, format,  args);
  str[size - 1] = 0x00; /* add the final NULL character */

  return ret;
}
#else
#undef s_strncpy
/**
 * \def s_strncpy
 * \brief Secure version of strncpy.
 * \param dest destination buffer
 * \param src source buffer to copy
 * \param n maximum size to copy
 * \warning It does not return a value (like strncpy does).
 */
#define s_strncpy(dest, src, n) do { \
  strncpy((dest), (src), (n) - 1); \
  dest[n - 1] = 0x00; \
}while(0);

#endif

#if defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 500
/**
 * \brief strdup replacement.
 *
 * strdup() is from X/OPEN (XSI extension).
 * \param s string to duplicate
 * \return pointer on duplicate string
 * \warning Do not forget to free the pointer after use
 * \author Sebastien Vincent
 */
char* strdup(const char* s);
#endif

/**
 * \brief Convert a binary stream into hex value.
 * \param bin binary data
 * \param bin_len data length
 * \param hex buffer
 * \param hex_len length of buffer
 */
void hex_convert(const unsigned char* bin, size_t bin_len, unsigned char* hex,
    size_t hex_len);

/**
 * \brief Convert a ascii stream into integer value.
 * \param data ascii data
 * \param data_len data length
 * \param t a 32 bit unsigned integer
 */
void uint32_convert(const unsigned char* data, size_t data_len, uint32_t* t);

/**
 * \brief Convert a ascii stream into integer value.
 * \param data ascii data
 * \param data_len data length
 * \param t a 64 bit unsigned integer
 */
void uint64_convert(const unsigned char* data, size_t data_len, uint64_t* t);

#if defined(_WIN32) || defined(_WIN64)
/**
 * \brief The writev() function for win32 socket.
 * \param fd the socket descriptor to write the data
 * \param iov the iovector which contains the data
 * \param iovcnt number of element that should be written
 * \param addr source address to send with UDP, set to NULL if you want to send
 * with TCP
 * \param addr_size sizeof addr
 * \return number of bytes written or -1 if error
 * \warning this function work only with socket!
 */
ssize_t sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size);

/**
 * \brief The readv() function for win32 socket.
 * \param fd the socket descriptor to read the data
 * \param iov the iovector to store the data
 * \param iovcnt number of element that should be filled
 * \param addr if not NULL it considers using a UDP socket, otherwise it
 * considers using a TCP one
 * \param addr_size pointer on address size, will be filled by this function
 * \return number of bytes read or -1 if error
 * \warning this function work only with socket!
 */
ssize_t sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size);
#endif

#ifdef __cplusplus
}
#endif

#endif /* UTIL_SYS_H */

