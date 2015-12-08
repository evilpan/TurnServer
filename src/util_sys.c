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
 * \file util_sys.c
 * \brief Some helper system functions.
 * \author Sebastien Vincent
 * \date 2006-2010
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <fcntl.h>

#include <sys/stat.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <time.h>
#include <pwd.h>
#endif

#include "util_sys.h"

/**
 * \def UNKNOWN_ERROR
 * \brief Error string used when no other error string
 * are available.
 */
#define UNKNOWN_ERROR "Unknown error!"

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

int msleep(unsigned long usec)
{
  unsigned long sec = 0;
  struct timeval tv;

  sec = (unsigned long)usec / 1000000;
  usec = (unsigned long)usec % 1000000;

  tv.tv_sec = sec;
  tv.tv_usec = usec;

  select(0, NULL, NULL, NULL, &tv);

  return 0;
}

long get_dtablesize(void)
{
#if !defined(_WIN32) && !defined(_WIN64)
  return sysconf(_SC_OPEN_MAX);
  /*
     struct rlimit limit;
     getrlimit(RLIMIT_NOFILE, &limit);
     return limit.rlim_cur;
   */
#else
#ifndef FD_SETSIZE
#define FD_SETSIZE 256
#endif
  return FD_SETSIZE;
#endif
}

int is_big_endian(void)
{
  long one = 1;
  return !(*((char *)(&one)));
}

int is_little_endian(void)
{
  long one = 1;
  return (*((char *)(&one)));
}

char* get_error(int errnum, char* buf, size_t buflen)
{
  char* error = NULL;
# if _POSIX_C_SOURCE == 200112L && !defined(_GNU_SOURCE)
  /* POSIX version */
  int ret = 0;
  ret = strerror_r(errnum, buf, buflen);
  if(ret == -1)
  {
    strncpy(buf, UNKNOWN_ERROR, buflen - 1);
    buf[buflen - 1] = 0x00;
  }
  error = buf;
#elif defined(_GNU_SOURCE)
  /* GNU libc */
  error = strerror_r(errnum, buf, buflen);
#else
  /* no strerror_r() function, assume that strerror is reentrant! */
  strncpy(buf, strerror(errnum), buflen);
  error = buf;
#endif
  return error;
}

int go_daemon(const char* dir, mode_t mask, void (*cleanup)(void* arg),
    void* arg)
{
  pid_t pid = -1;
  long i = 0;
  long max = 0;
  int fd = -1;

#if defined(_WIN32) || defined(_WIN64)
  return -1;
#else

  pid = fork();

  if(pid > 0) /* father */
  {
    if(cleanup)
    {
      cleanup(arg);
    }
    _exit(EXIT_SUCCESS);
  }
  else if(pid == -1) /* error */
  {
    return -1;
  }

  /* child */

  if(setsid() == -1)
  {
    return -1;
  }

  max = sysconf(_SC_OPEN_MAX);
  for(i = STDIN_FILENO + 1 ; i < max ; i++)
  {
    close(i);
  }

  /* change directory */
  if(!dir)
  {
    dir = "/";
  }

  if(chdir(dir) == -1)
  {
    return -1;
  }

  /* change mask */
  umask(mask);

  /* redirect stdin, stdout and stderr to /dev/null */
  /* open /dev/null */
  if((fd = open("/dev/null", O_RDWR, 0)) != -1)
  {
    /* redirect stdin, stdout and stderr to /dev/null */
    close(STDIN_FILENO);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);

    if(fd > -1)
    {
      close(fd);
    }
  }

  return 0;
#endif
}

char* encode_http_string(const char* str)
{
  size_t len = strlen(str);
  char* p = NULL;
  unsigned int i = 0;
  unsigned int j = 0;

  /* in the worst case, it take 3x (%20) the size */
  p = malloc(sizeof(char) * (3 * len + 1));

  if(!p)
  {
    return NULL;
  }

  for(i = 0, j = 0 ; i < len ; i++, j++)
  {
    unsigned int t = (unsigned int)str[i];

    if(t < 42 || t == ',' || (t >= 58 && t < 64) ||
       (t >= 91 && t < 95) || t == '`' ||
       t > 122 || t == '+' || t == '&' ||
       t == ',' || t == ';' || t == '/' ||
       t == '?' || t == '@' || t == '$' ||
       t == '=' || t == ':' )
    {
      /* replace */
      sprintf(p + j, "%%%02X", t);
      j += 2;
    }
    else
    {
      p[j] = (char)t;
    }
  }

  p[j] = 0x00;

  return p;
}

#if defined(_XOPEN_SOURCE) && _XOPEN_SOURCE < 500
char* strdup(const char* str)
{
  char* ret = NULL;
  size_t nb = strlen(str);

  ret = malloc(nb + 1);
  if(!ret)
  {
    return NULL;
  }
  memcpy(ret, str, nb); /* also copy the NULL character */
  return ret;
}
#endif

#if defined(_WIN32) || defined(_WIN64)
ssize_t sock_readv(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t* addr_size)
{
  /* it should be sufficient,
   * the dynamically allocation is timecost.
   * We could use a static WSABUF* winiov but
   * the function would be non reentrant.
   */
  WSABUF winiov[50];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0;

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  if(addr) /* UDP case */
  {
    if(WSARecvFrom(fd, winiov, winiov_len, &ret, NULL, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSARecv(fd, winiov, winiov_len, &ret, NULL, NULL, NULL) != 0)
    {
      return -1;
    }
  }

  return (ssize_t)ret;
}

ssize_t sock_writev(int fd, const struct iovec *iov, size_t iovcnt,
    const struct sockaddr* addr, socklen_t addr_size)
{
  /* it should be sufficient,
   * the dynamically allocation is timecost.
   * We could use a static WSABUF* winiov but
   * the function would be non reentrant.
   */
  WSABUF winiov[50];
  DWORD winiov_len = iovcnt;
  size_t i = 0;
  DWORD ret = 0; /* number of byte read or written */

  if(iovcnt > sizeof(winiov))
  {
    return -1;
  }

  for(i = 0 ; i < iovcnt ; i++)
  {
    winiov[i].len = iov[i].iov_len;
    winiov[i].buf = iov[i].iov_base;
  }

  /* UDP case */
  if(addr)
  {
    if(WSASendTo(fd, winiov, winiov_len, &ret, 0, (struct sockaddr*)addr,
          addr_size, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  else /* TCP case */
  {
    if(WSASend(fd, winiov, winiov_len, &ret, 0, NULL, NULL) != 0)
    {
      /* error send */
      return -1;
    }
  }
  return (ssize_t)ret;
}
#endif

void iovec_free_data(struct iovec* iov, uint32_t nb)
{
  size_t i = 0;

  for(i = 0 ; i < nb ; i++)
  {
    free(iov[i].iov_base);
    iov[i].iov_base = NULL;
  }
}

int uid_drop_privileges(uid_t uid_real, gid_t gid_real, uid_t uid_eff,
    gid_t gid_eff, const char* user_name)
{
#if defined(_WIN32) || defined(_WIN64)
  return -1;
#else
  /* Unix */
  (void)gid_eff; /* not used for the moment */

  if(uid_real == 0 || uid_eff == 0)
  {
    /* program runs as root or sudoers */
    struct passwd user;
    struct passwd* tmpUser = &user;
    struct passwd* tmp = NULL;
    char buf[1024];

    if(!user_name)
    {
      if(uid_real == uid_eff)
      {
        /* runs as root and no user_name specified,
         * cannot drop privileges.
         */
        return -1;
      }

#ifdef _POSIX_SAVED_IDS
      if(setegid(gid_real) == -1)
      {
        return -1;
      }
      return seteuid(uid_real);
#else
      /* i.e. for *BSD */
      if(setregid(-1, gid_real) == -1)
      {
        return -1;
      }
      return setreuid(-1, uid_real);
#endif
    }

    /* get user_name information (UID and GID) */
    if(getpwnam_r(user_name, tmpUser, buf, sizeof(buf), &tmp) == 0)
    {
      if(setegid(user.pw_gid) == -1)
      {
        return -1;
      }
      return seteuid(user.pw_uid);
    }
    else
    {
      /* user does not exist, cannot lost our privileges */
      return -1;
    }
  }

  /* cannot lost our privileges */
  return -1;
#endif
}

int uid_gain_privileges(uid_t uid_eff, gid_t gid_eff)
{
#if defined(_WIN32) || defined(_WIN64)
  return -1;
#else
  /* Unix */
#ifdef _POSIX_SAVED_IDS
  if(setegid(gid_eff) == -1)
  {
    return -1;
  }
  return seteuid(uid_eff);
#else
  /* i.e for *BSD */
  if(setregid(-1, gid_eff) == -1)
  {
    return -1;
  }
  return setreuid(-1, uid_eff);
#endif
#endif
}

void hex_convert(const unsigned char* bin, size_t bin_len, unsigned char* hex,
    size_t hex_len)
{
  size_t i = 0;
  unsigned char j = 0;

  for(i = 0 ; i < bin_len && (i * 2) < hex_len ; i++)
  {
    j = (bin[i] >> 4) & 0x0f;

    if(j <= 9)
    {
      hex[i * 2] = (j + '0');
    }
    else
    {
      hex[i * 2] = (j + 'a' - 10);
    }

    j = bin[i] & 0x0f;

    if(j <= 9)
    {
      hex[i * 2 + 1] = (j + '0');
    }
    else
    {
      hex[i * 2 + 1] = (j + 'a' - 10);
    }
  }
}

void uint32_convert(const unsigned char* data, size_t data_len, uint32_t* t)
{
  unsigned int i = 0;
  *t = 0;

  for(i = 0 ; i < data_len ; i++)
  {
    *t = (*t) * 16;

    if(data[i] >= '0' && data[i] <= '9')
    {
      *t += data[i] - '0';
    }
    else if(data[i] >= 'a' && data[i] <='f')
    {
      *t += data[i] - 'a' + 10;
    }
  }
}

void uint64_convert(const unsigned char* data, size_t data_len, uint64_t* t)
{
  unsigned int i = 0;
  *t = 0;

  for(i = 0 ; i < data_len ; i++)
  {
    *t = (*t) * 16;

    if(data[i] >= '0' && data[i] <= '9')
    {
      *t += data[i] - '0';
    }
    else if(data[i] >= 'a' && data[i] <='f')
    {
      *t += data[i] - 'a' + 10;
    }
  }
}

#ifdef __cplusplus
}
#endif

