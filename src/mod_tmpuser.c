/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2010 BlueJimp
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

/**
 * \file mod_tmpuser.c
 * \brief Module that can add/delete temporary user.
 *
 * It consists of a socket that will listen for incoming messages and process
 * them. Message format is as follow:
 * - To create a user, create user:password:domain
 * - To delete a user, delete user
 *
 * \author Sebastien Vincent
 * \date 2011
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "turnserver.h"
#include "list.h"
#include "tls_peer.h"
#include "mod_tmpuser.h"

/**
 * \struct tmpuser
 * \brief Structure for the tmpuser module.
 */
struct tmpuser
{
  int initialized; /**< initialized flag */
  int sock; /**< Localhost socket */
  struct list_head* account_list; /**< account list */
  struct list_head client_list; /**< TCP client socket list */
};

/**
 * \var g_tmpuser
 * \brief Global reference for the tmpuser module.
 */
static struct tmpuser g_tmpuser;

/**
 * \brief Create a temporary user.
 * \param user user name
 * \param password user password
 * \param domain domain name
 * \return 0 if success, -1 otherwise
 */
static int tmpuser_create(const char* user, const char* password,
    const char* domain)
{
  struct account_desc* desc = NULL;

  if(!g_tmpuser.account_list)
  {
    return -1;
  }

  desc = account_list_find(g_tmpuser.account_list, user, NULL);

  /* user already exist */
  if(desc)
  {
    return -1;
  }

  desc = account_desc_new(user, password, domain, AUTHORIZED);
  if(!desc)
  {
    return -1;
  }

  desc->is_tmp = 1;

  account_list_add(g_tmpuser.account_list, desc);
  return 0;
}

/**
 * \brief Delete a temporary user.
 * \param user user name
 * \return 0 if success, -1 otherwise
 */
static int tmpuser_delete(const char* user)
{
  struct account_desc* desc = NULL;

  if(!g_tmpuser.account_list)
  {
    return -1;
  }

  desc = account_list_find(g_tmpuser.account_list, user, NULL);

  /* only delete temporary user! */
  if(desc && desc->is_tmp)
  {
    account_list_remove(g_tmpuser.account_list, desc);
  }
  else
  {
    return -1;
  }

  return 0;
}

int tmpuser_init(struct list_head* account_list)
{
  INIT_LIST(g_tmpuser.client_list);

  g_tmpuser.account_list = NULL;
  g_tmpuser.sock = socket_create(TCP, "localhost", 8086, 0, 1);

  if(g_tmpuser.sock == -1)
  {
    return -1;
  }

  if(listen(g_tmpuser.sock, 5) == -1)
  {
    close(g_tmpuser.sock);
    g_tmpuser.sock = -1;
    return -1;
  }

  g_tmpuser.account_list = account_list;
  g_tmpuser.initialized = 1;
  return 0;
}

int tmpuser_get_socket()
{
  return g_tmpuser.sock;
}

struct list_head* tmpuser_get_tcp_clients(void)
{
  return &g_tmpuser.client_list;
}

void tmpuser_add_tcp_client(struct socket_desc* desc)
{
  struct list_head* l = (struct list_head*)&desc->list;
  LIST_ADD(l, &g_tmpuser.client_list);
}

void tmpuser_remove_tcp_client(struct socket_desc* desc)
{
  struct list_head* l = (struct list_head*)&desc->list;
  LIST_DEL(l);
}

int tmpuser_process_msg(const char* buf, ssize_t len)
{
  int create = 0;
  int delete = 0;
  char* save_ptr = NULL;
  const char* delim = ":";
  char* token = NULL;
  char* login = NULL;
  char* password = NULL;
  char* realm = NULL;
  char* buf2 = (char*)buf;

  buf2[len - 1] = 0x00;

  if(len < 1 || !buf)
  {
    return -1;
  }

  token = strtok_r(buf2, delim, &save_ptr);
  if(!token)
  {
    return -1;
  }

  if(!strncmp(token, "create ", 7))
  {
    create = 1;
    login = strdup(token + 7);
  }
  else if(!strncmp(token, "delete ", 7))
  {
    char* bn = NULL;

    delete = 1;
    login = strdup(token + 7);

    bn = strchr(login, '\n');
    if(bn)
    {
      *bn = 0x00;
    }

    bn = strchr(login, '\r');
    if(bn)
    {
      *bn = 0x00;
    }
  }
  else
  {
    return -1;
  }

  if(create)
  {
    token = strtok_r(NULL, delim, &save_ptr);
    if(!token)
    {
      free(login);
      return -1;
    }
    password = strdup(token);

    token = strtok_r(NULL, delim, &save_ptr);
    if(!token)
    {
      free(login);
      free(password);
      return -1;
    }
    realm = strdup(token);

    token = strtok_r(NULL, delim, &save_ptr);
  }

  if(create)
  {
    int r = tmpuser_create(login, password, realm);
    free(login);
    free(password);
    free(realm);
    return r;
  }
  else if(delete)
  {
    int r = tmpuser_delete(login);
    free(login);
    return r;
  }

  return -1;
}

void tmpuser_destroy(void)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  if(!g_tmpuser.initialized)
  {
    return;
  }

  if(g_tmpuser.sock > 0)
  {
    close(g_tmpuser.sock);
  }

  list_iterate_safe(get, n, &g_tmpuser.client_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);

    if(tmp->sock)
    {
      close(tmp->sock);
    }
    free(tmp);
  }

  g_tmpuser.sock = -1;

  /* let temporary accounts be deleted in the list cleanup in
   * turnserver.c's main() function with the other account
   */
  g_tmpuser.account_list = NULL;

  INIT_LIST(g_tmpuser.client_list);
}

