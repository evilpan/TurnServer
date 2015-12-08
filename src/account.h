/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2009 Sebastien Vincent <sebastien.vincent@turnserver.org>
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
 * \file account.h
 * \brief Account on TURN server.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifndef ACCOUNT_H
#define ACCOUNT_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "list.h"

/**
 * \enum account_state
 * \brief Account access state.
 */
enum account_state
{
  AUTHORIZED, /**< Client is authorized to access service */
  RESTRICTED, /**< Client has limited access to service (bandwidth, ...) */
  REFUSED, /**< Client is always refused to access service (i.e. blacklist) */
};

/**
 * \struct account_desc
 * \brief Account descriptor.
 */
struct account_desc
{
  char username[514]; /**< Username */
  char realm[256]; /**< Realm */
  unsigned char key[16]; /**< MD5 hash */
  enum account_state state; /**< Access state */
  size_t allocations; /**< Number of allocations used */
  int is_tmp; /**< If account is a temporary account */
  struct list_head list; /**< For list management */
};

/**
 * \brief Create a new account.
 *
 * The account will be in the state AUTHORIZED when created.
 * \param username NULL-terminated username
 * \param password NULL-terminated password
 * \param realm NULL-terminated realm
 * \param state account state
 * \return pointer on account_desc or NULL if problem
 */
struct account_desc* account_desc_new(const char* username,
    const char* password, const char* realm, enum account_state state);

/**
 * \brief Free an account.
 * \param desc pointer on pointer allocated by account_desc_new
 */
void account_desc_free(struct account_desc** desc);

/**
 * \brief Set the state for an account.
 * \param desc account descriptor
 * \param state state to set
 */
void account_desc_set_state(struct account_desc* desc, enum account_state state);

/**
 * \brief Find a account with specified username and realm from a list.
 * \param list list of accounts
 * \param username
 * \param realm realm
 * \return pointer on account_desc or NULL if not found
 */
struct account_desc* account_list_find(struct list_head* list,
    const char* username, const char* realm);

/**
 * \brief Free a list of accounts.
 * \param list list of accounts
 */
void account_list_free(struct list_head* list);

/**
 * \brief Add an account to a list.
 * \param list list of accounts
 * \param desc account descriptor to add
 */
void account_list_add(struct list_head* list, struct account_desc* desc);

/**
 * \brief Remove and free an account from a list.
 * \param list list of accounts
 * \param desc account to remove
 */
void account_list_remove(struct list_head* list, struct account_desc* desc);

/**
 * \brief Parse account file and fill up a list.
 *
 * Each lines of file MUST be: login:password:domain.org:state
 * In other words, the value is separated with a ':'
 * \param list list of accounts
 * \param file account file
 * \return 0 if success, -1 if error
 */
int account_parse_file(struct list_head* list, const char* file);

#endif /* ACCOUNT_H */

