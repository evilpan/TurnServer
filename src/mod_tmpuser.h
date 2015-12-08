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
 * \file mod_tmpuser.h
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

#ifndef MOD_TMPUSER_H
#define MOD_TMPUSER_H

#include "account.h"

struct socket_desc;

/**
 * \brief Initialize the module.
 * \param account_list list of account.
 * \return 0 if success, -1 otherwise
 */
int tmpuser_init(struct list_head* account_list);

/**
 * \brief Get the listen socket.
 * \return listen socket descriptor
 */
int tmpuser_get_socket(void);

/**
 * \brief Get the TCP client list.
 * \return TCP client list
 */
struct list_head* tmpuser_get_tcp_clients(void);

/**
 * \brief Add the specified socket descriptor.
 * \param desc socket descriptor to add
 */
void tmpuser_add_tcp_client(struct socket_desc* desc);

/**
 * \brief Remove the specified socket descriptor.
 * \param desc socket descriptor to remove
 */
void tmpuser_remove_tcp_client(struct socket_desc* desc);

/**
 * \brief Process a message coming from the network.
 * \param buf buffer message
 * \param len length of buffer message
 * \return 0 if processing is successful, -1 otherwise
 */
int tmpuser_process_msg(const char* buf, ssize_t len);

/**
 * \brief Destroy any extra data/memory used by this module.
 */
void tmpuser_destroy(void);

#endif /* MOD_TMPUSER_H */

