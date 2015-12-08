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

/**
 * \file allocation.h
 * \brief Allocation between TURN client and external(s) client(s).
 * \author Sebastien Vincent
 * \date 2008-2010
 */

#ifndef ALLOCATION_H
#define ALLOCATION_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "list.h"

/**
 * \struct allocation_token
 * \brief Allocation token.
 */
struct allocation_token
{
  uint8_t id[8]; /**< Token ID */
  int sock; /**< The opened socket */
  timer_t expire_timer; /**< Expire timer */
  struct list_head list; /**< For list management */
  struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_tuple
 * \brief Allocation tuple.
 */
struct allocation_tuple
{
  int transport_protocol; /**< Transport protocol */
  struct sockaddr_storage client_addr; /**< Client address */
  struct sockaddr_storage server_addr; /**< Server address */
};

/**
 * \struct allocation_permission
 * \brief Network address permission.
 */
struct allocation_permission
{
  int family; /**< Address family */
  uint8_t peer_addr[16]; /**< Peer address */
  timer_t expire_timer; /**< Expire timer */
  struct list_head list; /**< For list management */
  struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_channel
 * \brief Allocation channel.
 */
struct allocation_channel
{
  int family; /**< Address family */
  uint8_t peer_addr[16]; /**< Peer address */
  uint16_t peer_port; /**< Peer port */
  uint16_t channel_number; /**< Channel bound to this peer */
  timer_t expire_timer; /**< Expire timer */
  struct list_head list; /**< For list management */
  struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_tcp_relay
 * \brief TCP relay information.
 */
struct allocation_tcp_relay
{
  uint32_t connection_id; /**< Connection ID */
  int family; /**< TCP relay family (IPv4 or IPv6) */
  uint8_t peer_addr[16]; /**< Peer address */
  uint16_t peer_port; /**< Peer port */
  int peer_sock; /**< Peer data connection (server <-> peer) */
  int client_sock; /**< Client data connection (client <-> server) */
  timer_t expire_timer; /**< Expire timer */
  int new; /**< If the connection is newly initiated */
  int ready; /**< If remote peer is connected (i.e. connect() has succeed
               before timeout) */
  time_t created; /**< Time when this relay has been created (this is used to
                    calculted timeout) */
  char* buf; /**< Internal buffer for peer data (before receiving
               ConnectionBind) */
  size_t buf_len; /**< Length of current data in internal buffer */
  size_t buf_size; /**< Capacity of internal buffer */
  uint8_t connect_msg_id[12]; /**< TURN message ID of the connection request
                                (if any) */
  struct list_head list; /**< For list management */
  struct list_head list2; /**< For list management (expired list) */
};

/**
 * \struct allocation_desc
 * \brief Allocation descriptor.
 */
struct allocation_desc
{
  char* username; /**< Username of client */
  unsigned char key[16]; /**< MD5 hash over username, realm and password */
  char realm[256]; /**< Realm of user */
  unsigned char nonce[48]; /**< Nonce of user */
  int relayed_transport_protocol; /**< Relayed transport protocol used */
  struct sockaddr_storage relayed_addr; /**< Relayed transport address */
  struct allocation_tuple tuple; /**< 5-tuple */
  struct list_head peers_channels; /**< List of channel to peer bindings */
  struct list_head peers_permissions; /**< List of peers permissions */
  struct list_head tcp_relays; /**< TCP relays information */
  int relayed_sock; /**< Socket for the allocated transport address */
  int relayed_sock_tcp; /**< Socket for the allocated transport address to
                          contact TCP peer (RFC6062). It is set to -1 if Connect
                          request succeed */
  int relayed_tls; /**< If allocation has been set in TLS */
  int relayed_dtls; /**< If allocation has been set in DTLS */
  int tuple_sock; /**< Socket for the connection between the TURN server and the
                    TURN client */
  uint8_t transaction_id[12]; /**< Transaction ID of the Allocate Request */
  timer_t expire_timer; /**< Expire timer */
  unsigned long bucket_capacity; /**< Capacity of token bucket */
  unsigned long bucket_tokenup; /**< Number of tokens available for upload */
  unsigned long bucket_tokendown; /**< Number of tokens available for
                                    download */
  struct timeval last_timeup ; /**< Last time of bandwidth limit checking for
                                 upload */
  struct timeval last_timedown ; /**< Last time of bandwidth limit checking for
                                   download */
  struct list_head list; /**< For list management */
  struct list_head list2; /**< For list management (expired list) */
};

/**
 * \brief Create a new allocation descriptor.
 * \param id transaction ID of the Allocate request
 * \param transport_protocol transport protocol (i.e. TCP, UDP, ...)
 * \param username login of the user
 * \param key MD5 hash over username, realm and password
 * \param realm realm of the user
 * \param nonce nonce of the user
 * \param relayed_addr relayed address and port
 * \param server_addr server network address and port
 * \param client_addr client network address and port
 * \param addr_size sizeof address
 * \param lifetime expire of the allocation
 * \return pointer on struct allocation_desc, or NULL if problem
 */
struct allocation_desc* allocation_desc_new(const uint8_t* id,
    uint8_t transport_protocol, const char* username, const unsigned char* key,
    const char* realm, const unsigned char* nonce,
    const struct sockaddr* relayed_addr, const struct sockaddr* server_addr,
    const struct sockaddr* client_addr, socklen_t addr_size, uint32_t lifetime);

/**
 * \brief Free an allocation descriptor.
 * \param desc pointer on pointer allocated by allocation_desc_new
 */
void allocation_desc_free(struct allocation_desc** desc);

/**
 * \brief Set timer of an allocation descriptor.
 * \param desc allocation descriptor
 * \param lifetime lifetime timer
 */
void allocation_desc_set_timer(struct allocation_desc* desc, uint32_t lifetime);

/**
 * \brief Find if a peer (network address only) has a permissions installed.
 * \param desc allocation descriptor
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \return pointer on allocation_permission or NULL if not found
 */
struct allocation_permission* allocation_desc_find_permission(
    struct allocation_desc* desc, int family, const uint8_t* peer_addr);

/**
 * \brief Find if a peer (network address only) has a permissions installed.
 * \param desc allocation descriptor
 * \param addr network address
 * \return pointer on allocation_permission or NULL if not found
 */
struct allocation_permission* allocation_desc_find_permission_sockaddr(
    struct allocation_desc* desc, const struct sockaddr* addr);

/**
 * \brief Add a permission for a peer.
 * \param desc allocation descriptor
 * \param lifetime lifetime of the permission
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_permission(struct allocation_desc* desc,
    uint32_t lifetime, int family, const uint8_t* peer_addr);

/**
 * \brief Find if a peer (transport address) has a channel bound.
 * \param desc allocation descriptor
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \param peer_port peer port
 * \return the channel if the peer has already a channel bound, 0 otherwise
 */
uint32_t allocation_desc_find_channel(struct allocation_desc* desc, int family, const uint8_t* peer_addr, uint16_t peer_port);

/**
 * \brief Find if a channel number has a peer (transport address).
 * \param desc allocation descriptor
 * \param channel channel number
 * \return pointer on allocation_channel if found, NULL otherwise
 */
struct allocation_channel* allocation_desc_find_channel_number(
    struct allocation_desc* desc, uint16_t channel);

/**
 * \brief Add a channel to a peer (transport address).
 * \param desc allocation descriptor
 * \param channel channel number
 * \param lifetime lifetime of the channel
 * \param family address family (IPv4 or IPv6)
 * \param peer_addr network address
 * \param peer_port peer port
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_channel(struct allocation_desc* desc, uint16_t channel,
    uint32_t lifetime, int family, const uint8_t* peer_addr,
    uint16_t peer_port);

/**
 * \brief Add a TCP relay.
 * \param desc allocation descriptor
 * \param id connection ID
 * \param peer_sock peer data connection socket
 * \param family peer address family (IPv4 or IPv6)
 * \param peer_addr peer address
 * \param peer_port peer port
 * \param timeout TCP relay timeout (if no ConnectionBind is received)
 * \param buffer_size internal buffer size (for peer data)
 * \param connect_msg_id Connect request message ID if client contact another
 * peer otherwise put NULL
 * \return 0 if success, -1 otherwise
 */
int allocation_desc_add_tcp_relay(struct allocation_desc* desc, uint32_t id,
    int peer_sock, int family, const uint8_t* peer_addr, uint16_t peer_port,
    uint32_t timeout, size_t buffer_size, uint8_t* connect_msg_id);

/**
 * \brief Remove a TCP relay.
 * \param list list of TCP relays
 * \param relay relay to remove
 */
void allocation_tcp_relay_list_remove(struct list_head* list,
    struct allocation_tcp_relay* relay);

/**
 * \brief Find a TCP relay identified by its connection ID.
 * \param desc allocation descriptor
 * \param id connection ID
 * \return TCP relay if found, NULL otherwise
 */
struct allocation_tcp_relay* allocation_desc_find_tcp_relay_id(
    struct allocation_desc* desc, uint32_t id);

/**
 * Find a TCP relay identified by its peer address and port.
 * \param desc allocation descriptor
 * \param family peer family address (IPv4 or IPv6)
 * \param peer_addr peer address
 * \param peer_port peer port
 * \return TCP relay if found, NULL otherwise
 */
struct allocation_tcp_relay* allocation_desc_find_tcp_relay_addr(
    struct allocation_desc* desc, int family, const uint8_t* peer_addr,
    uint16_t peer_port);

/**
 * \brief Set timer of an TCP relay.
 *
 * If timeout is 0, the timer is stopped.
 * \param relay TCP relay
 * \param timeout timeout to set
 */
void allocation_tcp_relay_set_timer(struct allocation_tcp_relay* relay,
    uint32_t timeout);

/**
 * \brief Reset the timer of the channel.
 * \param channel allocation channel
 * \param lifetime lifetime
 */
void allocation_channel_set_timer(struct allocation_channel* channel,
    uint32_t lifetime);

/**
 * \brief Reset the timer of the permission.
 * \param permission allocation permission
 * \param lifetime lifetime
 */
void allocation_permission_set_timer(struct allocation_permission* permission,
    uint32_t lifetime);

/**
 * \brief Free a list of allocations.
 * \param list list of allocations
 */
void allocation_list_free(struct list_head* list);

/**
 * \brief Add an allocation to a list.
 * \param list list of allocations
 * \param desc allocation descriptor to add
 */
void allocation_list_add(struct list_head* list, struct allocation_desc* desc);

/**
 * \brief Remove and free an allocation from a list.
 * \param list list of allocations
 * \param desc allocation to remove
 */
void allocation_list_remove(struct list_head* list,
    struct allocation_desc* desc);

/**
 * \brief Find in the list a element that match ID.
 * \param list list of allocations
 * \param id transaction ID
 * \return pointer on allocation_desc or NULL if not found
 */
struct allocation_desc* allocation_list_find_id(struct list_head* list,
    const uint8_t* id);

/**
 * \brief Find in the list a element that match username.
 * \param list list of allocations
 * \param username username
 * \param realm realm
 * \return pointer on allocation_desc or NULL if not found
 */
struct allocation_desc* allocation_list_find_username(struct list_head* list,
    const char* username, const char* realm);

/**
 * \brief Find in the list a element that match the 5-tuple.
 * \param list list of allocations
 * \param transport_protocol transport protocol
 * \param server_addr server address and port
 * \param client_addr client address and port
 * \param addr_size sizeof addr
 * \return pointer on allocation_desc or NULL if not found
 */
struct allocation_desc* allocation_list_find_tuple(struct list_head* list,
    int transport_protocol, const struct sockaddr* server_addr,
    const struct sockaddr* client_addr, socklen_t addr_size);

/**
 * \brief Find in the list a element that match the relayed address.
 * \param list list of allocations
 * \param relayed_addr relayed address and port
 * \param addr_size sizeof addr
 * \return pointer on allocation_desc or NULL if not found
 */
struct allocation_desc* allocation_list_find_relayed(struct list_head* list,
    const struct sockaddr* relayed_addr, socklen_t addr_size);

/**
 * \brief Create a new token.
 * \param id token ID (MUST be 64 bit length)
 * \param sock opened socket
 * \param lifetime lifetime
 * \return pointer on allocation_token or NULL if problem
 */
struct allocation_token* allocation_token_new(uint8_t* id, int sock,
    uint32_t lifetime);

/**
 * \brief Free a token.
 * \param token pointer on pointer allocated by allocation_token_new
 */
void allocation_token_free(struct allocation_token** token);

/**
 * \brief Set timer of an allocation token.
 * \param token allocation descriptor
 * \param lifetime lifetime timer
 */
void allocation_token_set_timer(struct allocation_token* token,
    uint32_t lifetime);

/**
 * \brief Add a token to a list.
 * \param list list of tokens
 * \param token token to add
 */
void allocation_token_list_add(struct list_head* list,
    struct allocation_token* token);

/**
 * \brief Find a specified token.
 * \param list list of tokens
 * \param id token ID (64 bit)
 * \return pointer on allocation_token or NULL if not found
 */
struct allocation_token* allocation_token_list_find(struct list_head* list,
    uint8_t* id);

/**
 * \brief Free a token list.
 * \param list list of tokens
 */
void allocation_token_list_free(struct list_head* list);

/**
 * \brief Remove and free a token from a list.
 * \param list list of allocations
 * \param desc allocation to remove
 */
void allocation_token_list_remove(struct list_head* list,
    struct allocation_token* desc);

#endif /* ALLOCATION_H */

