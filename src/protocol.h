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
 * \file protocol.h
 * \brief Creation of STUN/TURN messages and attributes, helper functions.
 * \author Sebastien Vincent
 * \date 2008-2010
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif

#include "turn.h"
#include "tls_peer.h"

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

#ifndef XOR_PEER_ADDRESS_MAX
/**
 * \def XOR_PEER_ADDRESS_MAX
 * \brief Maximum number of XOR-PEER-ADDRESS attributes in a request.
 */
#define XOR_PEER_ADDRESS_MAX 5
#endif

/**
 * \struct turn_message
 * \brief Structure containing pointers on STUN/TURN header and attributes.
 */
struct turn_message
{
  struct turn_msg_hdr* msg; /**< STUN/TURN header */
  struct turn_attr_mapped_address* mapped_addr; /**< MAPPED-ADDRESS attribute */
  struct turn_attr_xor_mapped_address* xor_mapped_addr; /**< XOR-MAPPED-ADDRESS attribute */
  struct turn_attr_alternate_server* alternate_server; /**< ALTERNATE-SERVER attribute */
  struct turn_attr_nonce* nonce; /**< NONCE attribute */
  struct turn_attr_realm* realm; /**< REALM attribute */
  struct turn_attr_username* username; /**< USERNAME attribute */
  struct turn_attr_error_code* error_code; /**< ERROR-CODE attribute */
  struct turn_attr_unknown_attribute* unknown_attribute; /**< UNKNOWN-ATTRIBUTE attribute */
  struct turn_attr_message_integrity* message_integrity; /**< MESSAGE-INTEGRITY attribute */
  struct turn_attr_fingerprint* fingerprint; /**< FINGERPRINT attribute */
  struct turn_attr_software* software; /**< SOFTWARE attribute */
  struct turn_attr_channel_number* channel_number; /**< CHANNEL-NUMBER attribute */
  struct turn_attr_lifetime* lifetime; /**< LIFETIME attribute */
  struct turn_attr_xor_peer_address* peer_addr[XOR_PEER_ADDRESS_MAX]; /**< XOR-PEER-ADDRESS attribute */
  struct turn_attr_data* data; /**< DATA attribute */
  struct turn_attr_xor_relayed_address* relayed_addr; /**< XOR-RELAYED-ADDRESS attribute */
  struct turn_attr_even_port* even_port; /**< REQUESTED-PROPS attribute */
  struct turn_attr_requested_transport* requested_transport; /**< REQUESTED-TRANSPORT attribute */
  struct turn_attr_dont_fragment* dont_fragment; /**< DONT-FRAGMENT attribute */
  struct turn_attr_reservation_token* reservation_token; /**< RESERVATION-TOKEN attribute */
  struct turn_attr_requested_address_family* requested_addr_family; /**< REQUESTED-ADDRESS-FAMILY attribute (RFC6156) */
  struct turn_attr_connection_id* connection_id; /**< CONNECTION-ID attribute (RFC6062) */
  size_t xor_peer_addr_overflow; /**< If set to 1, not all the XOR-PEER-ADDRESS given in request are in this structure */
};

/* STUN specific error message */

/**
 * \brief Create a complete error 400.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_400(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 401.
 * \param method method used
 * \param id transaction ID
 * \param realm realm value
 * \param nonce nonce value
 * \param nonce_len nonce length
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_401(int method, const uint8_t* id,
    const char* realm, const uint8_t* nonce, size_t nonce_len,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 420.
 * \param method method used
 * \param id transaction ID
 * \param unknown array unknown attributes
 * \param unknown_size sizeof unknown array
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_420(int method, const uint8_t* id,
    const uint16_t* unknown, size_t unknown_size, struct iovec* iov,
    size_t* index);

/**
 * \brief Create a complete error 438.
 * \param method method used
 * \param id transaction ID
 * \param realm realm value
 * \param nonce nonce value
 * \param nonce_len nonce length
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_438(int method, const uint8_t* id,
    const char* realm, const uint8_t* nonce, size_t nonce_len,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 500.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_500(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/* TURN specific error message */

/**
 * \brief Create a complete error 403.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_403(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 437.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_437(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 440.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_440(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 441.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_441(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 442.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_442(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 443.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_443(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 446.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_446(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 447.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_447(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 486.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_486(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a complete error 508.
 * \param method method used
 * \param id transaction ID
 * \param iov vector
 * \param index will be filled with the number of element added
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_error_response_508(int method, const uint8_t* id,
    struct iovec* iov, size_t* index);

/**
 * \brief Create a TURN (or STUN) message.
 * \param type type of the message
 * \param len length of the message without 20 bytes TURN header
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_create(uint16_t type, uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN (or STUN) attribute.
 * \param type type of the attribute
 * \param len length of the attribute
 * \param iov vector
 * \param data data to add
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_create(uint16_t type, uint16_t len,
    struct iovec* iov, const void* data);

/**
 * \brief Create a STUN Binding Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_binding_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a STUN Binding Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_binding_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a STUN Binding Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_binding_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Allocate Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_allocate_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Allocate Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_allocate_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Allocate Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_allocate_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Refresh Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_refresh_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Refresh Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_refresh_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Refresh Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_refresh_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN CreatePermission Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_createpermission_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN CreatePermission Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_createpermission_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN CreatePermission Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_createpermission_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ChannelBind Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_channelbind_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ChannelBind Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_channelbind_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ChannelBind Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_channelbind_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Send Indication.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_send_indication_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Data Indication.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_data_indication_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Connect Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connect_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Connect Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connect_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN Connect Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connect_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ConnectionBind Request.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connectionbind_request_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ConnectionBind Response.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connectionbind_response_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ConnectionBind Error.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connectionbind_error_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a TURN ConnectionAttempt Indication.
 * \param len length of the message
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_msg_hdr or NULL if problem
 */
struct turn_msg_hdr* turn_msg_connectionattempt_indication_create(uint16_t len,
    const uint8_t* id, struct iovec* iov);

/**
 * \brief Create a MAPPED-ADDRESS attribute.
 * \param address address
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_mapped_address_create(
    const struct sockaddr* address, struct iovec* iov);

/**
 * \brief Create a USERNAME attribute.
 * \param username username value
 * \param len username length
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_username_create(const char* username,
    size_t len, struct iovec* iov);

/**
 * \brief Create a MESSAGE-INTEGRITY attribute.
 * \param hmac the SHA1-HMAC (MUST be 20 bytes length)
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_message_integrity_create(const uint8_t* hmac,
    struct iovec* iov);

/**
 * \brief Create a ERROR-CODE attribute.
 * \param code error code
 * \param reason reason string
 * \param len reason string length
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_error_create(uint16_t code, const char* reason,
    size_t len, struct iovec* iov);

/**
 * \brief Create a UNKNOWN-ATTRIBUTE.
 * \param unknown_attributes array of unknown attributes
 * \param attr_size number of element of unknown_attribute array
 * \param iov vector
 */
struct turn_attr_hdr* turn_attr_unknown_attributes_create(
    const uint16_t* unknown_attributes, size_t attr_size, struct iovec* iov);

/**
 * \brief Create a REALM attribute.
 * \param realm text as described in RFC 3261 (including the quotes)
 * \param len length of realm
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_realm_create(const char* realm, size_t len,
    struct iovec* iov);

/**
 * \brief Create a NONCE attribute.
 * \param nonce seqence of quoted-text or quoted-pair which are defined in RFC 3261 (including quotes)
 * \param len length of nonce
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_nonce_create(const uint8_t* nonce, size_t len,
    struct iovec* iov);

/**
 * \brief Create a XOR-MAPPED-ADDRESS attribute.
 * \param address address
 * \param cookie magic cookie
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_xor_mapped_address_create(
    const struct sockaddr* address, uint32_t cookie, const uint8_t* id,
    struct iovec* iov);

/**
 * \brief Create a SOFTWARE attribute.
 * \param software software description
 * \param len length of software
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_software_create(const char* software,
    size_t len, struct iovec* iov);

/**
 * \brief Create a ALTERNATE-SERVER attribute.
 * \param address address
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_alternate_server_create(
    const struct sockaddr* address, struct iovec* iov);

/**
 * \brief Create a FINGERPRINT attribute.
 * \param fingerprint fingerprint
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_fingerprint_create(uint32_t fingerprint,
    struct iovec* iov);

/**
 * \brief Create a CHANNEL-NUMBER attribute.
 * \param number channel number
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_channel_number_create(uint16_t number,
    struct iovec* iov);

/**
 * \brief Create a LIFETIME attribute.
 * \param lifetime lifetime
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_lifetime_create(uint32_t lifetime,
    struct iovec* iov);

/**
 * \brief Create a XOR-PEER-ADDRESS attribute.
 * \param address address
 * \param cookie magic cookie
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_xor_peer_address_create(
    const struct sockaddr* address, uint32_t cookie, const uint8_t* id,
    struct iovec* iov);

/**
 * \brief Create a DATA attribute.
 * \param data data
 * \param datalen length of data
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_data_create(const void* data, size_t datalen,
    struct iovec* iov);

/**
 * \brief Create a XOR-RELAYED-ADDRESS attribute.
 * \param address address
 * \param cookie magic cookie
 * \param id 96 bit transaction ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_xor_relayed_address_create(
    const struct sockaddr* address, uint32_t cookie, const uint8_t* id,
    struct iovec* iov);

/**
 * \brief Create a REQUESTED-PROPS attribute.
 * \param flags flags value (for the moment just R flag are defined => 0x80)
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_even_port_create(uint8_t flags,
    struct iovec* iov);

/**
 * \brief Create a REQUESTED-TRANSPORT attribute.
 * \param protocol transport protocol
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_requested_transport_create(uint8_t protocol,
    struct iovec* iov);

/**
 * \brief Create a DONT-FRAGMENT attribute.
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_dont_fragment_create(struct iovec* iov);

/**
 * \brief Create a RESERVATION-TOKEN attribute.
 * \param token token (must be 8 bytes length)
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_reservation_token_create(const uint8_t* token,
    struct iovec* iov);

/**
 * \brief Create a REQUESTED-ADDRESS-FAMILY attribute.
 * \param family family requested (IPv4 or IPv6)
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_requested_address_family_create(uint8_t family,
    struct iovec* iov);

/**
 * \brief Create a CONNECTION-ID attribute.
 * \param id 32 bits ID
 * \param iov vector
 * \return pointer on turn_attr_hdr or NULL if problem
 */
struct turn_attr_hdr* turn_attr_connection_id_create(uint32_t id,
    struct iovec* iov);

/**
 * \brief Send TURN message (which may contains attributes) over UDP.
 * \param sock socket
 * \param addr destination address
 * \param addr_size sizeof addr
 * \param iov vector which contains messages and attributes
 * \param iovlen number of element in iov
 * \return number of bytes sent or -1 if error
 */
int turn_udp_send(int sock, const struct sockaddr* addr, socklen_t addr_size,
    const struct iovec* iov, size_t iovlen);

/**
 * \brief Send TURN message (which may contains attributes) over TCP.
 * \param sock socket
 * \param iov vector which contains messages and attributes
 * \param iovlen number of element in iov
 * \return number of bytes sent or -1 if error
 */
int turn_tcp_send(int sock, const struct iovec* iov, size_t iovlen);

/**
 * \brief Send TURN message (which may contains attributes) over TLS (over TCP).
 * \param peer TLS peer
 * \param addr destination address
 * \param addr_size sizeof addr
 * \param total_len total length of the message to send
 * \param iov vector which contains messages and attributes
 * \param iovlen number of element in iov
 * \return number of bytes sent or -1 if error
 */
int turn_tls_send(struct tls_peer* peer, const struct sockaddr* addr,
    socklen_t addr_size, size_t total_len, const struct iovec* iov,
    size_t iovlen);

/**
 * \brief Send TURN message.
 * \param transport_protocol transport protocol of the socket (TCP or UDP)
 * \param sock socket descriptor
 * \param speer TLS peer if send with TLS (could be NULL)
 * \param addr destination address
 * \param addr_size sizeof addr
 * \param total_len total length of the message to send
 * \param iov vector which contains messages and attributes
 * \param iovlen number of element in iov
 * \return number of bytes sent or -1 if error
 */
int turn_send_message(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, size_t total_len,
    const struct iovec* iov, size_t iovlen);

/**
 * \brief Generate a 96 bit transaction ID.
 * \param id that will be filled with username value (MUST be 12 bytes length)
 * \return 0 if success, -1 otherwise
 * \warning id array MUST have 16 bytes length
 */
int turn_generate_transaction_id(uint8_t* id);

/**
 * \brief Generate a nonce value.
 *
 * nonce = 64-bit timestamp MD5(timestamp ":" key)
 *
 * When time_t is 4 bytes, the timestamp is padded with 0x30.
 *
 * \param nonce array that will be filled
 * \param len length of nonce
 * \param key key used
 * \param key_len key length
 * \return 0 if success, -1 otherwise
 */
int turn_generate_nonce(uint8_t* nonce, size_t len, uint8_t* key,
    size_t key_len);

/**
 * \brief Check if nonce is stale.
 * \param nonce nonce
 * \param len length of nonce
 * \param key nonce key
 * \param key_len length of the key
 * \return 1 if nonce is stale, 0 otherwise
 */
int turn_nonce_is_stale(uint8_t* nonce, size_t len, unsigned char* key,
    size_t key_len);

/**
 * \brief Calculate the MD5 key for long-term authentication.
 *
 * Key is compute as follow MD5(login ":" realm ":" password).
 * \param username username
 * \param realm realm
 * \param password password
 * \param key key (MUST be at least 16 bytes)
 * \param key_len length of the key (minimum 16 bytes)
 * \return 0 if success, 0 otherwise
 */
int turn_calculate_authentication_key(const char* username, const char* realm,
    const char* password, unsigned char* key, size_t key_len);

/**
 * \brief Calculate the HMAC-SHA1 hash.
 * \param buf buffer entry buffer to calculate HMAC
 * \param len length of the buffer
 * \param key key used to hash
 * \param key_len length of key
 * \param integrity buffer that will received HMAC hash (MUST be at least 20
 * bytes length)
 * \return 0 if success, -1 otherwise
 */
int turn_calculate_integrity_hmac(const unsigned char* buf, size_t len,
    const unsigned char* key, size_t key_len, unsigned char* integrity);

/**
 * \brief Calculate the HMAC-SHA1 hash.
 * \param iov vector which contains a message and attributes (without
 * MESSAGE-INTEGRITY)
 * \param iovlen number of element in iov
 * \param key key used to hash
 * \param key_len length of key
 * \param integrity buffer that will received HMAC hash (MUST be at least 20
 * bytes length)
 * \return 0 if success, -1 otherwise
 */
int turn_calculate_integrity_hmac_iov(const struct iovec* iov, size_t iovlen,
    const unsigned char* key, size_t key_len, unsigned char* integrity);

/**
 * \brief Calculate the fingerprint using CRC-32 from ITU V.42.
 * \param iov vector which contains a message and attributes (without
 * FINGERPRINT)
 * \param iovlen number of element in iov
 * \return 32 bit fingerprint
 */
uint32_t turn_calculate_fingerprint(const struct iovec* iov, size_t iovlen);

/**
 * \brief Compute and add MESSAGE-INTEGRITY and optionnally FINGERPRINT
 * attributes to message.
 * \param iov vector which contains a message and attributes
 * \param index index in the vector, it will be updated to the next unused
 * position if function succeed
 * \param key key used to hash
 * \param key_len length of key
 * \param add_fingerprint if set to 1, this function add FINGERPRINT attribute
 * \return 0 if success, -1 otherwise
 * \note This function set turn_msg_len field of TURN message to big endian (as
 * MESSAGE-INTEGRITY/FINGERPRINT are normally the last attributes added).
 */
int turn_add_message_integrity(struct iovec* iov, size_t* index,
    const unsigned char* key, size_t key_len, int add_fingerprint);

/**
 * \brief Compute fingerprint and add it to the message.
 * \param iov vector which contains a message and attributes
 * \param index index in the vector, it will be updated to the next unused
 * position if function succeed
 * \return 0 if success, -1 if failure
 */
int turn_add_fingerprint(struct iovec* iov, size_t* index);

/**
 * \brief (Address and port) XOR cookie.
 * \param family address famiily
 * \param peer_addr peer address (which contains already XORed address),
 * it will be filled with de-XORed address
 * \param peer_port peer port (which contains already XORed port), it will be
 * filled with de-XORed port
 * \param cookie cookie
 * \param msg_id ID of the message
 * \return 0 if success, -1 otherwise
 */
int turn_xor_address_cookie(int family, uint8_t* peer_addr, uint16_t* peer_port,
    const uint8_t* cookie, const uint8_t* msg_id);

/**
 * \brief Parse a STUN/TURN message.
 * \param msg raw buffer containing the message
 * \param msg_len size of buffer
 * \param message structures that will contains pointer on message header and
 * attributes.
 * \param unknown array that will be filled with unknown attributes
 * \param unknown_size sizeof initial array, will be filled with the number of
 * unknown options found
 * \return 0 if success, 1 if unknown comprehension-required attributes are
 * found, -1 if problem (malformed packet)
 * \warning If there are more than unknown_size attributes, they will not be put
 * in the array.
 */
int turn_parse_message(const char* msg, ssize_t msg_len,
    struct turn_message* message, uint16_t* unknown, size_t* unknown_size);

#ifdef __cplusplus
}
#endif

#endif /* PROTOCOL_H */

