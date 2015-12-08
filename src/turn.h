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
 * \file turn.h
 * \brief Header definition for STUN/TURN messages and attributes.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifndef TURN_H
#define TURN_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef _MSC_VER
#include <windows.h>
/* replace stdint.h types for MS Windows */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
/* __attribute__ is a GCC extension
 * and it is not recognized by Microsoft
 * compiler, so define it as nothing
 */
#define __attribute__(x)
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
#extern "C" { /* } */
#endif

/* STUN message classes */
#define STUN_REQUEST                    0x0000
#define STUN_INDICATION                 0x0010
#define STUN_SUCCESS_RESP               0x0100
#define STUN_ERROR_RESP                 0x0110

/* macros from RFC5389 to determine if message is a request,
 * success/error response or indication
 */
#define STUN_IS_REQUEST(msg_type)      (((msg_type) & 0x0110) == STUN_REQUEST)
#define STUN_IS_INDICATION(msg_type)   (((msg_type) & 0x0110) == STUN_INDICATION)
#define STUN_IS_SUCCESS_RESP(msg_type) (((msg_type) & 0x0110) == STUN_SUCCESS_RESP)
#define STUN_IS_ERROR_RESP(msg_type)   (((msg_type) & 0x0110) == STUN_ERROR_RESP)

/* bit 0 and 1 are not set to 0 */
#define TURN_IS_CHANNELDATA(msg_type)  (((msg_type) & 0xC000) != 0)

#define STUN_GET_METHOD(msg_type)      ((msg_type) & 0x3EEF)
#define STUN_GET_CLASS(msg_type)       ((msg_type) & 0x0110)

/* macros to determine if an attribute is comprehension-required or
 * comprehension-optional
 */
#define STUN_IS_COMPREHENSION_REQUIRED(attr_type) (!((attr_type) & 0x8000))
#define STUN_IS_COMPREHENSION_OPTIONAL(attr_type) (((attr_type) & 0x8000))

/* Request/Response transactions */

/* Binding method */
#define STUN_METHOD_BINDING            0x0001

/* Allocate method */
#define TURN_METHOD_ALLOCATE           0x0003

/* Refresh method */
#define TURN_METHOD_REFRESH            0x0004

/* CreatePermission method */
#define TURN_METHOD_CREATEPERMISSION   0x0008

/* ChannelBind method */
#define TURN_METHOD_CHANNELBIND        0x0009

/* Connect method (RFC6062) */
#define TURN_METHOD_CONNECT            0x000A

/* ConnectionBind method (RFC6062) */
#define TURN_METHOD_CONNECTIONBIND     0x000B

/* Indications */

/* Send method */
#define TURN_METHOD_SEND               0x0006

/* Data method */
#define TURN_METHOD_DATA               0x0007

/* ConnectionAttempt method (RFC6062) */
#define TURN_METHOD_CONNECTIONATTEMPT  0x000C

/* standard STUN attributes */

/* MAPPED-ADDRESS */
#define STUN_ATTR_MAPPED_ADDRESS       0x0001

/* USERNAME */
#define STUN_ATTR_USERNAME             0x0006

/* MESSAGE-INTEGRITY */
#define STUN_ATTR_MESSAGE_INTEGRITY    0x0008

/* ERROR-CODE */
#define STUN_ATTR_ERROR_CODE           0x0009

/* UNKNOWN-ATTRIBUTES */
#define STUN_ATTR_UNKNOWN_ATTRIBUTES   0x000A

/* REALM */
#define STUN_ATTR_REALM                0x0014

/* NONCE */
#define STUN_ATTR_NONCE                0x0015

/* XOR-MAPPED-ADDRESS */
#define STUN_ATTR_XOR_MAPPED_ADDRESS   0x0020

/* SOFTWARE */
#define STUN_ATTR_SOFTWARE             0x8022

/* ALTERNATE-SERVER */
#define STUN_ATTR_ALTERNATE_SERVER     0x8023

/* FINGERPRINT */
#define STUN_ATTR_FINGERPRINT          0x8028

/* TURN attributes */

/* CHANNEL-NUMBER */
#define TURN_ATTR_CHANNEL_NUMBER       0x000C

/* LIFETIME */
#define TURN_ATTR_LIFETIME             0x000D

/* PEER-ADDRESS */
#define TURN_ATTR_XOR_PEER_ADDRESS     0x0012

/* DATA */
#define TURN_ATTR_DATA                 0x0013

/* RELAYED-ADDRESS */
#define TURN_ATTR_XOR_RELAYED_ADDRESS  0x0016

/* EVEN-PORT */
#define TURN_ATTR_EVEN_PORT            0x0018

/* REQUESTED-TRANSPORT */
#define TURN_ATTR_REQUESTED_TRANSPORT  0x0019

/* DONT-FRAGMENT */
#define TURN_ATTR_DONT_FRAGMENT        0X001A

/* RESERVATION-TOKEN */
#define TURN_ATTR_RESERVATION_TOKEN    0x0022

/* REQUESTED-ADDRESS-FAMILY (RFC6156) */
#define TURN_ATTR_REQUESTED_ADDRESS_FAMILY  0x0017

/* CONNECTION-ID (RFC6062) */
#define TURN_ATTR_CONNECTION_ID        0x002A

/* STUN error codes */
#define STUN_ERROR_TRY_ALTERNATE       300
#define STUN_ERROR_BAD_REQUEST         400
#define STUN_ERROR_UNAUTHORIZED        401
#define STUN_ERROR_UNKNOWN_ATTRIBUTE   420
#define STUN_ERROR_STALE_NONCE         438
#define STUN_ERROR_SERVER_ERROR        500

/* TURN error codes */
#define TURN_ERROR_FORBIDDEN                      403
#define TURN_ERROR_ALLOCATION_MISMATCH            437
#define TURN_ERROR_WRONG_CREDENTIALS              441
#define TURN_ERROR_UNSUPPORTED_TRANSPORT_PROTOCOL 442
#define TURN_ERROR_ALLOCATION_QUOTA_REACHED       486
#define TURN_ERROR_INSUFFICIENT_CAPACITY          508

/* RFC6156 (TURN-IPV6) */
#define TURN_ERROR_ADDRESS_FAMILY_NOT_SUPPORTED   440
#define TURN_ERROR_PEER_ADDRESS_FAMILY_MISMATCH   443

/* RFC6062 (TURN-TCP) */
#define TURN_ERROR_CONNECTON_ALREADY_EXIST        446
#define TURN_ERROR_CONNECTON_TIMEOUT              447

/* STUN error recommended reasons */
#define STUN_ERROR_300            "Try Alternate"
#define STUN_ERROR_400            "Bad request"
#define STUN_ERROR_401            "Unauthorized"
#define STUN_ERROR_420            "Unknown attribute(s)"
#define STUN_ERROR_438            "Stale nonce"
#define STUN_ERROR_500            "Server error"

/* TURN error recommended reasons */
#define TURN_ERROR_403            "Forbidden"
#define TURN_ERROR_437            "Allocation mismatch"
#define TURN_ERROR_441            "Wrong credentials"
#define TURN_ERROR_442            "Unsupported transport protocol"
#define TURN_ERROR_486            "Allocation quota reached"
#define TURN_ERROR_508            "Insufficient capacity"

/* RFC6156 (TURN-IPV6) */
#define TURN_ERROR_440            "Address family not supported"
#define TURN_ERROR_443            "Peer address family mismatch"

/* RFC6062 (TURN-TCP) */
#define TURN_ERROR_446            "Connection Already Exists"
#define TURN_ERROR_447            "Connection Timeout or Failure"

/* STUN magic cookie */
#define STUN_MAGIC_COOKIE              0x2112A442

/* STUN FINGERPRINT XOR value */
#define STUN_FINGERPRINT_XOR_VALUE     0x5354554E

/* family address for MAPPED-ADDRESS like attributes */
#define STUN_ATTR_FAMILY_IPV4          0x01
#define STUN_ATTR_FAMILY_IPV6          0x02

/* default allocation lifetime (in seconds) unless refreshed */
#define TURN_DEFAULT_ALLOCATION_LIFETIME      600

/* maximum allocation lifetime (in seconds) unless refreshed */
#define TURN_MAX_ALLOCATION_LIFETIME          3600

/* default permission lifetime (in seconds) unless refreshed */
#define TURN_DEFAULT_PERMISSION_LIFETIME      300

/* default channel lifetime (in seconds) unless refreshed */
#define TURN_DEFAULT_CHANNEL_LIFETIME         600

/* lifetime of a nonce (in seconds) */
#define TURN_DEFAULT_NONCE_LIFETIME           3600

/* lifetime of a token (in seconds) */
#define TURN_DEFAULT_TOKEN_LIFETIME           60

/* RFC6062 (TURN-TCP) */
/* Timeout of TCP relay when no ConnectionBind is received (in seconds) */
#define TURN_DEFAULT_TCP_RELAY_TIMEOUT        30

/* RFC6062 (TURN-TCP) */
/* Timeout of TCP connect (in seconds) */
#define TURN_DEFAULT_TCP_CONNECT_TIMEOUT      30

/* Microsoft compiler use pragma pack to "packed" structure
 * instead of GCC that use __attribute__((packed)
 */
#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

/**
 * \struct turn_msg_hdr
 * \brief STUN/TURN message header.
 */
struct turn_msg_hdr
{
  uint16_t turn_msg_type; /**< Message type (first 2 bit are always set to 0) */
  uint16_t turn_msg_len; /**< Message length (without the 20 bytes of this
                           header) */
  uint32_t turn_msg_cookie; /**< Magic Cookie */
  uint8_t turn_msg_id[12]; /**< Transaction ID (96 bit) */
}__attribute__((packed));

/**
 * \struct turn_attr_hdr
 * \brief STUN/TURN attribute header.
 */
struct turn_attr_hdr
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_value[]; /**< Variable-size value */
}__attribute__((packed));

/**
 * \struct turn_attr_mapped_address
 * \brief MAPPED-ADDRESS attribute.
 */
struct turn_attr_mapped_address
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_reserved; /**< Ignored */
  uint8_t turn_attr_family; /**< Family: 0x01 = IPv4, 0x02 = IPv6 */
  uint16_t turn_attr_port; /**< Port in network byte order */
  uint8_t turn_attr_address[]; /**< Variable-size address */
}__attribute__((packed));

/**
 * \struct turn_attr_username
 * \brief USERNAME attribute
 */
struct turn_attr_username
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_username[]; /**< Username */
}__attribute__((packed));

/**
 * \struct turn_attr_message_integrity
 * \brief MESSAGE-INTEGRITY attribute.
 */
struct turn_attr_message_integrity
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_hmac[20]; /**< HMAC value */
}__attribute__((packed));

/**
 * \struct turn_attr_error_code
 * \brief ERROR-CODE attribute.
 */
struct turn_attr_error_code
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_reserved_class : 24; /**< 21 bit reserved (value = 0) and 3
                                            bit which indicates hundred digits
                                            of the response code (3 - 6) */
  uint32_t turn_attr_number : 8; /**< Number (0 - 99) */
  uint8_t turn_attr_reason[]; /**< Variable-size reason */
}__attribute__((packed));

/**
 * \struct turn_attr_unknown_attribute
 * \brief UNKNWON-ATTRIBUTE attribute.
 */
struct turn_attr_unknown_attribute
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_attributes[]; /**< Multiple of 4 attributes (each 16 bit) */
}__attribute__((packed));

/**
 * \struct turn_attr_realm
 * \brief REALM attribute.
 */
struct turn_attr_realm
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_realm[]; /**< Realm */
}__attribute__((packed));

/**
 * \struct turn_attr_nonce
 * \brief NONCE attribute.
 */
struct turn_attr_nonce
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_nonce[]; /**< Nonce */
}__attribute__((packed));

/**
 * \struct turn_attr_xor_mapped_address
 * \brief XOR-MAPPED-ADDRESS attribute.
 */
struct turn_attr_xor_mapped_address
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_reserved; /**< Ignored */
  uint8_t turn_attr_family; /**< Family: 0x01 = IPv4, 0x02 = IPv6 */
  uint16_t turn_attr_port; /**< Port in network byte order */
  uint8_t turn_attr_address[]; /**< Variable-size address */
}__attribute__((packed));

/**
 * \struct turn_attr_software
 * \brief SOFTWARE attribute.
 */
struct turn_attr_software
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_software[]; /**< Textual description of the software */
}__attribute__((packed));

/**
 * \struct turn_attr_alternate_server
 * \brief ALTERNATE-SERVER attribute.
 */
struct turn_attr_alternate_server
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_reserved; /**< Ignored */
  uint8_t turn_attr_family; /**< Family: 0x01 = IPv4, 0x02 = IPv6 */
  uint16_t turn_attr_port; /**< Port in network byte order */
  uint8_t turn_attr_address[]; /**< Variable-size address */
}__attribute__((packed));

/**
 * \struct turn_attr_fingerprint
 * \brief FINGERPRINT attribute.
 */
struct turn_attr_fingerprint
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_crc; /**< CRC-32 */
}__attribute__((packed));

/**
 * \struct turn_attr_channel_number
 * \brief CHANNEL-NUMBER attribute.
 */
struct turn_attr_channel_number
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint16_t turn_attr_number; /**< Channel number value */
  uint16_t turn_attr_rffu; /**< Reserved For Future Use, must be 0 */
}__attribute__((packed));

/**
 * \struct turn_attr_lifetime
 * \brief LIFETIME attribute.
 */
struct turn_attr_lifetime
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_lifetime; /**< Lifetime of the binding */
}__attribute__((packed));

/**
 * \struct turn_attr_xor_peer_address
 * \brief XOR-PEER-ADDRESS attribute.
 */
struct turn_attr_xor_peer_address
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_reserved; /**< Ignored */
  uint8_t turn_attr_family; /**< Family: 0x01 = IPv4, 0x02 = IPv6 */
  uint16_t turn_attr_port; /**< Port in network byte order */
  uint8_t turn_attr_address[]; /**< Variable-size address */
}__attribute__((packed));

/**
 * \struct turn_attr_data
 * \brief DATA attribute.
 */
struct turn_attr_data
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_data[]; /**< Raw data payload */
}__attribute__((packed));

/**
 * \struct turn_attr_xor_relayed_address
 * \brief XOR-RELAYED-ADDRESS attribute.
 */
struct turn_attr_xor_relayed_address
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_reserved; /**< Ignored */
  uint8_t turn_attr_family; /**< Family: 0x01 = IPv4, 0x02 = IPv6 */
  uint16_t turn_attr_port; /**< Port in network byte order */
  uint8_t turn_attr_address[]; /**< Variable-size address */
}__attribute__((packed));

/**
 * \struct turn_attr_even_port
 * \brief EVENT-PORT attribute.
 */
struct turn_attr_even_port
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_flags; /**< Flags (just R flag are defined in RFC5766) */
}__attribute__((packed));

/**
 * \struct turn_attr_requested_transport
 * \brief REQUESTED-TRANSPORT attribute.
 */
struct turn_attr_requested_transport
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_protocol : 8; /**< Transport protocol number */
  uint32_t turn_attr_reserved : 24; /**< Reserved, must be 0 */
}__attribute__((packed));

/**
 * \struct turn_attr_dont_fragment
 * \brief DONT-FRAGMENT attribute.
 */
struct turn_attr_dont_fragment
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
}__attribute__((packed));

/**
 * \struct turn_attr_reservation_token
 * \brief RESERVATION-TOKEN attribute.
 */
struct turn_attr_reservation_token
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint8_t turn_attr_token[8]; /**< Token */
}__attribute__((packed));

/**
 * \struct turn_channel_data
 * \brief ChannelData packet.
 */
struct turn_channel_data
{
  uint16_t turn_channel_number; /**< Channel number */
  uint16_t turn_channel_len; /**< Length of the data */
  uint8_t turn_channel_data[]; /**< Data */
}__attribute__((packed));

/**
 * \struct turn_attr_requested_address_family.
 * \brief REQUESTED-ADDRESS-FAMILY attribute (RFC6156).
 */
struct turn_attr_requested_address_family
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_family : 8; /**<  Family (IPv4 or IPv6) requested */
  uint32_t turn_attr_reserved : 24; /**< Reserved */
}__attribute__((packed));

/**
 * \struct turn_attr_connection_id
 * \brief CONNECTION-ID attribute (RFC6062).
 */
struct turn_attr_connection_id
{
  uint16_t turn_attr_type; /**< Attribute type */
  uint16_t turn_attr_len; /**< Length of "value" */
  uint32_t turn_attr_id; /**<  Connection ID */
}__attribute__((packed));

/* end of "packed" structure for Microsoft compiler */
#ifdef _MSC_VER
#pragma pack(pop)
#endif

#ifdef __cplusplus
}
#endif

#endif /* TURN_H */

