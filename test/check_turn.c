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
 * \file check_turn.c
 * \brief Unit tests for TURN messages and attributes generation.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#include <stdlib.h>
#include <string.h>

#include <check.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "../src/util_sys.h"
#include "../src/turn.h"
#include "../src/protocol.h"

START_TEST(test_attr_create)
{
  struct iovec iov[50];
  size_t index = 0;
  ssize_t nb = -1;
  index = 0;
  uint8_t id[12];
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct turn_attr_hdr* attr2 = NULL;
  struct sockaddr_in daddr;
  struct sockaddr_in daddr2;
  struct msghdr msg;
  int sock = -1;
  unsigned char md_buf[16]; /* MD5 */

  nb = turn_generate_transaction_id(id);
  fail_unless(nb == 0, "Failed to generate transaction ID.");

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  daddr.sin_family = AF_INET;
  daddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  daddr.sin_port = htons(3478);
  memset(daddr.sin_zero, 0x00, sizeof(daddr.sin_zero));

  daddr2.sin_family = AF_INET;
  daddr2.sin_addr.s_addr = inet_addr("192.168.0.1");
  daddr2.sin_port = htons(444);
  memset(daddr2.sin_zero, 0x00, sizeof(daddr2.sin_zero));

  /* Allocate request */
  hdr = turn_msg_allocate_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* MAPPED-ADDRESS */
  attr = turn_attr_mapped_address_create((struct sockaddr*)&daddr2,
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-MAPPED-ADDRESS */
  attr = turn_attr_xor_mapped_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-RELAYED-ADDRESS */
  attr = turn_attr_xor_relayed_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* ALTERNATE-SERVER */
  attr = turn_attr_alternate_server_create((struct sockaddr*)&daddr2,
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* NONCE */
  {
    unsigned char* key = "Calamar power";
    size_t len = strlen(key);
    uint8_t nonce_value[48];

    nb = turn_generate_nonce(nonce_value, sizeof(nonce_value), key, len);
    fail_unless(nb == 0, "generate nonce failed");

    attr = turn_attr_nonce_create(nonce_value, sizeof(nonce_value),
        &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* REALM */
  attr = turn_attr_realm_create("heyrealm", strlen("heyrealm"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create("ping6", strlen("ping6"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* ERROR-CODE */
  attr = turn_attr_error_create(400, "Bad request", strlen("Bad request"),
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* UNKNOWN-ATTRIBUTE */
  {
    uint16_t tab[3] = {0x0002, 0x0001, 0x0003};
    uint16_t tab2[4] = {0x0001, 0x0002, 0x0003, 0x0004};

    attr = turn_attr_unknown_attributes_create(tab,
        sizeof(tab) / sizeof(uint16_t), &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    attr = turn_attr_unknown_attributes_create(tab2,
        sizeof(tab2) / sizeof(uint16_t), &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* DATA */
  attr = turn_attr_data_create("data", strlen("data"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* CHANNEL-NUMBER */
  attr = turn_attr_channel_number_create(0xBEEF, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* LIFETIME */
  attr = turn_attr_lifetime_create(0x00000005, &iov[index]); /* 5 second */
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create("Client TURN 0.1 test",
      strlen("Client TURN 0.1 test"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REQUESTED-TRANSPORT */
  attr = turn_attr_requested_transport_create(IPPROTO_UDP, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* EVEN-PORT */
  attr = turn_attr_even_port_create(0x80, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* DONT-FRAGMENT */
  attr = turn_attr_dont_fragment_create(&iov[index]);
  fail_unless(attr != NULL, "attribute header create failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* MESSAGE-INTEGRITY */
  attr = turn_attr_message_integrity_create(NULL, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;

  nb = index; /* number of element before MESSAGE-INTEGRITY */
  index++;

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* after convert STUN/TURN message length to big endian we can calculate
   * HMAC-SHA1
   */
  /* index -1 because we do not take into account MESSAGE-INTEGRITY attribute */
  md5_generate(md_buf, "login:domain.org:password",
      strlen("login:domain.org:password"));
  turn_calculate_integrity_hmac_iov(iov, index - 1, md_buf, sizeof(md_buf),
      ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);
  attr2 = attr;

  /* test CRC-32 */
  {
    unsigned char buf[40];
    uint32_t crc = 0;
    uint32_t crc_hello = htonl(0x86a61036);

    strncpy(buf, "hello", 40);
    buf[39] = 0x00;

    crc = crc32_generate(buf, strlen("hello"), 0);
    nb = memcmp(&crc, &crc_hello, sizeof(uint32_t));
    fail_unless(nb == 0, "CRC32 failed!");
  }

  /* FINGERPRINT */
  attr = turn_attr_fingerprint_create(0, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len = ntohs(hdr->turn_msg_len) + iov[index].iov_len;
  index++;

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* calculate fingerprint */
  /* index -1, we do not take into account FINGERPRINT attribute */
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc =
    htonl(turn_calculate_fingerprint(iov, index - 1));
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^=
    htonl(STUN_FINGERPRINT_XOR_VALUE);

  nb = turn_udp_send(sock, (struct sockaddr*)&daddr, sizeof(daddr), iov, index);
  fail_unless(nb > 0, "turn_udp_send failed");

  /* check message integrity */
  {
    unsigned char hashmac[20];
    uint16_t len_save = hdr->turn_msg_len; /* store in big endian */

    /* verify integrity with valid login/realm/password */
    md5_generate(md_buf, "login:domain.org:password",
        strlen("login:domain.org:password"));

    /* change length up to message integrity */
    hdr->turn_msg_len = ntohs(hdr->turn_msg_len) - sizeof(
        struct turn_attr_fingerprint);
    hdr->turn_msg_len = htons(hdr->turn_msg_len);

    turn_calculate_integrity_hmac_iov(iov, index - 2, md_buf, sizeof(md_buf),
        hashmac);
    nb = memcmp(hashmac,
        ((struct turn_attr_message_integrity*)attr2)->turn_attr_hmac, 20);
    fail_unless(nb == 0, "hmac integrity failed");

    /* verify integrity with invalid login/realm/password */
    memset(hashmac, 0x00, 20);
    md5_generate(md_buf, "login2:domain.org:password",
        strlen("login2:domain.org:password"));
    turn_calculate_integrity_hmac_iov(iov, index - 2, md_buf, sizeof(md_buf),
        hashmac);
    nb = memcmp(hashmac,
        ((struct turn_attr_message_integrity*)attr2)->turn_attr_hmac, 20);
    fail_unless(nb != 0, "hmac integrity succeed");

    /* restore length value */
    hdr->turn_msg_len = len_save;
  }

  /* check fingerprint */
  {
    uint32_t crc = turn_calculate_fingerprint(iov, index - 1);
    fail_unless(htonl(crc) ^ htonl(STUN_FINGERPRINT_XOR_VALUE) ==
        ((struct turn_attr_fingerprint*)attr)->turn_attr_crc,
        "Fingerprint check");
  }

  iovec_free_data(iov, index);
  close(sock);
}
END_TEST

START_TEST(test_msg_create)
{
  struct iovec iov[50];
  size_t index = 0;
  ssize_t nb = -1;
  index = 0;
  char id[12];
  struct turn_msg_hdr* hdr = NULL;
  struct sockaddr_in daddr;
  struct msghdr msg;
  int sock = -1;
  size_t i = 0;

  sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  daddr.sin_family = AF_INET;
  daddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  daddr.sin_port = htons(3478);
  memset(daddr.sin_zero, 0x00, sizeof(daddr.sin_zero));

  nb = turn_generate_transaction_id(id);
  fail_unless(nb == 0, "Failed to generate transaction ID.");

  /* Allocate response */
  hdr = turn_msg_allocate_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* add an unknown comprehension-required attributes */
  turn_attr_create(0x7FFE, 4, &iov[index], &sock);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  nb = turn_udp_send(sock, (struct sockaddr*)&daddr, sizeof(daddr), iov, index);
  fail_unless(nb > 0, "turn_udp_send failed");

  index = 0;

  /* Binding request */
  hdr = turn_msg_binding_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Binding response */
  hdr = turn_msg_binding_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Binding error */
  hdr = turn_msg_binding_error_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Allocate request */
  hdr = turn_msg_allocate_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Allocate response */
  hdr = turn_msg_allocate_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Allocate error */
  hdr = turn_msg_allocate_error_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* ChannelBind request */
  hdr = turn_msg_channelbind_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* ChannelBind response */
  hdr = turn_msg_channelbind_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* ChannelBind error */
  hdr = turn_msg_channelbind_error_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* CreatePermission request */
  hdr = turn_msg_createpermission_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* CreatePermission response */
  hdr = turn_msg_createpermission_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* CreatePermission error */
  hdr = turn_msg_createpermission_error_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Refresh request */
  hdr = turn_msg_refresh_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Refresh error */
  hdr = turn_msg_refresh_response_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Refresh error */
  hdr = turn_msg_refresh_error_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Send indication */
  hdr = turn_msg_send_indication_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* Data indication request */
  hdr = turn_msg_data_indication_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  for(i = 0 ; i < index ; i++)
  {
    nb = turn_udp_send(sock, (struct sockaddr*)&daddr, sizeof(daddr), &iov[i],
        1);
    fail_unless(nb > 0, "sendmsg failed");
  }

  iovec_free_data(iov, index);
  close(sock);
}
END_TEST

START_TEST(test_message_parse)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct sockaddr_in daddr;
  struct sockaddr_in daddr2;
  struct iovec iov[50];
  char buf[1500];
  int nb = 0;
  size_t index = 0;
  uint8_t id[12];
  uint16_t tab[16];
  size_t tab_size = 16;
  unsigned char md_buf[16];

  nb = turn_generate_transaction_id(id);
  fail_unless(nb == 0, "Failed to generate transaction ID.");

  daddr.sin_family = AF_INET;
  daddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  daddr.sin_port = htons(3478);
  memset(daddr.sin_zero, 0x00, sizeof(daddr.sin_zero));

  daddr2.sin_family = AF_INET;
  daddr2.sin_addr.s_addr = inet_addr("192.168.0.1");
  daddr2.sin_port = htons(444);
  memset(daddr2.sin_zero, 0x00, sizeof(daddr2.sin_zero));

  /* Allocate request */
  hdr = turn_msg_allocate_request_create(0, id, &iov[index]);
  fail_unless(hdr != NULL, "header creation failed");
  index++;

  /* MAPPED-ADDRESS */
  attr = turn_attr_mapped_address_create((struct sockaddr*)&daddr2,
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-MAPPED-ADDRESS */
  attr = turn_attr_xor_mapped_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-RELAYED-ADDRESS */
  attr = turn_attr_xor_relayed_address_create((struct sockaddr*)&daddr2,
      STUN_MAGIC_COOKIE, id, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* ALTERNATE-SERVER */
  attr = turn_attr_alternate_server_create((struct sockaddr*)&daddr2,
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create("\"heynonce\"", strlen("\"heynonce\""),
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create("heyrealm", strlen("heyrealm"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create("ping6", strlen("ping6"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* ERROR-CODE */
  attr = turn_attr_error_create(420, "Bad request", strlen("Bad request"),
      &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* UNKNOWN-ATTRIBUTE */
  {
    uint16_t tab[3] = {0x0002, 0x0001, 0x0003};
    uint16_t tab2[4] = {0x0001, 0x0002, 0x0003, 0x0004};

    attr = turn_attr_unknown_attributes_create(tab,
        sizeof(tab) / sizeof(uint16_t), &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    attr = turn_attr_unknown_attributes_create(tab2,
        sizeof(tab2) / sizeof(uint16_t), &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* DATA */
  attr = turn_attr_data_create("data", strlen("data"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* CHANNEL-NUMBER */
  attr = turn_attr_channel_number_create(0xBEEF, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* LIFETIME */
  attr = turn_attr_lifetime_create(0xDEADBEEF, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create("Client TURN 0.1 test",
      strlen("Client TURN 0.1 test"), &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REQUESTED-TRANSPORT */
  attr = turn_attr_requested_transport_create(IPPROTO_UDP, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* EVEN-PORT */
  attr = turn_attr_even_port_create(0x80, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* RESERVATION-TOKEN */
  {
    uint8_t token[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    attr = turn_attr_reservation_token_create(token, &iov[index]);
    fail_unless(attr != NULL, "attribute header creation failed");
    hdr->turn_msg_len += iov[index].iov_len;
    index++;
  }

  /* DONT-FRAGMENT */
  attr = turn_attr_dont_fragment_create(&iov[index]);
  fail_unless(attr != NULL, "attribute header create failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* FINGERPRINT */
  attr = turn_attr_fingerprint_create(0xDEADBEEF, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* MESSAGE-INTEGRITY */
  attr = turn_attr_message_integrity_create(NULL, &iov[index]);
  fail_unless(attr != NULL, "attribute header creation failed");
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* after convert STUN/TURN message length to big endian we can calculate
   * HMAC-SHA1
   */
  /* index -1 because we do not take into account MESSAGE-INTEGRITY attribute */
  md5_generate(md_buf, "login:domain.org:password",
      strlen("login:domain.org:password"));
  turn_calculate_integrity_hmac_iov(iov, index - 1, md_buf, sizeof(md_buf),
      ((struct turn_attr_message_integrity*)attr)->turn_attr_hmac);

  /* put iovec into a raw buffer */
  {
    char* ptr = buf;
    for(nb = 0 ; nb < index ; nb++)
    {
      memcpy(ptr, iov[nb].iov_base, iov[nb].iov_len);
      ptr += iov[nb].iov_len;
    }
  }

  nb = turn_parse_message(buf, sizeof(buf),  &message, tab, &tab_size);

  /* test if the header and all the attributes are present */
  fail_unless(message.msg != NULL, "header must be present");
  fail_unless(message.mapped_addr != NULL, "mapped_addr must be present");
  fail_unless(message.peer_addr != NULL, "peer_addr must be present");
  fail_unless(message.relayed_addr != NULL, "relayed_addr must be present");
  fail_unless(message.alternate_server != NULL,
      "alternate_server must be present");
  fail_unless(message.xor_mapped_addr != NULL,
      "xor_mapped_addr must be present");
  fail_unless(message.reservation_token != NULL,
      "reservation_token must be present");
  fail_unless(message.data != NULL, "data must be present");
  fail_unless(message.channel_number != NULL, "channel_number must be present");
  fail_unless(message.lifetime != NULL, "lifetime must be present");
  fail_unless(message.nonce != NULL, "nonce must be present");
  fail_unless(message.realm != NULL, "realm must be present");
  fail_unless(message.username != NULL, "username must be present");
  fail_unless(message.even_port != NULL, "even_port must be present");
  fail_unless(message.requested_transport != NULL,
      "requested_transport must be present");
  fail_unless(message.dont_fragment != NULL, "dont_fragment must be present");
  fail_unless(message.unknown_attribute != NULL,
      "unknown_attribute must be present");
  fail_unless(message.message_integrity == NULL,
      "fingerprint MUST be the last attribute");
  fail_unless(message.fingerprint != NULL, "fingerprint must be present");
  fail_unless(message.software != NULL, "software must be present");
  fail_unless(message.error_code != NULL, "error_code must be present");

  iovec_free_data(iov, index);
}
END_TEST

Suite* turn_msg_suite(void)
{
  Suite* s = suite_create("TURN messages and attributes tests");

  /* Core test case */
  TCase* tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_msg_create);
  tcase_add_test(tc_core, test_attr_create);
  tcase_add_test(tc_core, test_message_parse);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char** argv)
{
  unsigned int number_failed = 0;

  Suite* s = turn_msg_suite();
  SRunner* sr = srunner_create(s);

  srunner_run_all(sr, CK_NORMAL);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

