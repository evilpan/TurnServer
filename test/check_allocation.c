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
 * \file check_allocation.c
 * \brief Unit tests for allocation management.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <check.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "../src/allocation.h"

START_TEST(test_allocation_list)
{
  struct list_head allocation_list;
  struct allocation_desc* ret = NULL;
  struct allocation_desc* ret2 = NULL;
  struct sockaddr_in client_addr;
  struct sockaddr_in client_addr2;
  struct sockaddr_in server_addr;
  struct sockaddr_in relayed_addr;
  struct sockaddr_in relayed_addr2;
  uint8_t id[12];
  uint8_t id2[12];
  unsigned char key[16];
  unsigned char nonce[48];
  char* realm = "domain.org";
  int nb = -1;
  uint32_t channel = 0;

  memset(id, 0xFE, 12);
  memset(id2, 0xEF, 12);

  client_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "10.9.91.1", &client_addr.sin_addr);
  client_addr.sin_port = htons(3560);
  memset(&client_addr.sin_zero, 0x00, sizeof(client_addr.sin_zero));

  memcpy(&client_addr2, &client_addr, sizeof(client_addr));
  client_addr2.sin_port = htons(3565);

  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "192.168.0.1", &server_addr.sin_addr);
  server_addr.sin_port = htons(3300);
  memset(&server_addr.sin_zero, 0x00, sizeof(server_addr.sin_zero));

  memcpy(&relayed_addr, &server_addr, sizeof(server_addr));
  relayed_addr.sin_port = htons(48000);

  memcpy(&relayed_addr2, &server_addr, sizeof(server_addr));
  relayed_addr2.sin_port = htons(48005);

  INIT_LIST(allocation_list);

  /* create a valid allocation descriptor */
  ret = allocation_desc_new(id, IPPROTO_UDP, "login", key, realm, nonce,
      (struct sockaddr*)&relayed_addr, (struct sockaddr*)&server_addr,
      (struct sockaddr*)&client_addr, sizeof(client_addr), 3600);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  /* create a valid allocation descriptor */
  ret2 = allocation_desc_new(id2, IPPROTO_UDP, "login2", key, realm, nonce,
      (struct sockaddr*)&relayed_addr2, (struct sockaddr*)&server_addr,
      (struct sockaddr*)&client_addr2, sizeof(client_addr2), 3600);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  allocation_list_add(&allocation_list, ret);
  allocation_list_add(&allocation_list, ret2);

  ret = allocation_list_find_id(&allocation_list, id);
  fail_unless(ret != NULL, "Allocation not found (id not match)");

  id[0] = 0x42;
  ret = allocation_list_find_id(&allocation_list, id);
  fail_unless(ret == NULL, "Allocation found (id match)");

  /* free the list */
  allocation_list_free(&allocation_list);

}
END_TEST

START_TEST(test_allocation_add)
{
  struct allocation_desc* ret = NULL;
  struct sockaddr_in client_addr;
  struct sockaddr_in server_addr;
  struct sockaddr_in relayed_addr;
  struct allocation_permission* permission = NULL;
  uint8_t id[12];
  int nb = -1;
  uint32_t channel = 0;
  unsigned char key[16];
  unsigned char nonce[48];
  char* realm = "domain.org";

  memset(id, 0xEA, 12);

  client_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "10.9.91.1", &client_addr.sin_addr);
  client_addr.sin_port = htons(3560);
  memset(&client_addr.sin_zero, 0x00, sizeof(client_addr.sin_zero));

  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "192.168.0.1", &server_addr.sin_addr);
  server_addr.sin_port = htons(3300);
  memset(&server_addr.sin_zero, 0x00, sizeof(server_addr.sin_zero));

  memcpy(&relayed_addr, &server_addr, sizeof(server_addr));
  relayed_addr.sin_port = htons(48000);

  /* create a valid allocation descriptor */
  ret = allocation_desc_new(id, IPPROTO_UDP, "login", key, realm, nonce,
      (struct sockaddr*)&relayed_addr, (struct sockaddr*)&server_addr,
      (struct sockaddr*)&client_addr, sizeof(client_addr), 3600);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  /* add a permission */
  inet_pton(AF_INET, "98.2.1.2", &client_addr.sin_addr);

  nb = allocation_desc_add_permission(ret, 19, client_addr.sin_family,
      (char*)&client_addr.sin_addr);
  fail_unless(nb == 0, "add permission failed");

  /*
  nb = allocation_desc_add_channel(ret, 58, 18, (struct sockaddr*)&client_addr,
  sizeof(client_addr));
  */
  nb = allocation_desc_add_channel(ret, 58, 18, client_addr.sin_family,
      (char*)&client_addr.sin_addr, ntohs(client_addr.sin_port));
  fail_unless(nb == 0, "add channel failed");

  /* test finding a permission for a peer */
  permission = allocation_desc_find_permission(ret, client_addr.sin_family,
      (char*)&client_addr.sin_addr);
  fail_unless(permission != NULL, "Find permission not found for the peer");

  inet_pton(AF_INET, "98.2.1.3", &client_addr.sin_addr);
  permission = allocation_desc_find_permission(ret, client_addr.sin_family,
      (char*)&client_addr.sin_addr);
  fail_unless(permission == NULL, "Find permission found for the peer");

  /* test finding channel for a peer */
  inet_pton(AF_INET, "98.2.1.2", &client_addr.sin_addr);
  channel = allocation_desc_find_channel(ret, client_addr.sin_family,
      (char*)&client_addr.sin_addr, ntohs(client_addr.sin_port));
  fail_unless(channel > 0, "Find channel failed");

  inet_pton(AF_INET, "98.2.1.3", &client_addr.sin_addr);
  channel = allocation_desc_find_channel(ret, client_addr.sin_family,
      (char*)&client_addr.sin_addr, ntohs(client_addr.sin_port));
  fail_unless(channel == 0, "Find channel success");

  /* free it */
  allocation_desc_free(&ret);
  fail_unless(ret == NULL, "allocation_desc_free does not set to NULL!");
}
END_TEST

START_TEST(test_allocation_create)
{
  struct allocation_desc* ret = NULL;
  struct sockaddr_in client_addr;
  struct sockaddr_in server_addr;
  struct sockaddr_in relayed_addr;
  uint8_t id[12];
  unsigned char key[16];
  unsigned char nonce[48];
  char* realm = "domain.org";

  memset(id, 0xEA, 12);

  client_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "10.9.91.1", &client_addr.sin_addr);
  client_addr.sin_port = htons(3560);
  memset(&client_addr.sin_zero, 0x00, sizeof(client_addr.sin_zero));

  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, "192.168.0.1", &server_addr.sin_addr);
  server_addr.sin_port = htons(3300);
  memset(&server_addr.sin_zero, 0x00, sizeof(server_addr.sin_zero));

  memcpy(&relayed_addr, &server_addr, sizeof(server_addr));
  relayed_addr.sin_port = htons(48000);

  /* create a valid allocation descriptor */
  ret = allocation_desc_new(id, IPPROTO_UDP, "login", key, realm, nonce,
      (struct sockaddr*)&relayed_addr, (struct sockaddr*)&server_addr,
      (struct sockaddr*)&client_addr, sizeof(client_addr), 3600);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  /* free it */
  allocation_desc_free(&ret);
  fail_unless(ret == NULL, "allocation_desc_free does not set to NULL!");

  /* create a invalid allocation descriptor */
  ret = allocation_desc_new(id, IPPROTO_UDP, "login", key, realm, nonce, NULL,
      (struct sockaddr*)&server_addr, (struct sockaddr*)&client_addr,
      sizeof(client_addr), 3600);
  fail_unless(ret == NULL, "Invalid parameter (NULL in parameter)");
}
END_TEST

Suite* turn_msg_suite(void)
{
  Suite* s = suite_create("Allocation management tests");

  /* Core test case */
  TCase* tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_allocation_create);
  tcase_add_test(tc_core, test_allocation_add);
  tcase_add_test(tc_core, test_allocation_list);
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

