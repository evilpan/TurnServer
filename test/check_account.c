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
 * \file check_account.c
 * \brief Unit tests for account management.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#include <stdlib.h>
#include <string.h>

#include <check.h>

#include "../src/account.h"

START_TEST(test_account_create)
{
  struct account_desc* ret = NULL;

  /* create a valid account descriptor */
  ret = account_desc_new("login", "password", "domain.org", AUTHORIZED);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  /* free it */
  account_desc_free(&ret);
  fail_unless(ret == NULL, "account_desc_free does not set to NULL!");

  /* create a invalid account descriptor */
  ret = account_desc_new("login", NULL, "domain.org", AUTHORIZED);
  fail_unless(ret == NULL, "Invalid parameter (NULL in parameter)");

  /* create a invalid account descriptor */
  ret = account_desc_new(NULL, "password", "domain.org", AUTHORIZED);
  fail_unless(ret == NULL, "Invalid parameter (NULL in parameter)");

  /* create a invalid account descriptor */
  ret = account_desc_new("login", "password", NULL, AUTHORIZED);
  fail_unless(ret == NULL, "Invalid parameter (NULL in parameter)");
}
END_TEST

START_TEST(test_account_list)
{
  struct list_head account_list;
  struct account_desc* ret = NULL;
  struct account_desc* ret2 = NULL;
  struct account_desc* ret3 = NULL;

  INIT_LIST(account_list);

  /* create a valid account descriptor */
  ret = account_desc_new("login", "password", "domain.org", AUTHORIZED);
  fail_unless(ret != NULL, "Invalid parameter or memory problem");

  ret2 = account_desc_new("login2", "password2", "domain.org", AUTHORIZED);
  fail_unless(ret2 != NULL, "Invalid parameter or memory problem");

  account_list_add(&account_list, ret);
  account_list_add(&account_list, ret2);

  /* find an account in the list */
  ret3 = account_list_find(&account_list, "login", "domain.org");
  fail_unless(ret3 != NULL, "The list has not a match");

  /* find an unknown account in the list */
  ret3 = account_list_find(&account_list, "login44", "domain.org");
  fail_unless(ret3 == NULL, "The list has a match");

  /* find an valid name but unknown realm */
  ret3 = account_list_find(&account_list, "login", "domain2.org");
  fail_unless(ret3 == NULL, "The list has a match");

  /* find an valid name but no realm specified */
  ret3 = account_list_find(&account_list, "login", NULL);
  fail_unless(ret3 != NULL, "The list has not a match");

  /* free the list and the account */
  account_list_free(&account_list);
  ret = NULL;
  ret2 = NULL;
  ret3 = NULL;
}
END_TEST

Suite* turn_msg_suite(void)
{
  Suite* s = suite_create("Account management tests");

  /* Core test case */
  TCase* tc_core = tcase_create("Core");
  tcase_add_test(tc_core, test_account_create);
  tcase_add_test(tc_core, test_account_list);
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

