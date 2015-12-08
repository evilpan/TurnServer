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
 * \file conf.c
 * \brief Configuration parsing.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <confuse.h>

#include "conf.h"
#include "turnserver.h"

/**
 * \brief Free the resources used by the lex parser.
 *
 * This function comes from libconfuse and is not called
 * in cfg_free(), that's why call it here.
 * \note Require libconfuse >= 2.6.
 * \return 0
 */
extern int cfg_yylex_destroy(void);

/**
 * \var g_denied_address_opts
 * \brief Denied address option.
 */
static cfg_opt_t g_denied_address_opts[] =
{
  CFG_STR("address", "", CFGF_NONE),
  CFG_INT("mask", 24, CFGF_NONE),
  CFG_INT("port", 0, CFGF_NONE),
  CFG_END()
};

/**
 * \var g_opts
 * \brief Options recognized.
 */
static cfg_opt_t g_opts[]=
{
  CFG_STR("listen_address", NULL, CFGF_LIST),
  CFG_STR("listen_addressv6", NULL, CFGF_LIST),
  CFG_INT("udp_port", 3478, CFGF_NONE),
  CFG_INT("tcp_port", 3478, CFGF_NONE),
  CFG_INT("tls_port", 5349, CFGF_NONE),
  CFG_BOOL("tls", cfg_false, CFGF_NONE),
  CFG_BOOL("dtls", cfg_false, CFGF_NONE),
  CFG_INT("max_port", 65535, CFGF_NONE),
  CFG_INT("min_port", 49152, CFGF_NONE),
  CFG_BOOL("turn_tcp", cfg_false, CFGF_NONE),
  CFG_BOOL("tcp_buffer_userspace", cfg_true, CFGF_NONE),
  CFG_INT("tcp_buffer_size", 1500, CFGF_NONE),
  CFG_INT("restricted_bandwidth", 10, CFGF_NONE),
  CFG_BOOL("daemon", cfg_false, CFGF_NONE),
  CFG_STR("unpriv_user", NULL, CFGF_NONE),
  CFG_INT("max_client", 50, CFGF_NONE),
  CFG_INT("max_relay_per_username", 10, CFGF_NONE),
  CFG_INT("allocation_lifetime", 1800, CFGF_NONE),
  CFG_STR("nonce_key", NULL, CFGF_NONE),
  CFG_STR("ca_file", NULL, CFGF_NONE),
  CFG_STR("cert_file", NULL, CFGF_NONE),
  CFG_STR("private_key_file", NULL, CFGF_NONE),
  CFG_STR("realm", "domain.org", CFGF_NONE),
  CFG_STR("account_method", "file", CFGF_NONE),
  CFG_STR("account_file", "users.txt", CFGF_NONE),
  CFG_SEC("denied_address", g_denied_address_opts, CFGF_MULTI),
  CFG_INT("bandwidth_per_allocation", 0, CFGF_NONE),
  CFG_BOOL("mod_tmpuser", cfg_false, CFGF_NONE),
  /* the following attributes are not used for the moment */
  CFG_STR("account_db_login", "anonymous", CFGF_NONE),
  CFG_STR("account_db_password", "anonymous", CFGF_NONE),
  CFG_STR("account_db_name", "turnserver", CFGF_NONE),
  CFG_STR("account_db_address", "127.0.0.1", CFGF_NONE),
  CFG_INT("account_db_port", 3306, CFGF_NONE),
  CFG_END()
};

/**
 * \var g_cfg
 * \brief Config pointer.
 */
static cfg_t* g_cfg = NULL;

int turnserver_cfg_parse(const char* file, struct list_head* denied_address_list)
{
  int ret = 0;
  size_t i = 0;
  size_t nb = 0;
  g_cfg = cfg_init(g_opts, CFGF_NONE);

  ret = cfg_parse(g_cfg, file);

  if(ret == CFG_FILE_ERROR)
  {
    fprintf(stderr, "Cannot find configuration file %s\n", file);
    return -1;
  }
  else if(ret == CFG_PARSE_ERROR)
  {
    fprintf(stderr, "Parse error in configuration file %s\n", file);
    return -2;
  }

  /* check IPv4 listen addresses to be valid IPv4 ones */
  nb = cfg_size(g_cfg, "listen_address");
  for(i = 0 ; i < nb ; i++)
  {
    struct sockaddr_storage addr;
    char* str = cfg_getnstr(g_cfg, "listen_address", i);
    if(inet_pton(AF_INET, str, &addr) != 1)
    {
      return -2;
    }
  }

  /* check IPv6 listen addresses to be valid IPv6 ones */
  nb = cfg_size(g_cfg, "listen_addressv6");
  for(i = 0 ; i < nb ; i++)
  {
    struct sockaddr_storage addr;
    char* str = cfg_getnstr(g_cfg, "listen_addressv6", i);
    if(inet_pton(AF_INET6, str, &addr) != 1)
    {
      return -2;
    }
  }

  /* add the denied address */
  nb = cfg_size(g_cfg, "denied_address");
  for(i = 0 ; i < nb ; i++)
  {
    cfg_t* ad = cfg_getnsec(g_cfg, "denied_address", i);
    char* addr = cfg_getstr(ad, "address");
    uint8_t mask = cfg_getint(ad, "mask");
    uint16_t port = cfg_getint(ad, "port");
    struct denied_address* denied = NULL;

    if(!(denied = malloc(sizeof(struct denied_address))))
    {
      return -3;
    }

    memset(denied, 0x00, sizeof(struct denied_address));
    denied->mask = mask;
    denied->port = port;

    if(inet_pton(AF_INET, addr, denied->addr) != 1)
    {
      /* try IPv6 */
      if(inet_pton(AF_INET6, addr, denied->addr) != 1)
      {
        free(denied);
        return -2;
      }
      else
      {
        /* check mask */
        if(mask > 128)
        {
          free(denied);
          return -2;
        }
        denied->family = AF_INET6;
      }
    }
    else
    {
      /* mask check */
      if(mask > 24)
      {
        free(denied);
        return -2;
      }
      denied->family = AF_INET;
    }

    /* add to the list */
    LIST_ADD(&denied->list, denied_address_list);
  }

  return 0;
}

void turnserver_cfg_print(void)
{
  fprintf(stdin, "Configuration:\n");
  cfg_print(g_cfg, stderr);
}

void turnserver_cfg_free(void)
{
  if(g_cfg)
  {
    cfg_free(g_cfg);
    g_cfg = NULL;

    cfg_yylex_destroy();
  }
}

char* turnserver_cfg_listen_address(void)
{
  size_t nb = cfg_size(g_cfg, "listen_address");

  if(nb)
  {
    size_t l = (size_t)(rand() % nb);
    return cfg_getnstr(g_cfg, "listen_address", l);
  }
  else
  {
    return NULL;
  }
}

char* turnserver_cfg_listen_addressv6(void)
{
  size_t nb = cfg_size(g_cfg, "listen_addressv6");

  if(nb)
  {
    size_t l = (size_t)(rand() % nb);
    return cfg_getnstr(g_cfg, "listen_addressv6", l);
  }
  else
  {
    return NULL;
  }
}

uint16_t turnserver_cfg_udp_port(void)
{
  return cfg_getint(g_cfg, "udp_port");
}

uint16_t turnserver_cfg_tcp_port(void)
{
  return cfg_getint(g_cfg, "tcp_port");
}

uint16_t turnserver_cfg_tls_port(void)
{
  return cfg_getint(g_cfg, "tls_port");
}

int turnserver_cfg_tls(void)
{
  return cfg_getbool(g_cfg, "tls");
}

int turnserver_cfg_dtls(void)
{
  return cfg_getbool(g_cfg, "dtls");
}

uint16_t turnserver_cfg_max_port(void)
{
  return cfg_getint(g_cfg, "max_port");
}

uint16_t turnserver_cfg_min_port(void)
{
  return cfg_getint(g_cfg, "min_port");
}

int turnserver_cfg_turn_tcp(void)
{
  return cfg_getbool(g_cfg, "turn_tcp");
}

int turnserver_cfg_tcp_buffer_userspace(void)
{
  return cfg_getbool(g_cfg, "tcp_buffer_userspace");
}

uint32_t turnserver_cfg_tcp_buffer_size(void)
{
  return cfg_getint(g_cfg, "tcp_buffer_size");
}

uint32_t turnserver_cfg_restricted_bandwidth(void)
{
  return cfg_getint(g_cfg, "restricted_bandwidth");
}

int turnserver_cfg_daemon(void)
{
  return cfg_getbool(g_cfg, "daemon");
}

char* turnserver_cfg_unpriv_user(void)
{
  return cfg_getstr(g_cfg, "unpriv_user");
}

uint16_t turnserver_cfg_max_client(void)
{
  return cfg_getint(g_cfg, "max_client");
}

uint16_t turnserver_cfg_max_relay_per_username(void)
{
  return cfg_getint(g_cfg, "max_relay_per_username");
}

uint16_t turnserver_cfg_allocation_lifetime(void)
{
  return cfg_getint(g_cfg, "allocation_lifetime");
}

char* turnserver_cfg_nonce_key(void)
{
  return cfg_getstr(g_cfg, "nonce_key");
}

char* turnserver_cfg_ca_file(void)
{
  return cfg_getstr(g_cfg, "ca_file");
}

char* turnserver_cfg_cert_file(void)
{
  return cfg_getstr(g_cfg, "cert_file");
}

char* turnserver_cfg_private_key_file(void)
{
  return cfg_getstr(g_cfg, "private_key_file");
}

char* turnserver_cfg_realm(void)
{
  return cfg_getstr(g_cfg, "realm");
}

uint16_t turnserver_cfg_bandwidth_per_allocation(void)
{
  return cfg_getint(g_cfg, "bandwidth_per_allocation");
}

char* turnserver_cfg_account_method(void)
{
  return cfg_getstr(g_cfg, "account_method");
}

char* turnserver_cfg_account_file(void)
{
  return cfg_getstr(g_cfg, "account_file");
}

char* turnserver_cfg_account_db_login(void)
{
  return cfg_getstr(g_cfg, "account_db_login");
}

char* turnserver_cfg_account_db_password(void)
{
  return cfg_getstr(g_cfg, "account_db_password");
}

char* turnserver_cfg_account_db_name(void)
{
  return cfg_getstr(g_cfg, "account_db_name");
}

char* turnserver_cfg_account_db_address(void)
{
  return cfg_getstr(g_cfg, "account_db_address");
}

uint16_t turnserver_cfg_account_db_port(void)
{
  return cfg_getint(g_cfg, "account_db_port");
}

int turnserver_cfg_mod_tmpuser(void)
{
  return cfg_getbool(g_cfg, "mod_tmpuser");
}
