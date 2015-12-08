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
 * \file conf.h
 * \brief Configuration parsing.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#ifndef CONF_H
#define CONF_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdint.h>

#include "list.h"

#if 0 /* not used for the moment */
#include <limits.h>

/**
 * \struct turnserver_cfg
 * \brief TurnServer configuration.
 */
struct turnserver_cfg
{
  char listen_address[256]; /**< Listening address (IPv4 address or FQDN) */
  char listen_addressv6[256]; /**< Listening address (IPv6 address or FQDN) */
  uint16_t udp_port; /**< UDP listening port */
  uint16_t tcp_port; /**< TCP listening port */
  uint16_t tls_port; /**< TLS listening port */
  int tls; /**< TLS socket support */
  int dtls; /**< DTLS socket support (not in TURN standard) */
  int daemon; /**< Daemon state */
  char realm[256]; /**< Realm */
  uint16_t max_client; /**< Max simultanous client */
  uint16_t max_relay_per_username; /**< Max relay per username */
  uint32_t allocation_lifetime; /**< Lifetime the server will maintain a binding (in seconds) */
  char nonce_key[255]; /**< Private key used to generate nonce */
  char ca_file[PATH_MAX]; /**< CA file */
  char cert_file[PATH_MAX]; /**< Certificate file */
  char private_key_file[PATH_MAX]; /**< Private key file */
  char account_method; /**< Method (only "file" are implemented) */
  char account_file[PATH_MAX]; /**< Account file */
};
#endif

/**
 * \brief Parse the configuration file.
 * \param file the file name
 * \param denied_address_list the denied address list that will be filled
 * \return -1 if the file canont be found\n
 * -3 memory problem\n
 * -2 if parse error\n
 *  0 if OK
 * \note Do not forget to call turnserver_cfg_free() to free parser memory.
 */
int turnserver_cfg_parse(const char* file, struct list_head* denied_address_list);

/**
 * \brief Print the options.
 */
void turnserver_cfg_print(void);

/**
 * \brief Free the config.
 */
void turnserver_cfg_free(void);

/**
 * \brief Get IPv4 listening address.
 *
 * In case of many IPv4 addresses are set in configuration
 * file (for load sharing), this function choose one of
 * them and return it.
 * \return listening address
 * \note If NULL, the server will not allow IPv4 relaying.
 */
char* turnserver_cfg_listen_address(void);

/**
 * \brief Get IPv6 listening address.
 *
 * In case of many IPv6 addresses are set in configuration
 * file (for load sharing), this function choose one of
 * them and return it.
 * \return listening address
 * \note If NULL, the server will not allow IPv6 relaying.
 */
char* turnserver_cfg_listen_addressv6(void);

/**
 * \brief Get the UDP listening port.
 * \return UDP port
 */
uint16_t turnserver_cfg_udp_port(void);

/**
 * \brief Get the TCP listening port.
 * \return TCP port
 */
uint16_t turnserver_cfg_tcp_port(void);

/**
 * \brief Get the TLS listening port.
 * \return TLS port
 */
uint16_t turnserver_cfg_tls_port(void);

/**
 * \brief Run with TLS socket.
 * \return 1 if server has to start with TLS, 0 otherwise
 * \note Server could also receive and process non-TLS data.
 */
int turnserver_cfg_tls(void);

/**
 * \brief Run with DTLS socket.
 *
 * Please note that DTLS (TLS over UDP) is not in TURN standard and so is an
 * experimental feature of TurnServer.
 * \return 1 if server has to start with DTLS, 0 otherwise
 */
int turnserver_cfg_dtls(void);

/**
 * \brief Get the maximum allocation port number.
 *
 * It is strongly discouraged to have ports under 49152 only if server knows
 * there are not other services running on one on these ports.
 *
 * It is more than discouraged to have ports for range 1 - 1024. TURN client
 * should not use TURN server to run standard services.
 */
uint16_t turnserver_cfg_max_port(void);

/**
 * \brief Get the minumum allocation port number.
 *
 * It is strongly discouraged to have ports under 49152 only if server knows
 * there are not other services running on one on these ports.
 *
 * It is more than discouraged to have ports for range 1 - 1024. TURN client
 * should not use TURN server to run standard services.
 */
uint16_t turnserver_cfg_min_port(void);

/**
 * \brief Run with or without TURN-TCP extension.
 * \return 1 if TURN-TCP is enable, 0 otherwise
 */
int turnserver_cfg_turn_tcp(void);

/**
 * \brief Get TURN-TCP buffering mode.
 * \return 1 for userspace buffering, 0 for kernel buffering
 */
int turnserver_cfg_tcp_buffer_userspace(void);

/**
 * \brief Get TURN-TCP internal buffer size for peer data.
 * \return internal buffer size
 */
uint32_t turnserver_cfg_tcp_buffer_size(void);

/**
 * \brief Get the behavior of server at startup.
 * \return 1 if server has to daemonize, 0 otherwise
 */
int turnserver_cfg_daemon(void);

/**
 * \brief Get the unprivileged username.
 * \return unprivileged username
 */
char* turnserver_cfg_unpriv_user(void);

/**
 * \brief Get the maximum number of simulanous client.
 * \return max client
 */
uint16_t turnserver_cfg_max_client(void);

/**
 * \brief Get the maximum number of relay per username.
 * \return max number of allocation per username
 */
uint16_t turnserver_cfg_max_relay_per_username(void);

/**
 * \brief Get lifetime of an allocation binding (in seconds).
 * \return default lifetime of an allocation binding
 */
uint16_t turnserver_cfg_allocation_lifetime(void);

/**
 * \brief Get the key to generate nonce.
 * \return key
 */
char* turnserver_cfg_nonce_key(void);

/**
 * \brief Get the Certificate Authority file.
 * \return CA file
 */
char* turnserver_cfg_ca_file(void);

/**
 * \brief Get the server certificate file.
 * \return certificate file
 */
char* turnserver_cfg_cert_file(void);

/**
 * \brief Get the server private key file.
 * \return private key file
 */
char* turnserver_cfg_private_key_file(void);

/**
 * \brief Get the realm.
 * \return realm
 */
char* turnserver_cfg_realm(void);

/**
 * \brief Get the bandwidth limitation per allocation (in kB/s).
 * \return bandwidth limit in kB/s
 */
uint16_t turnserver_cfg_bandwidth_per_allocation(void);

/**
 * \brief Get bandwidth for a restricted user (in kB/s).
 * \return bandwidth limit in kB/s
 */
uint32_t turnserver_cfg_restricted_bandwidth(void);

/**
 * \brief Get the account method (file, mysql-db, ...).
 * \return method
 */
char* turnserver_cfg_account_method(void);

/**
 * \brief Get the account file (in case of account method is "file").
 * \return file name
 */
char* turnserver_cfg_account_file(void);

/**
 * \brief Get the account database login (in case of account method is db).
 * \return database login
 */
char* turnserver_cfg_account_db_login(void);

/**
 * \brief Get the account database password (in case of account method is db).
 * \return database password
 */
char* turnserver_cfg_account_db_password(void);

/**
 * \brief Get the account database name (in case of account method is db).
 * \return database name
 */
char* turnserver_cfg_account_db_name(void);

/**
 * \brief Get the account database network address (in case of account method is
 * db).
 * \return database network address
 */
char* turnserver_cfg_account_db_address(void);

/**
 * \brief Get the account database network port (in case of account method is
 * db).
 * \return database network port
 */
uint16_t turnserver_cfg_account_db_port(void);

/**
 * \brief Returns whether or not mod_tmpuser is enabled.
 * \return 1 if mod_tmpuser is enabled, 0 otherwise
 */
int turnserver_cfg_mod_tmpuser(void);

#endif /* CONF_H */

