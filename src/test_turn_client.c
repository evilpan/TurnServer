/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2010 Sebastien Vincent <sebastien.vincent@turnserver.org>
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
 * \file test_turn_client.c
 * \brief TURN client example that supports UDP, TCP, TLS and DTLS
 * and relay protocol with UDP or TCP.
 * \author Sebastien Vincent
 * \date 2010
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifndef _MSC_VER
/* Microsoft compiler does not have it */
#include <stdint.h>
#else
/* Microsoft compiler does not want users
 * to use snprintf directly...
 */
#define snprintf _snprintf
/* Microsoft compiler use closesocket()
 * instead of close() to close a socket
 */
#define close closesocket
#endif

#if defined(_WIN32) || defined(_WIN64)
/* Windows needs Winsock2 include
 * to have access to network functions
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#else
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif

#include "util_sys.h"
#include "util_crypto.h"
#include "protocol.h"
#include "tls_peer.h"

/**
 * \def SOFTWARE_DESCRIPTION
 * \brief Name of the software.
 */
#define SOFTWARE_DESCRIPTION "TURN client example 0.1"

/**
 * \struct client_configuration
 * \brief Describes client configuration setup.
 */
struct client_configuration
{
  char* username; /**< User */
  char* password; /**< User password */
  char* realm; /**< Realm */
  char* server_address; /**< TURN server address */
  char* peer_address; /**< Peer address */
  char* peer_port; /**< Peer port */
  char* certificate_file; /**< SSL certificate pathname */
  char* private_key_file; /**< SSL private key pathname */
  char* ca_file; /**< Certification authority pathname */
  char* protocol; /**< Transport protocol used (UDP, TCP, TLS or DTLS) */
  char* relay_protocol; /**< Protocol used to relay data (UDP or TCP) */
};

/**
 * \brief Print help menu.
 * \param name name of the program
 * \param version version of the program
 */
static void client_print_help(const char* name, const char* version)
{
  fprintf(stdout, "TURN client example %s\n", version);
  fprintf(stdout, "Usage: %s -t transport_protocol -s turnserver_address -p peer_address -w peer_port [-r relay_protocol]\n"
      "\t[-u user] [-g password] [-d realm] [-k private_key] [-c certificate] [-a ca] [-h] [-v]\n\n", name);
  fprintf(stdout, "Transport protocol could be \"udp\", \"tcp\", \"tls\" or \"dtls\"\n");
  fprintf(stdout, "Relay protocol could be \"udp\" or \"tcp\"\n");
}

/**
 * \brief Parse the command line arguments.
 * \param argc number of argument
 * \param argv array of argument
 * \param conf client configuration
 */
static void client_parse_cmdline(int argc, char** argv, struct client_configuration* conf)
{
  static const char* optstr = "t:r:s:p:w:k:c:a:u:g:d:hv";
  int s = 0;

  while((s = getopt(argc, argv, optstr)) != -1)
  {
    switch(s)
    {
      case 'h': /* help */
        client_print_help(argv[0], "0.1");
        exit(EXIT_SUCCESS);
        break;
      case 'v': /* version */
        fprintf(stdout, "%s\n", SOFTWARE_DESCRIPTION);
        fprintf(stdout, "Copyright (C) 2010 Sebastien Vincent.\n");
        fprintf(stdout, "This is free software; see the source for copying conditions.  There is NO\n");
        fprintf(stdout, "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n");
        exit(EXIT_SUCCESS);
      case 't': /* transport protocol */
        if(optarg)
        {
          conf->protocol = optarg;
        }
        break;
      case 'r': /* relay protocol */
        if(optarg)
        {
          conf->relay_protocol = optarg;
        }
        break;
      case 's': /* TURN server address */
        if(optarg)
        {
          conf->server_address = optarg;
        }
        break;
      case 'p': /* peer address */
        if(optarg)
        {
          conf->peer_address = optarg;
        }
        break;
      case 'w': /* peer port */
        if(optarg)
        {
          if(atol(optarg) == 0)
          {
            fprintf(stderr, "Bad peer port (must be between 1 and 65535).\n");
          }
          else
          {
            conf->peer_port = optarg;
          }
        }
        break;
      case 'u': /* user */
        if(optarg)
        {
          conf->username = optarg;
        }
        break;
      case 'g': /* password */
        if(optarg)
        {
          conf->password = optarg;
        }
        break;
      case 'd': /* realm */
        if(optarg)
        {
          conf->realm = optarg;
        }
        break;
      case 'c': /* certificate file */
        if(optarg)
        {
          conf->certificate_file = optarg;
        }
        break;
      case 'k': /* private key file */
        if(optarg)
        {
          conf->private_key_file = optarg;
        }
        break;
      case 'a': /* certication authority file */
        if(optarg)
        {
          conf->ca_file = optarg;
        }
        break;
      default:
        break;
    }
  }
}

/**
 * \brief SSL verification callback.
 * \param preverify_ok status of the pre verification
 * \param store X509 store context
 * \return 1 if verification is OK, 0 otherwise
 */
int verify_callback(int preverify_ok, X509_STORE_CTX* store)
{
  (void)store;
  /* uncomment the following line to fail the SSL certificate verification */
  /* preverify_ok = 0; */
  return preverify_ok;
}

/**
 * \brief Receive TURN message.
 * \param transport_protocol transport protocol
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param buf receive buffer
 * \param buflen buf length
 * \return number of bytes received if success, -1 if error
 */
static int client_recv_message(int transport_protocol, int sock, struct tls_peer* speer, char* buf, size_t buflen)
{
  struct sockaddr_storage saddr;
  socklen_t saddr_size = sizeof(struct sockaddr_storage);
  char buffer[8192];
  ssize_t nb = -1;

  if(transport_protocol == IPPROTO_UDP)
  {
    if((nb = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&saddr, &saddr_size)) == -1)
    {
      perror("recvfrom");
      return -1;
    }
  }
  else /* IPPROTO_TCP */
  {
    if((nb = recv(sock, buffer, sizeof(buffer), 0)) == -1)
    {
      perror("recv");
      return -1;
    }

    getpeername(sock, (struct sockaddr*)&saddr, &saddr_size);
  }

  if(speer)
  {
    nb = (transport_protocol == IPPROTO_TCP) ? tls_peer_tcp_read(speer, buffer, nb, buf, buflen,
        (struct sockaddr*)&saddr, saddr_size, speer->sock) : tls_peer_udp_read(speer, buffer, nb,
        buf, buflen, (struct sockaddr*)&saddr, saddr_size);

    if(nb == -1)
    {
      return -1;
    }
  }
  else
  {
    /* if pass a too small buffer, data is lost! */
    if(nb > (ssize_t)buflen)
    {
      nb = buflen;
    }

    memcpy(buf, buffer, nb);
  }

  return nb;
}

/**
 * \brief Setup local socket.
 * \param transport_protocol transport protocol (UDP or TCP)
 * \param addr local address
 * \param port local port
 * \param sock if function succeed, will store socket descriptor
 * \param speer if function succeed and speer is valid pointer,
 * it will store TLS stuff
 * \param ca_file certification authority file
 * \param certificate_file SSL certificate file
 * \param key_file SSL private key file
 * \return 0 if success, -1 if error
 */
static int client_setup_socket(int transport_protocol, const char* addr, uint16_t port, int* sock,
    struct tls_peer** speer, const char* ca_file, const char* certificate_file, const char* key_file)
{
  if(speer)
  {
    *speer = tls_peer_new(transport_protocol, addr, port, ca_file,
        certificate_file, key_file, verify_callback);

    if((*speer))
    {
      *sock = (*speer)->sock;
      return 0;
    }

    return -1;
  }
  else if(sock)
  {
    *sock = socket_create(transport_protocol, addr, port, 0, 1);
    return (*sock != -1) ? 0 : -1;
  }

  return -1;
}

/**
 * \brief Connect to TURN server.
 * \param transport_protocol transport protocol (UDP or TCP)
 * \param addr server address
 * \param addr_size sizeof addr
 * \param sock socket descriptor
 * \param speer connect with TLS if not NULL
 * \return 0 if success, -1 if error
 */
static int client_connect_server(int transport_protocol, const struct sockaddr* addr, socklen_t addr_size,
    int sock, struct tls_peer* speer)
{
  if(speer)
  {
    /* first connect() if TCP */
    if(transport_protocol == IPPROTO_TCP)
    {
      if(connect(sock, addr, addr_size) == -1)
      {
        perror("connect");
        return -1;
      }
    }

    /* Perform SSL handshake */
    if(tls_peer_do_handshake(speer, addr, addr_size) == -1)
    {
      fprintf(stderr, "TLS handshake failed!\n");
      return -1;
    }

    fprintf(stdout, "TLS handshake OK.\n");
    return 0;
  }
  else if(sock != -1)
  {
    if(transport_protocol == IPPROTO_TCP)
    {
      if(connect(sock, addr, addr_size) == -1)
      {
        perror("connect");
        return -1;
      }

      return 0;
    }
    else if(transport_protocol == IPPROTO_UDP)
    {
      /* no need to connect in UDP */
      return 0;
    }
  }

  return -1;
}

/**
 * \brief Send a TURN Allocate request.
 * \param transport_protocol transport protocol used
 * \param relay_protocol relay protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param family peer address family (STUN_ATTR_FAMILY_IPV4 or STUN_ATTR_FAMILY_IPV6)
 * \param user username
 * \param domain domain
 * \param md_buf MD5 hash of user:domain:password
 * \param nonce nonce, for first request server nonce will be filled into this variable
 * \param nonce_len nonce length, for first request server nonce length will be filled into this variable
 * \return 0 if success or -1 if error. Note that the first request will returns -1 (need nonce)
 */
static int client_allocate_address(int transport_protocol, int relay_protocol, int sock,
    struct tls_peer* speer, const struct sockaddr* addr, socklen_t addr_size, uint8_t family,
    const char* user, const unsigned char* md_buf, const char* domain, uint8_t* nonce, size_t* nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[8192];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  if(!user || !domain || !nonce)
  {
    return -1;
  }

  /* Allocate request */
  hdr = turn_msg_allocate_request_create(0, id, &iov[index]);
  index++;

  if(*nonce_len)
  {
    /* NONCE */
    attr = turn_attr_nonce_create(nonce, *nonce_len, &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* REALM */
    attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* USERNAME */
    attr = turn_attr_username_create(user, strlen(user), &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* LIFETIME */
    attr = turn_attr_lifetime_create(0x000000A5, &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* SOFTWARE */
    attr = turn_attr_software_create("Client TURN 0.1 test", strlen("Client TURN 0.1 test"), &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* REQUESTED-TRANSPORT */
    attr = turn_attr_requested_transport_create(relay_protocol, &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    /* REQUESTED-ADDRESS-FAMILY */
    attr = turn_attr_requested_address_family_create(family, &iov[index]);
    hdr->turn_msg_len += iov[index].iov_len;
    index++;

    (void)attr;

    if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
    {
      /* MESSAGE-INTEGRITY option has to be in message, so
       * deallocate ressources and return
       */
      iovec_free_data(iov, index);
      return -1;
    }
  }

  fprintf(stdout, "Send Allocate request.\n");

  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1 || (nonce_len == 0 && !message.nonce))
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  if(!(*nonce_len))
  {
    memcpy(nonce, message.nonce->turn_attr_nonce, ntohs(message.nonce->turn_attr_len));
    nonce[ntohs(message.nonce->turn_attr_len)] = 0x00;
    *nonce_len = ntohs(message.nonce->turn_attr_len);
  }

  return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
 * \brief Send a TURN CreatePermission request.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param lifetime lifetime (0 to release allocation)
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_refresh_allocation(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, uint32_t lifetime, const char* user,
    const unsigned char* md_buf, const char* domain, uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  /* Refresh request */
  hdr = turn_msg_refresh_request_create(0, id, &iov[index]);
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* LIFETIME */
  attr = turn_attr_lifetime_create(lifetime, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send Refresh request.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
 * \brief Send a TURN CreatePermission request.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param peer_addr peer address
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_create_permission(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
    const char* user, const unsigned char* md_buf, const char* domain, uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  /* CreatePermission request */
  hdr = turn_msg_createpermission_request_create(0, id, &iov[index]);
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send CreatePermission request.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
 * \brief Send a TURN Send indication.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param peer_addr peer address
 * \param data data to send
 * \param data_len data length
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_send_data(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
    const char* data, size_t data_len, const char* user, const unsigned char* md_buf,
    const char* domain, uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  /* Send indication */
  hdr = turn_msg_send_indication_create(0, id, &iov[index]);
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* DATA */
  attr = turn_attr_data_create(data, data_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send Send indication.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  if(message.data)
  {
    fprintf(stdout, "Receive data: %u\n", ntohs(message.data->turn_attr_len));
  }

  return 0;
}

/**
 * \brief Send a TURN ChannelBind request.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param peer_addr peer address
 * \param channel channel to bind
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_channelbind(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
    uint16_t channel, const char* user, const unsigned char* md_buf, const char* domain,
    uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  /* CreatePermission request */
  hdr = turn_msg_channelbind_request_create(0, id, &iov[index]);
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* CHANNEL-NUMBER */
  attr = turn_attr_channel_number_create(channel, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send CreatePermission request.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
 * \brief Send a TURN CreatePermission request.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param channel data channel
 * \param data data to send
 * \param data_len data length
 * \return 0 if success or -1 if error.
 */
static int client_send_channeldata(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, uint16_t channel, const char* data, size_t data_len)
{
  struct iovec iov[2];
  size_t index = 0;
  struct turn_channel_data channel_data;
  ssize_t nb = -1;
  char buf[1500];

  channel_data.turn_channel_number = htons(channel);
  channel_data.turn_channel_len = htons(data_len);

  iov[index].iov_base = &channel_data;
  iov[index].iov_len = sizeof(struct turn_channel_data);
  index++;

  iov[index].iov_base = (void*)data;
  iov[index].iov_len = data_len;
  index++;

  fprintf(stdout, "Send ChannelData.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        sizeof(struct turn_channel_data) + data_len, iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb > 0)
  {
    struct turn_channel_data* dt = (struct turn_channel_data*)buf;
    fprintf(stdout, "Received ChannelData: %u bytes\n", ntohs(dt->turn_channel_len));
  }

  return 0;
}

/**
 * \brief Send a TURN-TCP Connect request and if success, send a ConnectionBind.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param peer_addr peer address
 * \param sock_tcp pointer that will receive socket descriptor if function succeed
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_send_connect(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
    int* sock_tcp, const char* user, const unsigned char* md_buf, const char* domain,
    uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);

  turn_generate_transaction_id(id);

  /* Connect request */
  hdr = turn_msg_connect_request_create(0, id, &iov[index]);
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send Connect request.\n");
  if(turn_send_message(transport_protocol, sock, speer, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);
  index = 0;

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  if(!message.connection_id)
  {
    fprintf(stderr, "No connection ID.\n");
    return -1;
  }

  *sock_tcp = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

  /* establish relay connection */
  if(*sock_tcp == -1 || connect(*sock_tcp, addr, addr_size) == -1)
  {
    fprintf(stderr, "Failed to connect to TURN server.\n");
    return -1;
  }

  turn_generate_transaction_id(id);

  /* ConnectionBind request */
  hdr = turn_msg_connectionbind_request_create(0, id, &iov[index]);
  index++;

  /* CONNECTION-ID */
  attr = turn_attr_connection_id_create(message.connection_id->turn_attr_id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send ConnectionBind request.\n");
  if(turn_send_message(transport_protocol, *sock_tcp, NULL, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }
  iovec_free_data(iov, index);

  nb = client_recv_message(transport_protocol, *sock_tcp, NULL, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }
  fprintf(stdout, "Receive ConnectionBind response OK\n");

  return STUN_IS_ERROR_RESP(ntohs(message.msg->turn_msg_type)) ? -1 : 0;
}

/**
 * \brief Wait a ConnectionAttempt and send ConnectionBind request.
 * \param transport_protocol transport protocol used
 * \param sock socket descriptor
 * \param speer TLS peer
 * \param addr server address
 * \param addr_size sizeof addr
 * \param peer_addr peer address
 * \param sock_tcp pointer that will receive socket descriptor if function succeed
 * \param user username
 * \param md_buf MD5 of user:domain:password
 * \param domain domain
 * \param nonce nonce
 * \param nonce_len nonce length
 * \return 0 if success or -1 if error.
 */
static int client_wait_connection(int transport_protocol, int sock, struct tls_peer* speer,
    const struct sockaddr* addr, socklen_t addr_size, const struct sockaddr* peer_addr,
    int* sock_tcp, const char* user, const unsigned char* md_buf, const char* domain,
    uint8_t* nonce, size_t nonce_len)
{
  struct turn_message message;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[16];
  size_t index = 0;
  uint8_t id[12];
  ssize_t nb = -1;
  char buf[1500];
  uint16_t tabu[16];
  size_t tabu_size = sizeof(tabu) / sizeof(uint16_t);
  sfd_set fdsr;
  struct timeval tv;
  int nsock = 0;

  tv.tv_sec = 10; /* 10 seconds before timeout */
  tv.tv_usec = 0;
  SFD_ZERO(&fdsr);
  SFD_SET(sock, &fdsr);

  nsock = sock + 1;

  if(select(nsock, (fd_set*)(void*)&fdsr, NULL, NULL, &tv) <= 0)
  {
    /* timeout or error */
    perror("select");
    return -1;
  }

  /* here we are sure that data are available on socket */

  nb = client_recv_message(transport_protocol, sock, speer, buf, sizeof(buf));

  if(nb == -1)
  {
    fprintf(stderr, "Receive failed!\n");
    return -1;
  }

  if(turn_parse_message(buf, nb, &message, tabu, &tabu_size) == -1)
  {
    fprintf(stderr, "Parsing failed!\n");
    return -1;
  }

  if(!message.connection_id)
  {
    fprintf(stderr, "No connection ID.\n");
    return -1;
  }

  turn_generate_transaction_id(id);

  *sock_tcp = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);

  /* establish relay connection */
  if(*sock_tcp == -1 || connect(*sock_tcp, addr, addr_size) == -1)
  {
    fprintf(stderr, "Failed to connect to TURN server.\n");
    return -1;
  }

  turn_generate_transaction_id(id);

  /* ConnectionBind request */
  hdr = turn_msg_connectionbind_request_create(0, id, &iov[index]);
  index++;

  /* CONNECTION-ID */
  attr = turn_attr_connection_id_create(message.connection_id->turn_attr_id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* NONCE */
  attr = turn_attr_nonce_create(nonce, nonce_len, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* REALM */
  attr = turn_attr_realm_create(domain, strlen(domain), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* USERNAME */
  attr = turn_attr_username_create(user, strlen(user), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* SOFTWARE */
  attr = turn_attr_software_create(SOFTWARE_DESCRIPTION, strlen(SOFTWARE_DESCRIPTION), &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  /* XOR-PEER-ADDRESS */
  attr = turn_attr_xor_peer_address_create(peer_addr, STUN_MAGIC_COOKIE, id, &iov[index]);
  hdr->turn_msg_len += iov[index].iov_len;
  index++;

  (void)attr;

  if(turn_add_message_integrity(iov, &index, md_buf, 16, 1) == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, index);
    return -1;
  }

  fprintf(stdout, "Send ConnectionBind request.\n");
  if(turn_send_message(transport_protocol, *sock_tcp, NULL, addr, addr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, index) == -1)
  {
    fprintf(stderr, "Send failed!\n");
    perror("send");
    iovec_free_data(iov, index);
    return -1;
  }

  iovec_free_data(iov, index);
  return 0;
}

/**
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of argument
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
  int transport_protocol = 0;
  int relay_protocol = 0;
  int sock = -1;
  struct tls_peer* speer = NULL;
  size_t len = 0;
  int use_tls = 0;
  struct sockaddr_storage server_addr;
  struct sockaddr_storage peer_addr;
  socklen_t server_addr_size = 0;
  struct addrinfo hints;
  struct addrinfo* res = NULL;
  char port_str[8];
  uint8_t nonce[513];
  size_t nonce_len = 0;
  char* user = "toto";
  char* password = "password";
  char* domain = "domain.org";
  const uint16_t channel = 0x4009;
  char data[1024];
  uint8_t family = 0;
  struct client_configuration conf;
  unsigned char* userdomainpass = NULL;
  size_t userdomainpass_len = 0;
  unsigned char md_buf[16]; /* MD5 */
  int ret = EXIT_SUCCESS;
  int r = -1;

#if defined(_WIN32) || defined(_WIN64)
  /* Windows need to initialize and startup
   * WSAData object otherwise network-related
   * functions will fail
   */
  WSADATA wsa;
  if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
  {
    /* no need to go further since program
     * will not be able to bind/connect a socket
     */
    fprintf(stderr, "Error WSAStartup\n");
    exit(EXIT_FAILURE);
  }
#endif

  memset(&conf, 0x00, sizeof(struct client_configuration));
  client_parse_cmdline(argc, argv, &conf);

  /* check that all mandatory arguments are present */
  if(!conf.peer_address || !conf.peer_port || !conf.server_address || !conf.protocol)
  {
    client_print_help(argv[0], "0.1");
    exit(EXIT_FAILURE);
  }

  /* relay with UDP if not specified */
  if(!conf.relay_protocol)
  {
    conf.relay_protocol = "udp";
  }

  /* check the protocol is supported ones */
  len = strlen(conf.protocol);

  if(len != 3 && len != 4)
  {
    fprintf(stderr, "Bad protocol, possible choices are udp, tcp, tls or dtls.\n");
    exit(EXIT_FAILURE);
  }

  if(!strncmp(conf.protocol, "udp", len))
  {
    transport_protocol = IPPROTO_UDP;
  }
  else if(!strncmp(conf.protocol, "tcp", len))
  {
    transport_protocol = IPPROTO_TCP;
  }
  else if(!strncmp(conf.protocol, "tls", len))
  {
    transport_protocol = IPPROTO_TCP;
    use_tls = 1;
  }
  else if(!strncmp(conf.protocol, "dtls", len))
  {
    transport_protocol = IPPROTO_UDP;
    use_tls = 1;
  }
  else
  {
    fprintf(stderr, "Bad protocol, possible choices are udp, tcp, tls or dtls.\n");
    exit(EXIT_FAILURE);
  }

  len = strlen(conf.relay_protocol);

  if(!strncmp(conf.relay_protocol, "udp", len))
  {
    relay_protocol = IPPROTO_UDP;
  }
  else if(!strncmp(conf.relay_protocol, "tcp", len))
  {
    relay_protocol = IPPROTO_TCP;
  }
  else
  {
    fprintf(stderr, "Bad relay protocol, possible choice is only udp.\n");
    exit(EXIT_FAILURE);
  }

  /* if TURN-TCP is used, make sure that control connection is TCP */
  if(!strncmp(conf.relay_protocol, "tcp", len) && transport_protocol != IPPROTO_TCP)
  {
    fprintf(stderr, "TCP relays work only when client have a TCP connection to its TURN server.\n");
    exit(EXIT_FAILURE);
  }

  /* use configuration to set user/password/realm
   * or use default if not set
   */
  if(conf.username)
  {
    user = conf.username;
  }

  if(conf.realm)
  {
    domain = conf.realm;
  }

  if(conf.password)
  {
    password = conf.password;
  }

  fprintf(stdout, "Protocol: %s (%d) use TLS: %d.\n", conf.protocol, transport_protocol, use_tls);

  /* get address for server_address */

  /* convert uint16_t to string */
  snprintf(port_str, sizeof(port_str), "%u", use_tls ? 5349 : 3478);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = (transport_protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
  hints.ai_protocol = transport_protocol;
  hints.ai_flags = 0;

  if((r = getaddrinfo(conf.server_address, port_str, &hints, &res)) != 0)
  {
    fprintf(stderr, "getaddrinfo(%s:%s): %s\n", conf.server_address, port_str, gai_strerror(r));
    exit(EXIT_FAILURE);
  }

  memcpy(&server_addr, res->ai_addr, res->ai_addrlen);
  server_addr_size = res->ai_addrlen;
  freeaddrinfo(res);

  /* get address for peer_address */

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = 0;

  if((r = getaddrinfo(conf.peer_address, conf.peer_port, &hints, &res)) != 0)
  {
    fprintf(stderr, "getaddrinfo(%s:%s): %s\n", conf.peer_address, conf.peer_port, gai_strerror(r));
    exit(EXIT_FAILURE);
  }

  memcpy(&peer_addr, res->ai_addr, res->ai_addrlen);
  /* get family */
  family = (res->ai_addrlen == sizeof(struct sockaddr_in6)) ? STUN_ATTR_FAMILY_IPV6 : STUN_ATTR_FAMILY_IPV4;
  freeaddrinfo(res);

  /* make sure that if TLS is used, all mandatory related
   * parameters are present
   */
  if(use_tls && (!conf.certificate_file || !conf.private_key_file || !conf.ca_file))
  {
    fprintf(stderr, "Missing parameters to setup TLS (required -c, -p, -a command line parameters).\n");
    free(userdomainpass);
    exit(EXIT_FAILURE);
  }
  else if(use_tls)
  {
    /* initialize libssl */
    LIBSSL_INIT;
  }

  /* create local socket and connect to the TURN server */
  if(client_setup_socket(transport_protocol, (server_addr_size == sizeof(struct sockaddr_in6)) ? "::" : "0.0.0.0", 0, &sock, use_tls ? &speer : NULL, conf.ca_file, conf.certificate_file, conf.private_key_file) == -1)
  {
    fprintf(stderr, "Error creating local socket.\n");

    if(use_tls)
    {
      LIBSSL_CLEANUP;
    }
    exit(EXIT_FAILURE);
  }

  if(client_connect_server(transport_protocol, (struct sockaddr*)&server_addr, server_addr_size, sock, speer) == -1)
  {
    fprintf(stderr, "Error connecting to server.\n");
    ret = EXIT_FAILURE;
    goto quit;
  }

  /* calculate MD5 hash for user:domain:password */
  userdomainpass_len = strlen(user) + strlen(domain) + strlen(password) + 3; /* 2 ":" + 0x00 */
  userdomainpass = malloc(userdomainpass_len);

  if(!userdomainpass)
  {
    exit(EXIT_FAILURE);
  }

  snprintf((char*)userdomainpass, userdomainpass_len, "%s:%s:%s", user, domain, password);
  md5_generate(md_buf, userdomainpass, userdomainpass_len - 1);

  /* client connected and can send TURN message */
  fprintf(stdout, "sock: %d speer: %p connected!\n", sock, (void*)speer);

  /* first request always failed but response contains the nonce */
  client_allocate_address(transport_protocol, relay_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, family, user, md_buf, domain, nonce, &nonce_len);
  if(nonce_len == 0)
  {
    fprintf(stderr, "Allocation: bad message received (no nonce).\n");
    ret = EXIT_FAILURE;
    goto quit;
  }

  /* second request should succeed otherwise credentials are wrong or
   * requested family is not supported by TURN server
   */
  if(client_allocate_address(transport_protocol, relay_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, family, user, md_buf, domain, nonce, &nonce_len) == -1)
  {
    fprintf(stderr, "Probably wrong credentials or requested family not supported.\n");
    ret = EXIT_FAILURE;
    goto quit;
  }

  fprintf(stdout, "Allocate an address!\n");

  /* add permission(s) */
  if(client_create_permission(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, user, md_buf, domain, nonce, nonce_len) == -1)
  {
    fprintf(stderr, "CreatePermission failed.\n");
    ret = EXIT_FAILURE;
    goto quit;
  }

  fprintf(stdout, "Permission installed!\n");

  if(relay_protocol == IPPROTO_UDP)
  {
    /* send data with Send indication */
    memset(data, 0xfe, sizeof(data));
    if(client_send_data(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, data, sizeof(data), user, md_buf, domain, nonce, nonce_len) == -1)
    {
      fprintf(stderr, "Send indication failed.\n");
      ret = EXIT_FAILURE;
      goto quit;
    }

    /* bind to a channel */
    if(client_channelbind(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, channel, user, md_buf, domain, nonce, nonce_len) == -1)
    {
      fprintf(stderr, "ChannelBind failed.\n");
      ret = EXIT_FAILURE;
      goto quit;
    }

    fprintf(stderr, "Channel bound to %u.\n", channel);

    /* send data with ChannelData */
    if(client_send_channeldata(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, channel, data, sizeof(data)) == -1)
    {
      fprintf(stderr, "ChannelData failed.\n");
    }
  }
  else
  {
    /* relay data with TCP */
    int sock_tcp = -1;
    int sock_tcp2 = -1;
    char buf[1500];
    ssize_t nb = -1;

    memset(data, 0xef, sizeof(data));

    /* send a Connect request and if success, send a ConnectionBind */
    if(client_send_connect(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, &sock_tcp, user, md_buf, domain, nonce, nonce_len) == -1)
    {
      fprintf(stderr, "Connect to the server failed.\n");
      ret = EXIT_FAILURE;
      goto quit;
    }

    /* ok now send data on dedicated TCP socket */
    if(send(sock_tcp, data, sizeof(data), 0) == -1)
    {
      fprintf(stderr, "Failed to send data to TURN-TCP relay.\n");
    }
    else
    {
      if((nb = recv(sock_tcp, buf, sizeof(buf), 0)) != -1)
      {
        fprintf(stdout, "Receive %d bytes (TURN-TCP).\n", (int)nb);
      }
    }

    /* to test this code part, you have to connect to
     * the TCP allocated port on the server (use
     * netstat -aptn | grep turnserver)
     */

    /* wait ConnectionAttempt and then send ConnectionBind */
    if(client_wait_connection(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, (struct sockaddr*)&peer_addr, &sock_tcp2, user, md_buf, domain, nonce, nonce_len) == -1)
    {
      fprintf(stderr, "Error no incoming connection before timeout or system error.\n");
    }
    else
    {
      /* first receive is connection response */
      if(recv(sock_tcp2, buf, sizeof(buf), 0) == -1)
      {
        fprintf(stderr, "Error, recv()\n");
        ret = EXIT_FAILURE;
        goto quit;
      }

      /* ok now receive data on dedicated TCP socket */
      if((nb = recv(sock_tcp2, buf, sizeof(buf), 0)) != -1)
      {
        fprintf(stdout, "Receive %d bytes (TURN-TCP incoming connection).\n", (int)nb);
      }
    }

    if(sock_tcp > 0)
    {
      close(sock_tcp);
    }

    if(sock_tcp2 > 0)
    {
      close(sock_tcp2);
    }
  }

  /* release allocation by setting its lifetime to 0 */
  if(client_refresh_allocation(transport_protocol, sock, speer, (struct sockaddr*)&server_addr, server_addr_size, 0, user, md_buf, domain, nonce, nonce_len) == -1)
  {
    fprintf(stderr, "Refresh failed.\n");
  }

  /* free resources */
  fprintf(stdout, "Cleanup and exit.\n");

quit:
  free(userdomainpass);

  if(speer)
  {
    tls_peer_free(&speer);
    LIBSSL_CLEANUP;
  }
  else
  {
    close(sock);
  }

  return ret;
}

