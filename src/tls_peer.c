/*
 *  TurnServer - TURN server implementation.
 *  Copyright (C) 2008-2011 Sebastien Vincent <sebastien.vincent@turnserver.org>
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

/*
 * Copyright (C) 2008-2011 Sebastien Vincent.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * This product includes software developed by the OpenSSL Project
 * for use in the OpenSSL Toolkit (http://www.openssl.org/).
 */

/**
 * \file tls_peer.c
 * \brief TLS and DTLS peer implementation.
 * \author Sebastien Vincent
 * \date 2008-2011
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32) && !defined(_WIN64)
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>

#include <arpa/inet.h>
#include <netdb.h>
#elif defined(_MSC_VER)
/* Microsoft compiler does not want users
 * to use snprintf directly...
 */
#define snprintf _snprintf
#endif

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509v3.h>

#include "tls_peer.h"

/* macro should be declared in netinet/in.h even in POSIX compilation
 * but it appeared that it is not defined on some BSD system
 */
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41	
#endif

/* MinGW does not define IPV6_V6ONLY */
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

#ifdef __cplusplus
extern "C"
{ /* } */
#endif

/* this file has been inspired by the open-source's vpmn and resiprocate
 * projects
 */

/**
 * \struct ssl_peer
 * \brief Describes a SSL peer client.
 */
struct ssl_peer
{
  SSL* ssl; /**< The remote peer */
  int handshake_complete; /**< State of the handshake */
  struct sockaddr_storage addr; /**< Socket address */
  struct list_head list; /**< For list management */
};

/**
 * \brief Free a SSL peer.
 * \param peer the SSL peer
 */
static void ssl_peer_free(struct ssl_peer** peer)
{
  struct ssl_peer* ret = *peer;

  SSL_shutdown(ret->ssl);
  SSL_free(ret->ssl);

  free(*peer);
  *peer = NULL;
}

/**
 * \brief Create a new SSL peer.
 * \param addr socket address
 * \param addrlen sizeof address
 * \param ssl SSL instance
 * \return valid pointer on ssl_peer, NULL if failure
 */
static struct ssl_peer* ssl_peer_new(struct sockaddr* addr, socklen_t addrlen,
    SSL* ssl)
{
  struct ssl_peer* ret = NULL;

  if(!(ret = malloc(sizeof(struct ssl_peer))))
  {
    return NULL;
  }

  memset(ret, 0x00, sizeof(struct ssl_peer));
  memcpy(&ret->addr, addr, addrlen);
  ret->ssl = ssl;
  ret->handshake_complete = 0;

  return ret;
}

/**
 * \brief Find the specified ssl_peer that match address.
 * \param peer (D)TLS peer instance
 * \param addr socket address client to find
 * \param addrlen sizeof addr
 * \return a valid ssl_peer pointer or NULL if not found
 */
static struct ssl_peer* tls_peer_find_connection(struct tls_peer* peer,
    const struct sockaddr* addr, socklen_t addrlen)
{
  struct list_head* n = NULL;
  struct list_head* get = NULL;

  list_iterate_safe(get, n, &peer->remote_peers)
  {
    struct ssl_peer* tmp = NULL;

    tmp = list_get(get, struct ssl_peer, list);
    if(!memcmp(&tmp->addr, addr, addrlen))
    {
      return tmp;
    }
  }
  return NULL;
}

/**
 * \brief Add a ssl_peer.
 * \param peer (D)TLS peer
 * \param speer ssl_peer client
 */
static void tls_peer_add_connection(struct tls_peer* peer,
    struct ssl_peer* speer)
{
  LIST_ADD_TAIL(&speer->list, &peer->remote_peers);
}

/**
 * \brief Remove a connection from the peer.
 * \param peer (D)TLS peer
 * \param ssl SSL peer to remove
 */
static void tls_peer_remove_connection(struct tls_peer* peer,
    struct ssl_peer* ssl)
{
  /* to avoid compilation warnings */
  (void)peer;

  LIST_DEL(&ssl->list);
  ssl_peer_free(&ssl);
}

/**
 * \brief Remove (and free) all connections from the peer.
 * \param peer (D)TLS peer
 */
static void tls_peer_clear_connection(struct tls_peer* peer)
{
  struct list_head* n = NULL;
  struct list_head* get = NULL;

  list_iterate_safe(get, n, &peer->remote_peers)
  {
    struct ssl_peer* tmp = NULL;
    tmp = list_get(get, struct ssl_peer, list);
    tls_peer_remove_connection(peer, tmp);
    return;
  }
}

/**
 * \brief Manage (D)TLS peer according to the error.
 * \param peer (D)TLS peer
 * \param ssl SSL peer concerned
 * \param err the error number
 */
static void tls_peer_manage_error(struct tls_peer* peer, struct ssl_peer* ssl,
    int err)
{
  switch(err)
  {
    case SSL_ERROR_NONE:
      break;
    case SSL_ERROR_SSL:
      fprintf(stderr, "SSL_ERROR_SSL: %s\n",
          ERR_reason_error_string(ERR_get_error()));
      /* big problem, remove the connection */
      tls_peer_remove_connection(peer, ssl);
      break;
    case SSL_ERROR_WANT_READ:
      fprintf(stderr, "SSL_ERROR_WANT_READ\n");
      break;
    case SSL_ERROR_WANT_WRITE:
      fprintf(stderr, "SSL_ERROR_WANT_WRITE\n");
      break;
    case SSL_ERROR_SYSCALL:
      fprintf(stderr, "SSL_ERROR_SYSCALL\n");
      tls_peer_remove_connection(peer, ssl);
      break;
    case SSL_ERROR_ZERO_RETURN: /* connection closed */
      fprintf(stderr, "SSL_ERROR_ZERO_RETURN\n");
      /* big problem, remove the connection */
      tls_peer_remove_connection(peer, ssl);
      break;
    case SSL_ERROR_WANT_CONNECT:
      fprintf(stderr, "SSL_ERROR_WANT_CONNECT\n");
      break;
    case SSL_ERROR_WANT_ACCEPT:
      fprintf(stderr, "SSL_ERROR_WANT_ACCEPT\n");
      break;
    default:
      fprintf(stderr, "SSL_ERROR_UNKNOWN\n");
      break;
  }
}

/**
 * \brief Load the certificates material in a context.
 * \param ctx the context
 * \param ca_file Certification Authority file
 * \param cert_file certificate file
 * \param key_file private key file
 * \param verify_callback certificate verification callback
 * \return 0 if success, -1 otherwise
 */
static int tls_peer_load_certificates(SSL_CTX* ctx, const char* ca_file,
    const char* cert_file, const char* key_file,
    int (*verify_callback)(int, X509_STORE_CTX *))
{
  if(SSL_CTX_set_cipher_list(ctx, "DEFAULT") != 1)
  {
    /* printf("Error setting cipher list.\n"); */
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
      verify_callback);
  SSL_CTX_set_verify_depth(ctx, 1);
  /* SSL_CTX_set_options(ctx, SSL_OP_NO_QUERY_MTU); */

  if(SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) != 1)
  {
    return -1;
  }

  if(SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1)
  {
    return -1;
  }

  if(SSL_CTX_load_verify_locations(ctx, ca_file, NULL) != 1)
  {
    return -1;
  }

  return 0;
}

/**
 * \brief Setup a (D)TLS peer.
 * \param peer tls_peer instance to setup
 * \param type UDP or TCP
 * \param addr Network address
 * \param port port
 * \param ca_file certification authorities file
 * \param cert_file certificate file
 * \param key_file private key file
 * \return 0 if success, -1 otherwise
 * \note If returns -1, the caller must call tls_peer_free() as some memory
 * could be allocated
 */
static int tls_peer_setup(struct tls_peer* peer, enum protocol_type type,
    const char* addr, uint16_t port, const char* ca_file, const char* cert_file,
    const char* key_file)
{
  STACK_OF(X509_NAME)* calist = NULL;
  SSL_METHOD* method_server = NULL;
  SSL_METHOD* method_client = NULL;

  /* initialize list */
  INIT_LIST(peer->remote_peers);

  if(type == UDP)
  {
    method_client = (SSL_METHOD*)DTLSv1_client_method();
    method_server = (SSL_METHOD*)DTLSv1_server_method();
  }
  else
  {
    method_client = (SSL_METHOD*)TLSv1_client_method();
    method_server = (SSL_METHOD*)TLSv1_server_method();
  }

  peer->ctx_client = SSL_CTX_new(method_client);
  if(!peer->ctx_client)
  {
    return -1;
  }

  peer->ctx_server = SSL_CTX_new(method_server);
  if(!peer->ctx_server)
  {
    return -1;
  }

  peer->bio_fake = BIO_new(BIO_s_mem());
  if(!peer->bio_fake)
  {
    return -1;
  }

  BIO_set_mem_eof_return(peer->bio_fake, -1);

  if(ca_file)
  {
    /* load certificates in ctx_client and ctx_server */
    if((tls_peer_load_certificates(peer->ctx_client, ca_file, cert_file,
            key_file, peer->verify_callback) == -1) ||
       (tls_peer_load_certificates(peer->ctx_server, ca_file, cert_file,
            key_file, peer->verify_callback) == -1))
    {
      return -1;
    }

    calist = SSL_load_client_CA_file(ca_file);
    if(calist == NULL)
    {
      return -1;
    }

    SSL_CTX_set_client_CA_list(peer->ctx_server, calist);
  }

  peer->sock = socket_create(type, addr, port, 0, 0);
  peer->type = type;

  return (peer->sock > 0)  ? 0 : -1;
}

/**
 * \brief Read a (D)TLS message.
 * \param peer (D)TLS peer
 * \param buf in buffer
 * \param buflen in buffer length
 * \param bufout out buffer
 * \param bufoutlen out buffer length
 * \param speer SSL peer
 * \return number of bytes read or -1 if error or handshake not finalized
 */
static ssize_t tls_peer_read(struct tls_peer* peer, char* buf, ssize_t buflen,
    char* bufout, ssize_t bufoutlen, struct ssl_peer* speer)
{
  BIO* bio_read = NULL;
  ssize_t len = -1;
  int err = 0;

  /* printf("tls_peer_read\n"); */

  bio_read = BIO_new_mem_buf(buf, buflen);
  BIO_set_mem_eof_return(bio_read, -1);

  speer->ssl->rbio = bio_read;
  len = SSL_read(speer->ssl, bufout, bufoutlen);
  err = SSL_get_error(speer->ssl, len);

  BIO_free(bio_read);
  speer->ssl->rbio = NULL;

  if(!speer->handshake_complete && SSL_is_init_finished(speer->ssl))
  {
    /* at this point, socket can send data */
    speer->handshake_complete = 1;
  }

  if(len <= 0)
  {
    tls_peer_manage_error(peer, speer, err);
  }

  return len;
}

/**
 * \brief Verify certificate chain.
 * \param ssl SSL pointer
 * \return 1 if certificate verification is OK, 0 otherwise
 */
static int verify_certificate(SSL* ssl)
{
    X509* x509 = SSL_get_peer_certificate(ssl);

    if(x509)
    {
      if(SSL_get_verify_result(ssl) != X509_V_OK)
      {
        /* printf("problem certificate\n"); */
        return 0;
      }

      return 1;
    }

  return 1;
}

void tls_peer_print_connection(struct tls_peer* peer)
{
  struct list_head* n = NULL;
  struct list_head* get = NULL;
  char buf[INET6_ADDRSTRLEN];

  fprintf(stdout, "Current peer information (List size = %u)\n",
      list_size(&peer->remote_peers));

  list_iterate_safe(get, n, &peer->remote_peers)
  {
    struct ssl_peer* tmp = list_get(get, struct ssl_peer, list);

    if(getnameinfo((struct sockaddr*)&tmp->addr, sizeof(tmp->addr), buf,
          INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST) != 0)
    {
      continue;
    }
#ifndef NDEBUG
    fprintf(stdout, "Network address: %s handshake_completed: %u\n", buf,
        tmp->handshake_complete);
#endif
  }
}

int tls_peer_do_handshake(struct tls_peer* peer, const struct sockaddr* daddr,
    socklen_t daddr_size)
{
  int nsock = -1;
  struct timeval tv;
  int ret = -1;
  char buf[8192];
  char bufout[8192];
  struct ssl_peer* speer = NULL;
  struct sockaddr_storage daddr2;

  tls_peer_write(peer, NULL, 0, daddr, daddr_size);
  speer = tls_peer_find_connection(peer, daddr, daddr_size);
  if(!speer)
  {
    return -1;
  }

  while(!speer->handshake_complete)
  {
    fd_set fdsr;

    FD_ZERO(&fdsr);
    FD_SET(peer->sock, &fdsr);

    /* 4 seconds of timeout */
    tv.tv_sec = 4;
    tv.tv_usec = 0;

    nsock = peer->sock;
    nsock++;

    if(peer->type == TCP)
    {
      speer->handshake_complete = SSL_is_init_finished(speer->ssl);

      if(speer->handshake_complete)
      {
        /* handshake successfull */
        return 0;
      }
    }

    ret = select(nsock, &fdsr, NULL, NULL, &tv);

    if(ret > 0)
    {
      if(FD_ISSET(peer->sock, &fdsr))
      {
        ssize_t nb = -1;

        if(peer->type == UDP)
        {
          nb = recvfrom(peer->sock, buf, sizeof(buf), 0,
              (struct sockaddr*)&daddr2, &daddr_size);
        }
        else /* TCP */
        {
          nb = recv(peer->sock, buf, sizeof(buf), 0);
        }

        if(nb > 0)
        {
          if(peer->type == TCP)
          {
            if(tls_peer_tcp_read(peer, buf, nb, bufout, sizeof(bufout), daddr,
                daddr_size, peer->sock) == -1)
            {
              return -1;
            }
          }
          else /* UDP */
          {
            /* DTLS can return -1 for handshake so no failure if it happens */
            tls_peer_udp_read(peer, buf, nb, bufout, sizeof(bufout), daddr,
                daddr_size);
          }
        }
      }
    }
    else
    {
      /* if timeout or syscall error, break loop */
      break;
    }
  }

  return (ret > 0) ? 0 : -1;
}

ssize_t tls_peer_tcp_read(struct tls_peer* peer, char* buf, ssize_t buflen,
    char* bufout, ssize_t bufoutlen, const struct sockaddr* addr,
    socklen_t addrlen, int sock)
{
  struct ssl_peer* speer = NULL;

  /* printf("tls_peer_tcp_read\n"); */

  if(!addr || peer->type != TCP)
  {
    return -1;
  }

  speer = tls_peer_find_connection(peer, addr, addrlen);

  if(!speer)
  {
    /* printf("new peer\n"); */
    SSL* ssl = SSL_new(peer->ctx_server);

    if(!ssl)
    {
      return -1;
    }

    SSL_set_accept_state(ssl);

    /* associate the SSL pointer with the socket descriptor */
    SSL_set_fd(ssl, sock);

    speer = ssl_peer_new((struct sockaddr*)addr, addrlen, ssl);
    if(!speer)
    {
      SSL_free(ssl);
      return -1;
    }
    tls_peer_add_connection(peer, speer);
  }

  return tls_peer_read(peer, buf, buflen, bufout, bufoutlen, speer);
}

ssize_t tls_peer_udp_read(struct tls_peer* peer, char* buf, ssize_t buflen,
    char* bufout, ssize_t bufoutlen, const struct sockaddr* addr,
    socklen_t addrlen)
{
  struct ssl_peer* speer = NULL;

  /* printf("tls_peer_udp_read\n"); */

  if(!addr || peer->type != UDP)
  {
    return -1;
  }

  speer = tls_peer_find_connection(peer, addr, addrlen);

  if(!speer)
  {
    /* printf("new peer\n"); */
    BIO* bio_write = NULL;
    SSL* ssl = SSL_new(peer->ctx_server);

    if(!ssl)
    {
      return -1;
    }

    SSL_set_accept_state(ssl);

    if(!verify_certificate(ssl))
    {
      SSL_free(ssl);
      return -1;
    }

    bio_write = BIO_new_dgram(peer->sock, BIO_NOCLOSE);
    (void)BIO_dgram_set_peer(bio_write, addr);

    SSL_set_bio(ssl, NULL, bio_write);
    /* SSL_set_mtu(ssl, SSL3_RT_MAX_PLAIN_LENGTH); */

    speer = ssl_peer_new((struct sockaddr*)addr, addrlen, ssl);
    if(!speer)
    {
      SSL_free(ssl);
      return -1;
    }
    tls_peer_add_connection(peer, speer);
  }

  return tls_peer_read(peer, buf, buflen, bufout, bufoutlen, speer);
}

ssize_t tls_peer_write(struct tls_peer* peer, const char* buf, ssize_t buflen,
    const struct sockaddr* addr, socklen_t addrlen)
{
  BIO* bio_write = NULL;
  ssize_t len = -1;
  int err = 0;
  struct ssl_peer* speer = NULL;

  /* printf("tls_write\n"); */

  speer = tls_peer_find_connection(peer, addr, addrlen);

  if(!speer)
  {
    /* printf("new peer\n"); */
    SSL* ssl = SSL_new(peer->ctx_client);

    SSL_set_connect_state(ssl);

    if(!verify_certificate(ssl))
    {
      SSL_free(ssl);
      return -1;
    }

    if(peer->type != TCP)
    {
      bio_write = BIO_new_dgram(peer->sock, BIO_NOCLOSE);
      (void)BIO_dgram_set_peer(bio_write, addr);
      SSL_set_bio(ssl, peer->bio_fake, bio_write);
      /* SSL_set_mtu(ssl, SSL3_RT_MAX_PLAIN_LENGTH); */
    }
    else
    {
      SSL_set_fd(ssl, peer->sock);
    }

    speer = ssl_peer_new((struct sockaddr*)addr, addrlen, ssl);
    if(!speer)
    {
      CRYPTO_add(&peer->bio_fake->references, 1, CRYPTO_LOCK_BIO);
      SSL_free(ssl);
      return -1;
    }

    tls_peer_add_connection(peer, speer);
    SSL_do_handshake(speer->ssl);
    return 0;
  }

  if(!buf)
  {
    return -1;
  }

  len = SSL_write(speer->ssl, buf, buflen);
  err = SSL_get_error(speer->ssl, len);

  if(len <= 0)
  {
    tls_peer_manage_error(peer, speer, err);
  }

  return len;
}

int tls_peer_is_encrypted(const char* buf, size_t len)
{
  uint8_t c = 0;
  uint8_t v = 0;
  uint8_t v2 = 0;

  if(len < 3)
  {
    return 0;
  }

  c = buf[0];
  v = buf[1];
  v2 = buf[2];

  /* test the 3 first bytes */
  if(c == 0x14 || c == 0x15 || c == 0x16 || c == 0x17)
  {
    /* ok first byte indicates that it is possibly a TLS frame,
     * check the next two bytes to see if it is TLSv1 or DTLSv1
     */

    /* TLSv1 */
    if(v == 0x03 && v2 == 0x01)
    {
      return 1;
    }

    /* DTLSv1 */
    if(v == 0xfe && v2 == 0xff)
    {
      return 1;
    }
  }

  return 0;
}

int socket_create(enum protocol_type type, const char* addr, uint16_t port,
    int reuse, int nodelay)
{
  int sock = -1;
  struct addrinfo hints;
  struct addrinfo* res = NULL;
  struct addrinfo* p = NULL;
  char service[8];

  snprintf(service, sizeof(service), "%u", port);
  service[sizeof(service)-1] = 0x00;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = (type == TCP ? SOCK_STREAM : SOCK_DGRAM);
  hints.ai_protocol = (type == TCP ? IPPROTO_TCP : IPPROTO_UDP);
  hints.ai_flags = AI_PASSIVE;

  if(getaddrinfo(addr, service, &hints, &res) != 0)
  {
    return -1;
  }

  for(p = res ; p ; p = p->ai_next)
  {
    int on = 1;

    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if(sock == -1)
    {
      continue;
    }

    if(reuse)
    {
      setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    }

    if (type == TCP && nodelay)
    {
      setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(int));
    }

    /* accept IPv6 and IPv4 on the same socket */
    on = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(int));

    if(bind(sock, p->ai_addr, p->ai_addrlen) == -1)
    {
      close(sock);
      sock = -1;
      continue;
    }

    /* socket bound, break the loop */
    break;
  }

  freeaddrinfo(res);
  p = NULL;

  return sock;
}

void tls_peer_free(struct tls_peer** peer)
{
  struct tls_peer* ret = *peer;

  /* remote peer(s) */
  tls_peer_clear_connection(ret);

  /* CTXs */
  if(ret->ctx_client)
  {
    SSL_CTX_free(ret->ctx_client);
  }

  if(ret->ctx_server)
  {
    SSL_CTX_free(ret->ctx_server);
  }

  if(ret->bio_fake)
  {
    BUF_MEM* ptr = NULL;
    BIO_get_mem_ptr(ret->bio_fake, &ptr);
    /* so BIO_free() leaves BUF_MEM alone */
    (void)BIO_set_close(ret->bio_fake, BIO_NOCLOSE);
    BIO_free(ret->bio_fake);
    BUF_MEM_free(ptr);
  }

  if(ret->sock > 0)
  {
    close(ret->sock);
  }

  free(*peer);

  *peer = NULL;
}

struct tls_peer* tls_peer_new(enum protocol_type type, const char* addr,
    uint16_t port, const char* ca_file, const char* cert_file,
    const char* key_file, int (*verify_callback)(int, X509_STORE_CTX *))
{
  struct tls_peer* ret = NULL;

  if(!(ret = malloc(sizeof(struct tls_peer))))
  {
    return NULL;
  }

  memset(ret, 0x00, sizeof(struct tls_peer));

  ret->verify_callback = verify_callback;

  if(tls_peer_setup(ret, type, addr, port, ca_file, cert_file, key_file) == -1)
  {
    tls_peer_free(&ret);
    return NULL;
  }

  return ret;
}

#ifdef __cplusplus
}
#endif

