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
 * \file turnserver.c
 * \brief TURN Server implementation.
 * \author Sebastien Vincent
 * \date 2008-2012
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include "conf.h"
#include "protocol.h"
#include "allocation.h"
#include "account.h"
#include "tls_peer.h"
#include "util_sys.h"
#include "util_crypto.h"
#include "dbg.h"
#include "turnserver.h"
#include "mod_tmpuser.h"

#ifndef HAVE_SIGACTION
/* expiration stuff use real-time signals
 * that can only be handled by sigaction
 * so stop compilation with error
 */
#error "Must have sigaction."
#endif

/* for operating systems that support setting
 * DF flag from userspace, give them a
 * #define OS_SET_DF_SUPPORT
 */
#if defined(__linux__)
/**
 * \def OS_SET_DF_SUPPORT
 * \brief Current operating system can set the DF flag.
 */
#define OS_SET_DF_SUPPORT 1
#endif

/**
 * \def SOFTWARE_DESCRIPTION
 * \brief Textual description of the server.
 */
#define SOFTWARE_DESCRIPTION "TurnServer " PACKAGE_VERSION

/**
 * \def DEFAULT_CONFIGURATION_FILE
 * \brief Default configuration file pathname.
 */
#define DEFAULT_CONFIGURATION_FILE "/etc/turnserver.conf"

/**
 * \var g_run
 * \brief Running state of the program.
 */
static volatile sig_atomic_t g_run = 0;

/**
 * \var g_reinit
 * \brief Reload credentials (parse again account file).
 */
static volatile sig_atomic_t g_reinit = 0;

/**
 * \var g_expired_allocation_list
 * \brief List which constains expired allocation.
 */
static struct list_head g_expired_allocation_list;

/**
 * \var g_expired_permission_list
 * \brief List which constains expired permissions.
 */
static struct list_head g_expired_permission_list;

/**
 * \var g_expired_channel_list
 * \brief List which constains expired channels.
 */
static struct list_head g_expired_channel_list;

/**
 * \var g_expired_token_list
 * \brief List which contains expired tokens.
 */
static struct list_head g_expired_token_list;

/**
 * \var g_expired_tcp_relay_list
 * \brief List which contains expired TCP relays.
 */
static struct list_head g_expired_tcp_relay_list;

/**
 * \var g_token_list
 * \brief List of valid tokens.
 */
static struct list_head g_token_list;

/**
 * \var g_denied_address_list
 * \brief The denied address list.
 */
static struct list_head g_denied_address_list;

/**
 * \var g_supported_even_port_flags
 * \brief EVEN-PORT flags supported.
 *
 * For the moment the following flags are supported:
 * - R: reserve couple of ports (one even, one odd).
 */
static const uint8_t g_supported_even_port_flags = 0x80;

/**
 * \var g_tcp_socket_list
 * \brief List which contains remote TCP sockets.
 *
 * This list does not contains TURN-TCP related sockets.
 */
static struct list_head g_tcp_socket_list;

/**
 * \struct listen_sockets
 * \brief Gather all listen sockets (UDP, TCP, TLS and DTLS).
 */
struct listen_sockets
{
  int sock_tcp; /**< Listen TCP socket */
  int sock_udp; /**< Listen UDP socket */
  struct tls_peer* sock_tls; /**< Listen TLS socket */
  struct tls_peer* sock_dtls; /**< Listen DTLS socket */
};

/**
 * \brief Get sockaddr structure size according to its type.
 * \param ss sockaddr_storage structure
 * \return size of sockaddr_in or sockaddr_in6
 */
static inline socklen_t sockaddr_get_size(struct sockaddr_storage* ss)
{
  /* assume address type is IPv4 or IPv6 as TURN specification
   * supports only these two types of address
   */
  return (ss->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
    sizeof(struct sockaddr_in6);
}

/**
 * \brief Signal management.
 * \param code signal code
 */
static void signal_handler(int code)
{
  switch(code)
  {
    case SIGUSR1:
    case SIGUSR2:
    case SIGPIPE:
      break;
    case SIGHUP:
      g_reinit = 1;
      break;
    case SIGINT:
    case SIGTERM:
      /* stop the program */
      g_run = 0;
      break;
    default:
      break;
  }
}

/**
 * \brief Realtime signal management.
 *
 * This is mainly used when a object timer expired. As usage of functions like
 * free() in a signal handler are not permitted and to avoid race conditions,
 * this function put the desired expired object in an expired list and the main
 * loop will purge it.
 * \param signo signal number
 * \param info additionnal info
 * \param extra not used
 */
static void realtime_signal_handler(int signo, siginfo_t* info, void* extra)
{
  /* to avoid compilation warning because it is not used */
  (void)extra;

  if(!g_run)
  {
    /* if the program will exit, do not care about signals */
    return;
  }

  debug(DBG_ATTR, "Realtime signal received\n");

  if(signo == SIGRT_EXPIRE_ALLOCATION)
  {
    struct allocation_desc* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Allocation expires: %p\n", desc);
    /* add it to the expired list, the next loop will
     * purge it
     */
    LIST_ADD(&desc->list2, &g_expired_allocation_list);
  }
  else if(signo == SIGRT_EXPIRE_PERMISSION)
  {
    struct allocation_permission* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Permission expires: %p\n", desc);
    /* add it to the expired list */
    LIST_ADD(&desc->list2, &g_expired_permission_list);
  }
  else if(signo == SIGRT_EXPIRE_CHANNEL)
  {
    struct allocation_channel* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Channel expires: %p\n", desc);
    /* add it to the expired list */
    LIST_ADD(&desc->list2, &g_expired_channel_list);
  }
  else if(signo == SIGRT_EXPIRE_TOKEN)
  {
    struct allocation_token* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    debug(DBG_ATTR, "Token expires: %p\n", desc);
    /* add it to the expired list */
    LIST_ADD(&desc->list2, &g_expired_token_list);
  }
  else if(signo == SIGRT_EXPIRE_TCP_RELAY)
  {
    struct allocation_tcp_relay* desc = info->si_value.sival_ptr;

    if(!desc)
    {
      return;
    }

    /* remove relay from list */
    debug(DBG_ATTR, "TCP relay expires: %p\n", desc);
    LIST_ADD(&desc->list2, &g_expired_tcp_relay_list);
  }
}

/**
 * \brief Block realtime signal used in TurnServer.
 *
 * This is used to prevent race conditions when adding or removing objects in
 * expired list (which is mainly done in signal handler and in purge loop).
 */
static inline void turnserver_block_realtime_signal(void)
{
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
  sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
  sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
  sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
  sigprocmask(SIG_BLOCK, &mask, NULL);
}

/**
 * \brief Unblock realtime signal used in TurnServer.
 *
 * This is used to prevent race conditions when adding or removing objects in
 * expired list (which is mainly done in signal handler and in purge loop).
 */
static inline void turnserver_unblock_realtime_signal(void)
{
  sigset_t mask;

  sigemptyset(&mask);
  sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
  sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
  sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
  sigaddset(&mask, SIGRT_EXPIRE_TOKEN);
  sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

/**
 * \brief Print help menu.
 * \param name name of the program
 * \param version version of the program
 */
static void turnserver_print_help(const char* name, const char* version)
{
  fprintf(stdout, "TurnServer %s\n", version);
  fprintf(stdout, "Usage: %s [-c file] [-p pidfile] [-h] [-v]\n", name);
}

/**
 * \brief Parse the command line arguments.
 * \param argc number of argument
 * \param argv array of argument
 * \param configuration_file configuration (-c) argument will be filled in if
 * any
 * \param pid_file pid file (-p) argument will be filled in if any
 */
static void turnserver_parse_cmdline(int argc, char** argv,
    char** configuration_file, char** pid_file)
{
  static const char* optstr = "c:p:hv";
  int s = 0;

  while((s = getopt(argc, argv, optstr)) != -1)
  {
    switch(s)
    {
      case 'h': /* help */
        turnserver_print_help(argv[0], PACKAGE_VERSION);
        exit(EXIT_SUCCESS);
        break;
      case 'v': /* version */
        fprintf(stdout, "TurnServer %s\n", PACKAGE_VERSION);
        fprintf(stdout, "Copyright (C) 2008-2012 Sebastien Vincent.\n");
        fprintf(stdout, "This is free software; see the source for copying "
            "conditions.  There is NO\n");
        fprintf(stdout, "warranty; not even for MERCHANTABILITY or FITNESS FOR "
            "A PARTICULAR PURPOSE.\n\n");
        exit(EXIT_SUCCESS);
      case 'c': /* configuration file */
        if(optarg)
        {
          *configuration_file = optarg;
        }
        break;
      case 'p': /* pid file */
        if(optarg)
        {
          *pid_file = optarg;
        }
        break;
      default:
        break;
    }
  }
}

#ifdef NDEBUG

/**
 * \brief Disable core dump if the server crash.
 *
 * Typically it is used in release mode. It prevents
 * user/attacker to have access to core dump which could
 * contains some sensitive data.
 */
static void turnserver_disable_core_dump(void)
{
  struct rlimit limit;

  limit.rlim_cur = 0;
  limit.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &limit);
}

#endif

/**
 * \brief Check bandwidth limitation on uplink OR downlink.
 * \param desc allocation descriptor
 * \param byteup byte received on uplink connection. 0 means bandwidth check
 * will be made on downlink (if different than 0)
 * \param bytedown byte received on downlink connection. 0 means bandwidth check
 * will be made on uplink (if different than 0)
 * \return 1 if bandwidth threshold is exceeded, 0 otherwise
 */
static int turnserver_check_bandwidth_limit(struct allocation_desc* desc,
    size_t byteup, size_t bytedown)
{
  struct timeval now;
  unsigned long diff = 0;
  unsigned long d = turnserver_cfg_bandwidth_per_allocation();

  if(d <= 0)
  {
    /* bandwidth quota disabled */
    return 0;
  }

  /* check in ms */
  gettimeofday(&now, NULL);

  if(byteup)
  {
    if(desc->bucket_tokenup < desc->bucket_capacity)
    {
      /* count in milliseconds */
      diff = (now.tv_sec - desc->last_timeup.tv_sec) * 1000 +
        (now.tv_usec - desc->last_timeup.tv_usec) / 1000;
      d *= diff;
      desc->bucket_tokenup = MIN(desc->bucket_capacity,
          desc->bucket_tokenup + d);
      gettimeofday(&desc->last_timeup, NULL);
    }

    debug(DBG_ATTR, "Tokenup bucket available: %u, tokens requested: %u\n",
        desc->bucket_tokenup, byteup);

    if(byteup <= desc->bucket_tokenup)
    {
      desc->bucket_tokenup -= byteup;
    }
    else
    {
      /* bandwidth exceeded */
      return 1;
    }
  }
  else if(bytedown)
  {
    if(desc->bucket_tokendown < desc->bucket_capacity)
    {
      /* count in milliseconds */
      diff = (now.tv_sec - desc->last_timedown.tv_sec) * 1000 +
        (now.tv_usec - desc->last_timedown.tv_usec) / 1000;
      d *= diff;
      desc->bucket_tokendown = MIN(desc->bucket_capacity,
          desc->bucket_tokendown + d);
      gettimeofday(&desc->last_timedown, NULL);
    }

    debug(DBG_ATTR, "Tokendown bucket available: %u, tokens requested: %u\n",
        desc->bucket_tokendown, bytedown);

    if(bytedown <= desc->bucket_tokendown)
    {
      desc->bucket_tokendown -= bytedown;
    }
    else
    {
      /* bandwidth exceeded */
      return 1;
    }
  }

  /* bandwidth quota not reached */
  return 0;
}

/**
 * \brief Verify if the address is an IPv6 tunneled ones.
 * \param addr address to check
 * \param addrlen sizeof address
 * \return 1 if address is an IPv6 tunneled ones, 0 otherwise
 */
static int turnserver_is_ipv6_tunneled_address(const uint8_t* addr,
    size_t addrlen)
{
  if(addrlen == 16)
  {
    static const uint8_t addr_6to4[2] = {0x20, 0x02};
    static const uint8_t addr_teredo[4] = {0x20, 0x01, 0x00, 0x00};

    /* 6to4 or teredo address ? */
    if(!memcmp(addr, addr_6to4, 2) || !memcmp(addr, addr_teredo, 4))
    {
      return 1;
    }
  }
  return 0;
}

/**
 * \brief Verify if address/port is in denied list.
 * \param addr IPv4/IPv6 address to check
 * \param addrlen sizeof the address (IPv4 = 4, IPv6 = 16)
 * \param port port to check
 * \return 1 if address is denied, 0 otherwise
 */
static int turnserver_is_address_denied(const uint8_t* addr, size_t addrlen,
    uint16_t port)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;
  uint8_t nb = 0;
  uint8_t mod = 0;
  size_t i = 0;

  /* IPv6 address maximum length is 16 bytes */
  if(addrlen > 16)
  {
    return 0;
  }

  list_iterate_safe(get, n, &g_denied_address_list)
  {
    struct denied_address* tmp = list_get(get, struct denied_address, list);
    int diff = 0;

    /* compare addresses from same family */
    if((tmp->family == AF_INET6 && addrlen != 16) ||
       (tmp->family == AF_INET && addrlen != 4))
    {
      continue;
    }

    nb = (uint8_t)(tmp->mask / 8);

    for(i = 0 ; i < nb ; i++)
    {
      if(tmp->addr[i] != addr[i])
      {
        diff = 1;
        break;
      }
    }

    /* if mismatch in the addresses */
    if(diff)
    {
      continue;
    }

    /* OK so now the full bytes from the address are the same,
     * check for last bit if any
     */
    mod = (tmp->mask % 8);

    if(mod)
    {
      uint8_t b = 0;

      for(i = 0 ; i < mod ; i++)
      {
        b |= (1 << (7 - i));
      }

      if((tmp->addr[nb] & b) == (addr[nb] & b))
      {
        if(tmp->port == 0 || tmp->port == port)
        {
          return 1;
        }
      }
    }
    else
    {
      if(tmp->port == 0 || tmp->port == port)
      {
        return 1;
      }
    }
  }

  return 0;
}

/**
 * \brief Send a TURN Error response.
 * \param transport_protocol transport protocol to send the message
 * \param sock socket
 * \param method STUN/TURN method
 * \param id transaction ID
 * \param saddr address to send
 * \param saddr_size sizeof address
 * \param error error code
 * \param speer TLS peer, if not NULL, send the error in TLS
 * \param key MD5 hash of account, if present, MESSAGE-INTEGRITY will be added
 * \note Some error codes cannot be sent using this function (420, 438, ...).
 * \return 0 if success, -1 otherwise
 */
static int turnserver_send_error(int transport_protocol, int sock, int method,
    const uint8_t* id, int error, const struct sockaddr* saddr,
    socklen_t saddr_size, struct tls_peer* speer, unsigned char* key)
{
  struct iovec iov[16]; /* should be sufficient */
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  size_t idx = 0;

  switch(error)
  {
    case 400: /* Bad request */
      hdr = turn_error_response_400(method, id, &iov[idx], &idx);
      break;
    case 403: /* Forbidden */
      hdr = turn_error_response_403(method, id, &iov[idx], &idx);
      break;
    case 437: /* Alocation mismatch */
      hdr = turn_error_response_437(method, id, &iov[idx], &idx);
      break;
    case 440: /* Address family not supported */
      hdr = turn_error_response_440(method, id, &iov[idx], &idx);
      break;
    case 441: /* Wrong credentials */
      hdr = turn_error_response_441(method, id, &iov[idx], &idx);
      break;
    case 442: /* Unsupported transport protocol */
      hdr = turn_error_response_442(method, id, &iov[idx], &idx);
      break;
    case 443: /* Peer address family mismatch */
      hdr = turn_error_response_443(method, id, &iov[idx], &idx);
      break;
    case 446: /* Connection already exists (RFC6062) */
      hdr = turn_error_response_446(method, id, &iov[idx], &idx);
      break;
    case 447: /* Connection timeout or failure (RFC6062) */
      hdr = turn_error_response_447(method, id, &iov[idx], &idx);
      break;
    case 486: /* Allocation quota reached */
      hdr = turn_error_response_486(method, id, &iov[idx], &idx);
      break;
    case 500: /* Server error */
      hdr = turn_error_response_500(method, id, &iov[idx], &idx);
      break;
    case 508: /* Insufficient port capacity */
      hdr = turn_error_response_508(method, id, &iov[idx], &idx);
      break;
    default:
      break;
  }

  if(!hdr)
  {
    return -1;
  }

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(key)
  {
    if(turn_add_message_integrity(iov, &idx, key, 16, 1) == -1)
    {
      /* MESSAGE-INTEGRITY option has to be in message, so
       * deallocate ressources and return
       */
      iovec_free_data(iov, idx);
      return -1;
    }
    /* function above already set turn_msg_len field to big endian */
  }
  else
  {
    turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

    /* convert to big endian */
    hdr->turn_msg_len = htons(hdr->turn_msg_len);
  }

  /* finally send the response */
  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return 0;
}

/**
 * \brief Process a TURN Connect request (RFC6062).
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_connect_request(int transport_protocol, int sock,
    const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct allocation_desc* desc, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  uint8_t peer_addr[16];
  uint16_t peer_port = 0;
  uint16_t len = 0;
  struct sockaddr_storage storage;
  int peer_sock = -1;
  int family = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  uint32_t id = 0;
  long flags = 0;
  int ret = 0;

  debug(DBG_ATTR, "Connect request received!\n");

  /* check also that allocation has a maximum of one
   * outgoing connection
   * (if relayed_sock_tcp equals -1 it means that it exists
   * already an outgoing connection for this allocation)
   */
  if(!message->peer_addr[0] || desc->relayed_sock_tcp == -1)
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  switch(message->peer_addr[0]->turn_attr_family)
  {
    case STUN_ATTR_FAMILY_IPV4:
      len = 4;
      family = AF_INET;
      break;
    case STUN_ATTR_FAMILY_IPV6:
      len = 16;
      family = AF_INET6;
      break;
    default:
      return -1;
      break;
  }

  /* copy address/port */
  memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
  peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

  if(turn_xor_address_cookie(family, peer_addr, &peer_port, p,
        message->msg->turn_msg_id) == -1)
  {
    return -1;
  }

  if(desc->relayed_addr.ss_family != family)
  {
    debug(DBG_ATTR, "Could not relayed from a different family\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  /* check if server has already processed the same
   * XOR-PEER-ADDRESS with this allocation => error 446
   */
  if(allocation_desc_find_tcp_relay_addr(desc, family, peer_addr, peer_port))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 446, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  /* check if the address is not blacklisted, also check for an IPv6 tunneled
   * address that can lead to a tunne amplification attack
   * (see section 9.1 of RFC6156)
   */
  if(turnserver_is_address_denied(peer_addr, len, peer_port) ||
      turnserver_is_ipv6_tunneled_address(peer_addr, len))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 403, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  /* connection to peer */
  switch(family)
  {
    case AF_INET:
      ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
      memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
      ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
      memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
          sizeof((struct sockaddr_in*)&storage)->sin_zero);
      break;
    case AF_INET6:
      ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
      memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
      ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
      ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
      ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
      ((struct sockaddr_in6*)&storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
      break;
    default:
      return -1;
      break;
  }

  peer_sock = desc->relayed_sock_tcp;
  desc->relayed_sock_tcp = -1;

  /* set non-blocking mode */
  if((flags = fcntl(peer_sock, F_GETFL, NULL)) == -1)
  {
    return -1;
  }

  flags |= O_NONBLOCK;

  if(fcntl(peer_sock, F_SETFL, flags) == -1)
  {
    return -1;
  }

  ret = connect(peer_sock, (struct sockaddr*)&storage,
      sockaddr_get_size(&storage));

  if(errno == EINPROGRESS)
  {
    /* connection ongoing */
    /* generate unique ID */
    random_bytes_generate((uint8_t*)&id, 4);

    /* add it to allocation */
    if(allocation_desc_add_tcp_relay(desc, id, peer_sock, family, peer_addr,
          peer_port, TURN_DEFAULT_TCP_RELAY_TIMEOUT, 0,
          message->msg->turn_msg_id) == -1)
    {
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
      return -1;
    }
    return 0;
  }
  else if(ret < 0)
  {
    /* error */
    char error_str[256];
    get_error(errno, error_str, sizeof(error_str));
    syslog(LOG_ERR, "connect to peer failed: %s", error_str);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 447, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  return -1;
}

/**
 * \brief Process a TURN ConnectionBind request (RFC6062).
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \param account account descriptor
 * \param allocation_list list of allocations
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_connectionbind_request(int transport_protocol,
    int sock, const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct tls_peer* speer, struct account_desc* account,
    struct list_head* allocation_list)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  struct allocation_tcp_relay* tcp_relay = NULL;
  struct list_head* get = NULL;
  struct list_head* n = NULL;
  struct allocation_desc* desc = NULL;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[8];
  size_t idx = 0;

  debug(DBG_ATTR, "ConnectionBind request received!\n");

  if(!message->connection_id)
  {
    debug(DBG_ATTR, "No CONNECTION-ID attribute!\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
    return -1;
  }

  /* find corresponding allocation for TCP connection ID */
  list_iterate_safe(get, n, allocation_list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
    struct list_head* get2 = NULL;
    struct list_head* n2 = NULL;

    if(tmp->relayed_transport_protocol != IPPROTO_TCP ||
        memcmp(tmp->key, account->key, sizeof(tmp->key) != 0))
    {
      continue;
    }

    list_iterate_safe(get2, n2, &tmp->tcp_relays)
    {
      struct allocation_tcp_relay* tmp2 =
        list_get(get2, struct allocation_tcp_relay, list);

      if(tmp2->connection_id == message->connection_id->turn_attr_id)
      {
        desc = tmp;
        break;
      }
    }

    /* found ? */
    if(desc)
    {
      break;
    }
  }

  /* check if allocation exists and if its ID exists for this allocation
   * otherwise => error 400
   */
  if(!desc || !(tcp_relay = allocation_desc_find_tcp_relay_id(desc,
          message->connection_id->turn_attr_id)))
  {
    debug(DBG_ATTR, "No allocation or no allocation for CONNECTION-ID\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
    return -1;
  }

  /* only one ConnectionBind for a connection ID */
  if(tcp_relay->client_sock != -1)
  {
    return 0;
  }

  /* ConnectionBind response */
  if(!(hdr = turn_msg_connectionbind_response_create(0,
      message->msg->turn_msg_id, &iov[idx])))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    return -1;
  }
  idx++;

  /* connection-id */
  if(!(attr = turn_attr_connection_id_create(
          message->connection_id->turn_attr_id, &iov[idx])))
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    return -1;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          strlen(SOFTWARE_DESCRIPTION), &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
      == -1)
  {
    /* MESSAGE-INTEGRITY option has to be in message, so
     * deallocate ressources and return
     */
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    return -1;
  }

  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
    iovec_free_data(iov, idx);
    return -1;
  }

  /* free message */
  iovec_free_data(iov, idx);

  /* initialized client socket */
  tcp_relay->client_sock = sock;

  /* now on this socket no other TURN messaging is allowed, remove the socket
   * from the TCP remote sockets list
   */
  list_iterate_safe(get, n, &g_tcp_socket_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);

    if(tmp->sock == sock)
    {
      tmp->sock = -1;
      break;
    }
  }

  /* when removed from tcp_socket_list, it will be checked
   * again in tcp_relay list in select() so avoid it
   */
  tcp_relay->new = 1;

  /* stop timer */
  allocation_tcp_relay_set_timer(tcp_relay, 0);

  /* send out buffered data
   * note that it is only used if server
   * has been configured to use userspace
   * TCP internal buffer
   */
  if(tcp_relay->buf_len)
  {
    ssize_t nb_read = 0;
    ssize_t nb_read2 = 0;

    debug(DBG_ATTR, "Send buffered data to client (TURN-TCP)\n");

    /* server has buffered data available,
     * send them to client
     */
    while(tcp_relay->buf_len)
    {
      nb_read = send(tcp_relay->client_sock, tcp_relay->buf + nb_read2,
          tcp_relay->buf_len, 0);

      if(nb_read > 0)
      {
        tcp_relay->buf_len -= nb_read;
        nb_read2 += nb_read;
      }
      else
      {
        tcp_relay->buf_len = 0;
        break;
      }
    }
  }

  /* free memory now as it will not be used anymore */
  if(tcp_relay->buf)
  {
    free(tcp_relay->buf);
    tcp_relay->buf = NULL;
    tcp_relay->buf_size = 0;
  }

  return 0;
}

/**
 * \brief Process a STUN Binding request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message STUN message
 * \param saddr source address
 * \param saddr_size sizeof address
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_binding_request(int transport_protocol, int sock,
    const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct tls_peer* speer)
{
  struct iovec iov[4]; /* header, software, xor-address, fingerprint */
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;

  debug(DBG_ATTR, "Binding request received!\n");

  if(!(hdr = turn_msg_binding_response_create(0, message->msg->turn_msg_id,
          &iov[idx])))
  {
    return -1;
  }
  idx++;

  if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE,
          message->msg->turn_msg_id, &iov[idx])))
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
    return -1;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  /* NOTE: maybe add a configuration flag to enable/disable fingerprint in
   * output message
   */
  /* add a fingerprint */
  if(!(attr = turn_attr_fingerprint_create(0, &iov[idx])))
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, STUN_METHOD_BINDING,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
    return -1;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  /* compute fingerprint */

  /* convert to big endian */
  hdr->turn_msg_len = htons(hdr->turn_msg_len);

  /* do not take into account the attribute itself */
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc =
    htonl(turn_calculate_fingerprint(iov, idx - 1));
  ((struct turn_attr_fingerprint*)attr)->turn_attr_crc ^=
    htonl(STUN_FINGERPRINT_XOR_VALUE);

  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return 0;
}

/**
 * \brief Process a TURN ChannelData.
 * \param transport_protocol transport protocol used
 * \param channel_number channel number
 * \param buf raw data (including ChannelData header)
 * \param buflen length of the data
 * \param saddr source address (TURN client)
 * \param daddr destination address (TURN server)
 * \param saddr_size sizeof address
 * \param allocation_list list of allocations
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_channeldata(int transport_protocol,
    uint16_t channel_number, const char* buf, ssize_t buflen,
    const struct sockaddr* saddr, const struct sockaddr* daddr,
    socklen_t saddr_size, struct list_head* allocation_list)
{
  struct allocation_desc* desc = NULL;
  struct turn_channel_data* channel_data = NULL;
  struct allocation_channel* alloc_channel = NULL;
  size_t len = 0;
  char* msg = NULL;
  ssize_t nb = -1;
  int optval = 0;
  int save_val = 0;
  socklen_t optlen = sizeof(int);
  struct sockaddr_storage storage;
  uint8_t* peer_addr = NULL;
  uint16_t peer_port = 0;

  debug(DBG_ATTR, "ChannelData received!\n");

  channel_data = (struct turn_channel_data*)buf;
  len = ntohs(channel_data->turn_channel_len);

  if(len > (buflen - sizeof(struct turn_channel_data)))
  {
    /* length mismatch */
    debug(DBG_ATTR, "Length too big\n");
    return -1;
  }

  msg = (char*)channel_data->turn_channel_data;

  if(channel_number > 0x7FFF)
  {
    /* channel reserved for future use */
    debug(DBG_ATTR, "Channel number reserved for future use!\n");
    return -1;
  }

  /* with TCP, length MUST a multiple of four */
  if(transport_protocol == IPPROTO_TCP && (buflen % 4))
  {
    debug(DBG_ATTR, "TCP length must be multiple of four!\n");
    return -1;
  }

  desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr,
      saddr, saddr_size);
  if(!desc)
  {
    /* not found */
    debug(DBG_ATTR, "No allocation found\n");
    return -1;
  }

  if(desc->relayed_transport_protocol != IPPROTO_UDP)
  {
    /* ignore for TCP relayed allocation */
    debug(DBG_ATTR,
        "ChannelData does not intend to work with TCP relayed address!");
    return -1;
  }

  alloc_channel = allocation_desc_find_channel_number(desc, channel_number);

  if(!alloc_channel)
  {
    /* no channel bound to this peer */
    debug(DBG_ATTR, "No channel bound to this peer\n");
    return -1;
  }

  if(desc->relayed_addr.ss_family != alloc_channel->family)
  {
    debug(DBG_ATTR, "Could not relayed from a different family\n");
    return -1;
  }

  /* check bandwidth limit */
  if(turnserver_check_bandwidth_limit(desc, 0, len))
  {
    debug(DBG_ATTR, "Bandwidth quotas reached!\n");
    return -1;
  }

  peer_addr = alloc_channel->peer_addr;
  peer_port = alloc_channel->peer_port;

  switch(desc->relayed_addr.ss_family)
  {
    case AF_INET:
      ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
      memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
      ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
      memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
          sizeof((struct sockaddr_in*)&storage)->sin_zero);
      break;
    case AF_INET6:
      ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
      memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
      ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
      ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
      ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
      ((struct sockaddr_in6*)&storage)->sin6_len = sizeof(struct sockaddr_in6);
#endif
      break;
    default:
      return -1;
      break;
  }

  /* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
   * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
   */
  if(desc->relayed_addr.ss_family == AF_INET &&
     (desc->tuple.client_addr.ss_family == AF_INET ||
      (desc->tuple.client_addr.ss_family == AF_INET6 &&
      IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))))
  {
#ifdef OS_SET_DF_SUPPORT
    /* alternate behavior */
    optval = IP_PMTUDISC_DONT;

    if(!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
          &optlen))
    {
      setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
          sizeof(int));
    }
    else
    {
      /* little hack for not setting the old value of *_MTU_DISCOVER after
       * sending message in case getsockopt failed
       */
      optlen = 0;
    }
#else
    /* avoid compilation warning */
    optval = 0;
    optlen = 0;
    save_val = 0;
#endif
  }

  debug(DBG_ATTR, "Send ChannelData to peer\n");
  nb = sendto(desc->relayed_sock, msg, len, 0, (struct sockaddr*)&storage,
      sockaddr_get_size(&desc->relayed_addr));

#ifdef OS_SET_DF_SUPPORT
  /* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
  if(optlen)
  {
    /* restore original value */
    setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
        sizeof(int));
  }
#endif

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  return 0;
}

/**
 * \brief Process a TURN Send indication.
 * \param message TURN message
 * \param desc allocation descriptor
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_send_indication(
    const struct turn_message* message, struct allocation_desc* desc)
{
  const char* msg = NULL;
  size_t msg_len = 0;
  struct allocation_permission* alloc_permission = NULL;
  uint16_t peer_port = 0;
  uint8_t peer_addr[16];
  size_t len = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  ssize_t nb = -1;
  /* for get/setsockopt */
  int optval = 0;
  int save_val = 0;
  socklen_t optlen = sizeof(int);
  char str[INET6_ADDRSTRLEN];
  int family = 0;
  struct sockaddr_storage storage;

  debug(DBG_ATTR, "Send indication received!\n");

  if(!message->peer_addr[0] || !message->data)
  {
    /* no peer address, indication ignored */
    debug(DBG_ATTR, "No peer address\n");
    return -1;
  }

  switch(message->peer_addr[0]->turn_attr_family)
  {
    case STUN_ATTR_FAMILY_IPV4:
      len = 4;
      family = AF_INET;
      break;
    case STUN_ATTR_FAMILY_IPV6:
      len = 16;
      family = AF_INET6;
      break;
    default:
      return -1;
      break;
  }

  if(desc->relayed_addr.ss_family != family)
  {
    debug(DBG_ATTR, "Could not relayed from a different family\n");
    return -1;
  }

  /* copy peer address */
  memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
  peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

  if(turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family, peer_addr,
        &peer_port, p, message->msg->turn_msg_id) == -1)
  {
    return -1;
  }

  /* check if the address is not blacklisted, also check for an IPv6 tunneled
   * address that can lead to a tunnel amplification attack (see section 9.1 of
   * RFC6156)
   */
  if(turnserver_is_address_denied(peer_addr, len, peer_port) ||
      turnserver_is_ipv6_tunneled_address(peer_addr, len))
  {
    inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
    debug(DBG_ATTR, "TurnServer does not permit relaying to %s\n", str);
    return -1;
  }

  /* find a permission */
  alloc_permission = allocation_desc_find_permission(desc,
      desc->relayed_addr.ss_family, peer_addr);

  if(!alloc_permission)
  {
    /* no permission so packet dropped! */
    inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);
    debug(DBG_ATTR, "No permission for this peer (%s)\n", str);
    return -1;
  }

  /* send the message */
  if(message->data)
  {
    msg = (char*)message->data->turn_attr_data;
    msg_len = ntohs(message->data->turn_attr_len);

    /* check bandwidth limit */
    if(turnserver_check_bandwidth_limit(desc, 0, msg_len))
    {
      debug(DBG_ATTR, "Bandwidth quotas reached!\n");
      return -1;
    }

    switch(desc->relayed_addr.ss_family)
    {
      case AF_INET:
        ((struct sockaddr_in*)&storage)->sin_family = AF_INET;
        memcpy(&((struct sockaddr_in*)&storage)->sin_addr, peer_addr, 4);
        ((struct sockaddr_in*)&storage)->sin_port = htons(peer_port);
        memset(&((struct sockaddr_in*)&storage)->sin_zero, 0x00,
            sizeof((struct sockaddr_in*)&storage)->sin_zero);
        break;
      case AF_INET6:
        ((struct sockaddr_in6*)&storage)->sin6_family = AF_INET6;
        memcpy(&((struct sockaddr_in6*)&storage)->sin6_addr, peer_addr, 16);
        ((struct sockaddr_in6*)&storage)->sin6_port = htons(peer_port);
        ((struct sockaddr_in6*)&storage)->sin6_flowinfo = htonl(0);
        ((struct sockaddr_in6*)&storage)->sin6_scope_id = htonl(0);
#ifdef SIN6_LEN
        ((struct sockaddr_in6*)&storage)->sin6_len =
          sizeof(struct sockaddr_in6);
#endif
        break;
      default:
        return -1;
        break;
    }

    /* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
     * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
     */
    if(desc->relayed_addr.ss_family == AF_INET &&
       (desc->tuple.client_addr.ss_family == AF_INET ||
        (desc->tuple.client_addr.ss_family == AF_INET6 &&
        IN6_IS_ADDR_V4MAPPED(
          &((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))))
    {
      /* following is for IPv4-IPv4 relay only */
#ifdef OS_SET_DF_SUPPORT
      if(message->dont_fragment)
      {
        optval = IP_PMTUDISC_DO;
        debug(DBG_ATTR, "Will set DF flag\n");
      }
      else /* IPv4-IPv4 relay but no DONT-FRAGMENT attribute */
      {
        /* alternate behavior, set DF to 0 */
        optval = IP_PMTUDISC_DONT;
        debug(DBG_ATTR, "Will not set DF flag\n");
      }

      if(!getsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
            &optlen))
      {
        setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
            sizeof(int));
      }
      else
      {
        /* little hack for not setting the old value of *_MTU_DISCOVER after
         * sending message in case getsockopt failed
         */
        optlen = 0;
      }
#else
      /* avoid compilation warning */
      optval = 0;
      optlen = 0;
      save_val = 0;

      if(message->dont_fragment)
      {
        /* ignore message */
        debug(DBG_ATTR, "DONT-FRAGMENT attribute present and OS cannot set DF flag, ignore packet!\n");
        return -1;
      }
#endif
    }

    debug(DBG_ATTR, "Send data to peer\n");
    nb = sendto(desc->relayed_sock, msg, msg_len, 0, (struct sockaddr*)&storage,
        sockaddr_get_size(&desc->relayed_addr));

    /* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
#ifdef OS_SET_DF_SUPPORT
    if(optlen)
    {
      /* restore original value */
      setsockopt(desc->relayed_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
          sizeof(int));
    }
#endif

    if(nb == -1)
    {
      debug(DBG_ATTR, "turn_send_message failed\n");
    }
  }

  return 0;
}

/**
 * \brief Process a TURN CreatePermission request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_createpermission_request(int transport_protocol,
    int sock, const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct allocation_desc* desc, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  uint16_t peer_port = 0;
  uint8_t peer_addr[16];
  size_t len = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  size_t i = 0;
  size_t j = 0;
  struct allocation_permission* alloc_permission = NULL;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[4]; /* header, software, integrity, fingerprint */
  size_t idx = 0;
  char str[INET6_ADDRSTRLEN];
  char str2[INET6_ADDRSTRLEN];
  char str3[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  uint16_t port2 = 0;
  int family = 0;

  debug(DBG_ATTR, "CreatePermission request received\n");

  if(message->xor_peer_addr_overflow)
  {
    /* too many XOR-PEER-ADDRESS attributes => error 508 */
    debug(DBG_ATTR, "Too many XOR-PEER-ADDRESS attributes\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 508, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  if(!message->peer_addr[0])
  {
    /* no XOR-PEER-ADDRESS => error 400 */
    debug(DBG_ATTR, "Missing address attribute\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  /* get string representation of addresses for syslog */
  if(desc->relayed_addr.ss_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr,
        str3, INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr,
        str3, INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
  }

  if(saddr->sa_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
  }

  /* check address family for all XOR-PEER-ADDRESS attributes against the
   * relayed ones
   */
  for(i = 0 ; i < XOR_PEER_ADDRESS_MAX && message->peer_addr[i] ; i++)
  {
    switch(message->peer_addr[i]->turn_attr_family)
    {
      case STUN_ATTR_FAMILY_IPV4:
        len = 4;
        family = AF_INET;
        break;
      case STUN_ATTR_FAMILY_IPV6:
        len = 16;
        family = AF_INET6;
        break;
      default:
        return -1;
    }

    if((desc->relayed_addr.ss_family != family))
    {
      /* peer family mismatch => error 443 */
      debug(DBG_ATTR, "Peer family mismatch\n");
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 443, saddr, saddr_size, speer, desc->key);
      return -1;
    }

    /* now check that address is not denied */
    memcpy(peer_addr, message->peer_addr[i]->turn_attr_address, len);
    peer_port = ntohs(message->peer_addr[i]->turn_attr_port);

    if(turn_xor_address_cookie(message->peer_addr[i]->turn_attr_family,
          peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
    {
      return -1;
    }

    inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

    /* if one of the addresses is denied, directly send
     * a CreatePermission error response.
     */
    if(turnserver_is_address_denied(peer_addr, len, peer_port))
    {
      debug(DBG_ATTR,
          "TurnServer does not permit to install permission to %s\n", str);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 403, saddr, saddr_size, speer, desc->key);
      return -1;
    }
  }

  for(j = 0 ; j < XOR_PEER_ADDRESS_MAX && message->peer_addr[j] ; j++)
  {
    /* copy peer address */
    switch(message->peer_addr[j]->turn_attr_family)
    {
      case STUN_ATTR_FAMILY_IPV4:
        len = 4;
        family = AF_INET;
        break;
      case STUN_ATTR_FAMILY_IPV6:
        len = 16;
        family = AF_INET6;
        break;
      default:
        return -1;
    }

    memcpy(peer_addr, message->peer_addr[j]->turn_attr_address, len);
    peer_port = ntohs(message->peer_addr[j]->turn_attr_port);

    if(turn_xor_address_cookie(message->peer_addr[j]->turn_attr_family,
          peer_addr, &peer_port, p, message->msg->turn_msg_id) == -1)
    {
      return -1;
    }

    inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

    syslog(LOG_INFO, "CreatePermission transport=%u (d)tls=%u source=%s:%u "
        "account=%s relayed=%s:%u install_or_refresh=%s", transport_protocol,
        desc->relayed_tls || desc->relayed_dtls, str2, port2, desc->username,
        str3, port, str);

    /* find a permission */
    alloc_permission = allocation_desc_find_permission(desc,
        desc->relayed_addr.ss_family, peer_addr);

    /* update or create allocation permission on that peer */
    if(!alloc_permission)
    {
      debug(DBG_ATTR, "Install permission for %s %u\n", str, peer_port);
      allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME,
          desc->relayed_addr.ss_family, peer_addr);
    }
    else
    {
      debug(DBG_ATTR, "Refresh permission\n");
      allocation_permission_set_timer(alloc_permission,
          TURN_DEFAULT_PERMISSION_LIFETIME);
    }
  }

  /* send a CreatePermission success response */
  if(!(hdr = turn_msg_createpermission_response_create(0,
          message->msg->turn_msg_id, &iov[idx])))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    return -1;
  }
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
      == -1)
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  debug(DBG_ATTR,
      "CreatePermission successful, send success CreatePermission response\n");

  /* finally send the response */

  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return 0;
}

/**
 * \brief Process a TURN ChannelBind request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_channelbind_request(int transport_protocol,
    int sock, const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct allocation_desc* desc, struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  uint16_t channel = 0;
  struct allocation_channel* alloc_channel = NULL;
  struct allocation_permission* alloc_permission = NULL;
  uint8_t family = 0;
  uint16_t peer_port = 0;
  uint8_t peer_addr[16];
  size_t len = 0;
  uint32_t cookie = htonl(STUN_MAGIC_COOKIE);
  uint8_t* p = (uint8_t*)&cookie;
  char str[INET6_ADDRSTRLEN];
  char str2[INET6_ADDRSTRLEN];
  char str3[INET6_ADDRSTRLEN];
  uint16_t port = 0;
  uint16_t port2 = 0;
  uint32_t channel_use = 0; /* if refresh an existing ChannelBind */

  debug(DBG_ATTR, "ChannelBind request received!\n");

  if(!message->channel_number || !message->peer_addr[0])
  {
    /* attributes missing => error 400 */
    debug(DBG_ATTR, "Channel number or peer address attributes missing\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return 0;
  }

  channel = ntohs(message->channel_number->turn_attr_number);

  if(channel < 0x4000 || channel > 0x7FFF)
  {
    /* bad channel => error 400 */
    debug(DBG_ATTR, "Channel number is invalid\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return 0;
  }

  switch(message->peer_addr[0]->turn_attr_family)
  {
    case STUN_ATTR_FAMILY_IPV4:
      len = 4;
      family = AF_INET;
      break;
    case STUN_ATTR_FAMILY_IPV6:
      len = 16;
      family = AF_INET6;
      break;
    default:
      return -1;
      break;
  }

  /* check if the client has allocated a family address that match the peer
   * family address
   */
  if(desc->relayed_addr.ss_family != family)
  {
    debug(DBG_ATTR, "Do not allow requesting a Channel when allocated address "
        "family mismatch peer address family\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 443, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  memcpy(peer_addr, message->peer_addr[0]->turn_attr_address, len);
  peer_port = ntohs(message->peer_addr[0]->turn_attr_port);

  if(turn_xor_address_cookie(message->peer_addr[0]->turn_attr_family, peer_addr,
        &peer_port, p, message->msg->turn_msg_id) == -1)
  {
    return -1;
  }

  inet_ntop(family, peer_addr, str, INET6_ADDRSTRLEN);

  /* check if the address is not blacklisted, also check for an IPv6 tunneled
   * address that can lead to a tunnel amplification attack (see section 9.1 of
   * RFC6156)
   */
  if(turnserver_is_address_denied(peer_addr, len, peer_port) ||
      turnserver_is_ipv6_tunneled_address(peer_addr, len))
  {
    /* permission denied => error 403 */
    debug(DBG_ATTR,
        "TurnServer does not permit to create a ChannelBind to %s\n", str);

    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 403, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  debug(DBG_ATTR, "Client request a ChannelBinding for %s %u\n", str,
      peer_port);

  /* check that the transport address is not currently bound to another
   * channel
   */
  channel_use = allocation_desc_find_channel(desc, family, peer_addr,
      peer_port);
  if(channel_use && channel_use != channel)
  {
    /* transport address already bound to another channel */
    debug(DBG_ATTR, "Transport address already bound to another channel\n");
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
    return 0;
  }

  alloc_channel = allocation_desc_find_channel_number(desc, channel);

  if(alloc_channel)
  {
    /* check if same transport address */
    if(alloc_channel->peer_port != peer_port ||
        memcmp(alloc_channel->peer_addr, peer_addr, len) != 0)
    {
      /* different transport address => error 400 */
      debug(DBG_ATTR, "Channel already bound to another transport address\n");
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 400, saddr, saddr_size, speer, desc->key);
      return 0;
    }

    /* same transport address OK so refresh */
    allocation_channel_set_timer(alloc_channel, TURN_DEFAULT_CHANNEL_LIFETIME);
  }
  else
  {
    /* allocate new channel */
    if(allocation_desc_add_channel(desc, channel, TURN_DEFAULT_CHANNEL_LIFETIME,
          family, peer_addr, peer_port) == -1)
    {
      return -1;
    }
  }

  /* get string representation of addresses for syslog */
  if(desc->relayed_addr.ss_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)&desc->relayed_addr)->sin_addr,
        str3, INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in*)&desc->relayed_addr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)&desc->relayed_addr)->sin6_addr,
        str3, INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in6*)&desc->relayed_addr)->sin6_port);
  }

  if(saddr->sa_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
  }

  syslog(LOG_INFO, "ChannelBind transport=%u (d)tls=%u source=%s:%u account=%s "
      "relayed=%s:%u channel=%s:%u", transport_protocol, desc->relayed_tls ||
      desc->relayed_dtls, str2, port2, desc->username, str3, port, str,
      peer_port);

  /* find a permission */
  alloc_permission = allocation_desc_find_permission(desc, family, peer_addr);

  /* update or create allocation permission on that peer */
  if(!alloc_permission)
  {
    allocation_desc_add_permission(desc, TURN_DEFAULT_PERMISSION_LIFETIME,
        family, peer_addr);
  }
  else
  {
    allocation_permission_set_timer(alloc_permission,
        TURN_DEFAULT_PERMISSION_LIFETIME);
  }

  /* finally send the response */
  if(!(hdr = turn_msg_channelbind_response_create(0, message->msg->turn_msg_id,
          &iov[idx])))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    return -1;
  }
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
      == -1)
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
    return -1;
  }

  debug(DBG_ATTR,
      "ChannelBind successful, send success ChannelBind response\n");

  /* finally send the response */
  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return 0;
}

/**
 * \brief Process a TURN Refresh request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param desc allocation descriptor
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_refresh_request(int transport_protocol, int sock,
    const struct turn_message* message, const struct sockaddr* saddr,
    socklen_t saddr_size, struct list_head* allocation_list,
    struct allocation_desc* desc, struct account_desc* account,
    struct tls_peer* speer)
{
  uint16_t hdr_msg_type = htons(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  uint32_t lifetime = 0;
  struct iovec iov[5]; /* header, lifetime, software, integrity, fingerprint */
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  uint8_t key[16];
  char str[INET6_ADDRSTRLEN];
  uint16_t port = 0;

  debug(DBG_ATTR, "Refresh request received!\n");

  /* save key from allocation as it could be freed if lifetime equals 0 */
  memcpy(key, desc->key, sizeof(desc->key));

  /* RFC6156: at this stage server knows the 5-tuple and the allocation
   * associated.
   * No matter to know if the relayed address has a different address family
   * than 5-tuple, so no need to have REQUESTED-ADDRESS-FAMILY attribute in
   * Refresh request.
   */

  /* if REQUESTED-ADDRESS-FAMILY attribute is present and do not match relayed
   * address ones => error 443
   */
  if(message->requested_addr_family)
  {
    int family = 0;

    switch(message->requested_addr_family->turn_attr_family)
    {
      case STUN_ATTR_FAMILY_IPV4:
        family = AF_INET;
        break;
      case STUN_ATTR_FAMILY_IPV6:
        family = AF_INET6;
        break;
      default:
        return -1;
    }

    if(desc->relayed_addr.ss_family != family)
    {
      /* peer family mismatch => error 443 */
      debug(DBG_ATTR, "Peer family mismatch\n");
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 443, saddr, saddr_size, speer, key);
      return -1;
    }
  }

  if(message->lifetime)
  {
    lifetime = htonl(message->lifetime->turn_attr_lifetime);

    debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

    /* adjust lifetime (cannot be greater that maximum allowed) */
    lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

    if(lifetime > 0)
    {
      /* lifetime cannot be smaller than default */
      lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
    }
  }
  else
  {
    /* cannot override default max value for allocation time */
    lifetime = MIN(turnserver_cfg_allocation_lifetime(),
        TURN_DEFAULT_ALLOCATION_LIFETIME);
  }

  if(saddr->sa_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str,
        INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str,
        INET6_ADDRSTRLEN);
    port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
  }

  syslog(LOG_INFO, "Refresh transport=%u (d)tls=%u source=%s:%u account=%s",
      transport_protocol, desc->relayed_tls || desc->relayed_dtls, str, port,
      desc->username);

  if(lifetime > 0)
  {
    /* adjust lifetime */
    debug(DBG_ATTR, "Refresh allocation\n");
    allocation_desc_set_timer(desc, lifetime);
  }
  else
  {
    /* lifetime = 0 delete the allocation */
    /* protect the removing of the expired list if any */
    turnserver_block_realtime_signal();
    allocation_desc_set_timer(desc, 0); /* stop timeout */
    /* in case the allocation has expired during this statement */
    LIST_DEL(&desc->list2);
    turnserver_unblock_realtime_signal();

    allocation_list_remove(allocation_list, desc);

    /* decrement allocations for the account */
    account->allocations--;
    debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username,
        account->allocations);
    debug(DBG_ATTR, "Explicit delete of allocation\n");
    if(account->allocations == 0 && account->is_tmp)
    {
      account_list_remove(NULL, account);
    }
  }

  if(!(hdr = turn_msg_refresh_response_create(0, message->msg->turn_msg_id,
          &iov[idx])))
  {
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
    return -1;
  }
  idx++;

  if(!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
    return -1;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(turn_add_message_integrity(iov, &idx, key, sizeof(key), 1) == -1)
  {
    iovec_free_data(iov, idx);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, key);
    return -1;
  }

  debug(DBG_ATTR, "Refresh successful, send success refresh response\n");

  /* finally send the response */
  if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return 0;
}

/**
 * \brief Process a TURN Allocate request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_allocate_request(int transport_protocol, int sock,
    const struct turn_message* message, const struct sockaddr* saddr,
    const struct sockaddr* daddr, socklen_t saddr_size,
    struct list_head* allocation_list, struct account_desc* account,
    struct tls_peer* speer)
{
  struct allocation_desc* desc = NULL;
  struct itimerspec t; /* time before expire */
  uint16_t hdr_msg_type = ntohs(message->msg->turn_msg_type);
  uint16_t method = STUN_GET_METHOD(hdr_msg_type);
  struct sockaddr_storage relayed_addr;
  int r_flag = 0;
  uint32_t lifetime = 0;
  uint16_t port = 0;
  uint16_t reservation_port = 0;
  int relayed_sock = -1;
  int relayed_sock_tcp = -1; /* RFC6062 (TURN-TCP) */
  int reservation_sock = -1;
  socklen_t relayed_size = sizeof(struct sockaddr_storage);
  size_t quit_loop = 0;
  uint8_t reservation_token[8];
  char str[INET6_ADDRSTRLEN];
  char str2[INET6_ADDRSTRLEN];
  uint16_t port2 = 0;
  int has_token = 0;
  char* family_address = NULL;
  const uint16_t max_port = turnserver_cfg_max_port();
  const uint16_t min_port = turnserver_cfg_min_port();

  debug(DBG_ATTR, "Allocate request received!\n");

  /* check if it was a valid allocation */
  desc = allocation_list_find_tuple(allocation_list, transport_protocol, daddr,
      saddr, saddr_size);

  if(desc)
  {
    if(transport_protocol == IPPROTO_UDP && !memcmp(message->msg->turn_msg_id,
          desc->transaction_id, 12))
    {
      /* the request is a retransmission of a valid request, rebuild the
       * response
       */

      /* get some states */
      timer_gettime(desc->expire_timer, &t);
      lifetime = t.it_value.tv_sec;
      memcpy(&relayed_addr, &desc->relayed_addr,
          sizeof(struct sockaddr_storage));

      /* goto is bad... */
      goto send_success_response;
    }
    else
    {
      /* allocation mismatch => error 437 */
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 437, saddr, saddr_size, speer, desc->key);
    }

    return 0;
  }

  /* get string representation of address for syslog */
  if(saddr->sa_family == AF_INET)
  {
    inet_ntop(AF_INET, &((struct sockaddr_in*)saddr)->sin_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in*)saddr)->sin_port);
  }
  else /* IPv6 */
  {
    inet_ntop(AF_INET6, &((struct sockaddr_in6*)saddr)->sin6_addr, str2,
        INET6_ADDRSTRLEN);
    port2 = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);

    /* Do not accept allocation request from IPv6 tunneled address,
     * see section 9.1 of RC6156
     */
    if(turnserver_is_ipv6_tunneled_address(
          ((struct sockaddr_in6*)saddr)->sin6_addr.s6_addr, 16))
    {
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 403, saddr, saddr_size, speer,
          account->key);
    }
  }

  /* check for allocation quota */
  if(account->allocations >= turnserver_cfg_max_relay_per_username())
  {
    /* quota exceeded => error 486 */
    syslog(LOG_WARNING, "Allocation transport=%u (d)tls=%u source=%s:%u account=%s"
        " quota exceeded", transport_protocol, speer ? 1 : 0, str2, port2,
        account->username);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 486, saddr, saddr_size, speer, account->key);
    return -1;
  }

  /* check requested-transport */
  if(!message->requested_transport)
  {
    /* bad request => error 400 */
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
    return 0;
  }

  /* check if DONT-FRAGMENT attribute is supported */
#ifndef OS_SET_DF_SUPPORT
  if(message->dont_fragment)
  {
    /* header, error-code, unknown-attributes, software, message-integrity,
     * fingerprint
     */
    struct iovec iov[6];
    uint16_t unknown[2];
    struct turn_msg_hdr* error = NULL;
    struct turn_attr_hdr* attr = NULL;
    size_t idx = 0;

    /* send error 420 */
    unknown[0] = TURN_ATTR_DONT_FRAGMENT;

    if(!(error = turn_error_response_420(method, message->msg->turn_msg_id,
            unknown, 1, iov, &idx)))
    {
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
          account->key);
      return -1;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
            sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
    {
      error->turn_msg_len += iov[idx].iov_len;
      idx++;
    }

    if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
        == -1)
    {
      iovec_free_data(iov, idx);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
          account->key);
      return -1;
    }

    if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
          ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
        == -1)
    {
      debug(DBG_ATTR, "turn_send_message failed\n");
    }

    /* free sent data */
    iovec_free_data(iov, idx);
    return 0;
  }
#endif

  /* check if server supports requested transport */
  if(message->requested_transport->turn_attr_protocol != IPPROTO_UDP &&
     (message->requested_transport->turn_attr_protocol != IPPROTO_TCP ||
      !turnserver_cfg_turn_tcp()))
  {
    /* unsupported transport protocol => error 442 */
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 442, saddr, saddr_size, speer, account->key);
    return 0;
  }

  if(message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
  {
    /* RFC6062 (TURN-TCP):
     * - do not permit to allocate TCP relay with an
     * UDP-based connection
     * - requests do not contains DONT-FRAGMENT,
     * RESERVATION-TOKEN or EVEN-PORT.
     * => error 400
     */
    if(transport_protocol == IPPROTO_UDP || message->dont_fragment ||
        message->reservation_token || message->even_port)
    {
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
          account->key);
      return 0;
    }
  }

  if(message->even_port && message->reservation_token)
  {
    /* cannot have both EVEN-PORT and RESERVATION-TOKEN => error 400 */
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
    return 0;
  }

  if(message->requested_addr_family && message->reservation_token)
  {
    /* RFC6156: cannot have both REQUESTED-ADDRESS-FAMILY and RESERVATION-TOKEN
     * => error 400
     */
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 400, saddr, saddr_size, speer, account->key);
    return 0;
  }

  /* check reservation-token */
  if(message->reservation_token)
  {
    struct allocation_token* token = NULL;

    /* check if the requested reservation-token exists */
    if((token = allocation_token_list_find(&g_token_list,
            message->reservation_token->turn_attr_token)))
    {
      relayed_sock = token->sock;
      has_token = 1;

      /* suppress from the list */
      turnserver_block_realtime_signal();
      allocation_token_set_timer(token, 0); /* stop timer */
      LIST_DEL(&token->list2);
      turnserver_unblock_realtime_signal();

      allocation_token_list_remove(&g_token_list, token);
      debug(DBG_ATTR, "Take token reserved address!\n");
    }
    else
    {
      /* token does not exists so token not valid => error 508 */
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 508, saddr, saddr_size, speer,
          account->key);
      return 0;
    }
  }

  if(message->even_port)
  {
    r_flag = message->even_port->turn_attr_flags & 0x80;

    /* check if there are unknown other flags */
    if(message->even_port->turn_attr_flags & (~g_supported_even_port_flags))
    {
      /* unsupported flags => error 508 */
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 508, saddr, saddr_size, speer,
          account->key);
      return 0;
    }
  }

  if(message->lifetime)
  {
    lifetime = htonl(message->lifetime->turn_attr_lifetime);

    debug(DBG_ATTR, "lifetime: %u seconds\n", lifetime);

    /* adjust lifetime (cannot be greater than maximum allowed) */
    lifetime = MIN(lifetime, TURN_MAX_ALLOCATION_LIFETIME);

    /* lifetime cannot be smaller than default */
    lifetime = MAX(lifetime, TURN_DEFAULT_ALLOCATION_LIFETIME);
  }
  else
  {
    /* cannot override default max value for allocation time */
    lifetime = MIN(turnserver_cfg_allocation_lifetime(),
        TURN_MAX_ALLOCATION_LIFETIME);
  }

  /* RFC6156 */
  if(message->requested_addr_family)
  {
    switch(message->requested_addr_family->turn_attr_family)
    {
      case STUN_ATTR_FAMILY_IPV4:
        family_address = turnserver_cfg_listen_address();
        break;
      case STUN_ATTR_FAMILY_IPV6:
        family_address = turnserver_cfg_listen_addressv6();
        break;
      default:
        family_address = NULL;
        break;
    }

    /* check the family requested is supported */
    if(!family_address)
    {
      /* family not supported */
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 440, saddr, saddr_size, speer,
          account->key);
      return -1;
    }
  }
  else
  {
    /* REQUESTED-ADDRESS-FAMILY absent so allocate an IPv4 address */
    family_address = turnserver_cfg_listen_address();

    if(!family_address)
    {
      /* only happen when IPv4 relaying is disabled and try to allocate IPv6
       * address without adding REQUESTED-ADDRESS-FAMILY attribute.
       */
      /* family not supported */
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 440, saddr, saddr_size, speer,
          account->key);
      return -1;
    }
  }

  strncpy(str, family_address, INET6_ADDRSTRLEN);
  str[INET6_ADDRSTRLEN - 1] = 0x00;

  /* after all these checks, allocate an allocation! */

  /* allocate the relayed address or skip this if server has a token,
   * try 5 times to find a free port or couple of free ports.
   */
  while(!has_token && (relayed_sock == -1 && quit_loop < 5))
  {
    /* pick up a port (default between 49152 - 65535) */
    port = (uint16_t) (rand() % (max_port - min_port)) + min_port;

    /* allocate a even port */
    if(message->even_port && (port % 2))
    {
      port++;
    }

    /* TCP or UDP */
    /* in case of TCP, allow socket to reuse transport address since we create
     * another socket that will be bound to the same address
     */
    relayed_sock = socket_create(
        message->requested_transport->turn_attr_protocol, str, port,
        message->requested_transport->turn_attr_protocol == IPPROTO_TCP,
        message->requested_transport->turn_attr_protocol == IPPROTO_TCP);

    if(relayed_sock == -1)
    {
      quit_loop++;
      continue;
    }

    if(message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
    {
      /* special handling for TCP relay:
       * create a second socket bind on the same address/port,
       * the first one will be used to listen incoming connections,
       * the second will be used to connect peer (Connect request)
       */
      relayed_sock_tcp = socket_create(
          message->requested_transport->turn_attr_protocol, str, port, 1, 1);

      if(relayed_sock_tcp == -1)
      {
        /* system error */
        char error_str[256];
        get_error(errno, error_str, sizeof(error_str));
        syslog(LOG_ERR, "Unable to allocate TCP relay socket: %s", error_str);
        close(relayed_sock);
        turnserver_send_error(transport_protocol, sock, method,
            message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
            account->key);
        return -1;
      }

      if(listen(relayed_sock, 5) == -1)
      {
        /* system error */
        char error_str[256];
        get_error(errno, error_str, sizeof(error_str));
        syslog(LOG_ERR, "Unable to listen on relayed socket: %s", error_str);
        close(relayed_sock);
        close(relayed_sock_tcp);
        turnserver_send_error(transport_protocol, sock, method,
            message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
            account->key);
        return -1;
      }
    }

    if(r_flag)
    {
      reservation_port = port + 1;
      reservation_sock = socket_create(IPPROTO_UDP, str, reservation_port, 0,
          0);

      if(reservation_sock == -1)
      {
        close(relayed_sock);
        relayed_sock = -1;
      }
      else
      {
        struct allocation_token* token = NULL;

        /* store the reservation */
        random_bytes_generate(reservation_token, 8);

        token = allocation_token_new(reservation_token, reservation_sock,
            TURN_DEFAULT_TOKEN_LIFETIME);
        if(token)
        {
          allocation_token_list_add(&g_token_list, token);
        }
        else
        {
          close(reservation_sock);
          close(relayed_sock);
          reservation_sock = -1;
          relayed_sock = -1;
        }
      }
    }

    quit_loop++;
  }

  if(relayed_sock == -1)
  {
    char error_str[256];
    get_error(errno, error_str, sizeof(error_str));
    syslog(LOG_ERR, "Unable to allocate socket: %s", error_str);
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    return -1;
  }

  if(getsockname(relayed_sock, (struct sockaddr*)&relayed_addr, &relayed_size)
      != 0)
  {
    char error_str[256];
    get_error(errno, error_str, sizeof(error_str));
    syslog(LOG_ERR, "Error in getsockname: %s", error_str);
    close(relayed_sock);
    return -1;
  }

  if(relayed_addr.ss_family == AF_INET)
  {
    port = ntohs(((struct sockaddr_in*)&relayed_addr)->sin_port);
  }
  else /* IPv6 */
  {
    port = ntohs(((struct sockaddr_in6*)&relayed_addr)->sin6_port);
  }

  desc = allocation_desc_new(message->msg->turn_msg_id, transport_protocol,
      account->username, account->key, account->realm,
      message->nonce->turn_attr_nonce, (struct sockaddr*)&relayed_addr, daddr,
      saddr, sizeof(struct sockaddr_storage), lifetime);

  if(!desc)
  {
    /* send error response with code 500 */
    turnserver_send_error(transport_protocol, sock, method,
        message->msg->turn_msg_id, 500, saddr, saddr_size, speer, account->key);
    close(relayed_sock);
    return -1;
  }

  /* init token bucket */
  if(account->state == AUTHORIZED)
  {
    /* store it in bytes */
    desc->bucket_capacity = turnserver_cfg_bandwidth_per_allocation() * 1000;
  }
  else
  {
    /* store it in bytes */
    desc->bucket_capacity = turnserver_cfg_restricted_bandwidth() * 1000;
  }

  desc->bucket_tokenup = desc->bucket_capacity;
  desc->bucket_tokendown = desc->bucket_capacity;

  desc->relayed_transport_protocol =
    message->requested_transport->turn_attr_protocol;

  /* increment number of allocations */
  account->allocations++;
  debug(DBG_ATTR, "Account %s, allocations used: %u\n", account->username,
      account->allocations);
  syslog(LOG_INFO, "Account %s, allocations used: %zu", account->username,
      account->allocations);

  if(speer)
  {
    if(desc->tuple.transport_protocol == IPPROTO_TCP)
    {
      desc->relayed_tls = 1;
    }
    else /* UDP */
    {
      desc->relayed_dtls = 1;
    }
  }

  syslog(LOG_INFO, "Allocation transport=%u (d)tls=%u source=%s:%u account=%s "
      "relayed=%s:%u", transport_protocol, desc->relayed_tls ||
      desc->relayed_dtls, str2, port2, account->username, str, port);

  /* assign the sockets to the allocation */
  desc->relayed_sock = relayed_sock;

  if(message->requested_transport->turn_attr_protocol == IPPROTO_TCP)
  {
    desc->relayed_sock_tcp = relayed_sock_tcp;
  }

  desc->tuple_sock = sock;

  /* add to the list */
  allocation_list_add(allocation_list, desc);

  /* send back the success response */
send_success_response:
  {
    /* header, relayed-address, lifetime, reservation-token (if any),
     * xor-mapped-address, username, software, message-integrity, fingerprint
     */
    struct iovec iov[12];
    struct turn_msg_hdr* hdr = NULL;
    struct turn_attr_hdr* attr = NULL;
    size_t idx = 0;

    if(!(hdr = turn_msg_allocate_response_create(0, message->msg->turn_msg_id,
            &iov[idx])))
    {
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
      return -1;
    }
    idx++;

    /* required attributes */
    if(!(attr = turn_attr_xor_relayed_address_create(
            (struct sockaddr*)&relayed_addr, STUN_MAGIC_COOKIE,
            message->msg->turn_msg_id, &iov[idx])))
    {
      iovec_free_data(iov, idx);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(!(attr = turn_attr_lifetime_create(lifetime, &iov[idx])))
    {
      iovec_free_data(iov, idx);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500,saddr, saddr_size, speer, desc->key);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    switch(saddr->sa_family)
    {
      case AF_INET:
        port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
        break;
      case AF_INET6:
        port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
        break;
      default:
        iovec_free_data(iov, idx);
        return -1;
        break;
    }

    if(!(attr = turn_attr_xor_mapped_address_create(saddr, STUN_MAGIC_COOKIE,
            message->msg->turn_msg_id, &iov[idx])))
    {
      iovec_free_data(iov, idx);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(reservation_port)
    {
      /* server has stored a socket/port */
      debug(DBG_ATTR, "Send a reservation-token attribute\n");
      if(!(attr = turn_attr_reservation_token_create(reservation_token,
              &iov[idx])))
      {
        iovec_free_data(iov, idx);
        turnserver_send_error(transport_protocol, sock, method,
            message->msg->turn_msg_id, 500, saddr, saddr_size, speer,
            desc->key);
        return -1;
      }
      hdr->turn_msg_len += iov[idx].iov_len;
      idx++;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
            sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
    {
      hdr->turn_msg_len += iov[idx].iov_len;
      idx++;
    }

    if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
        == -1)
    {
      iovec_free_data(iov, idx);
      turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 500, saddr, saddr_size, speer, desc->key);
      return -1;
    }

    debug(DBG_ATTR, "Allocation successful, send success allocate response\n");

    if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
          ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
        == -1)
    {
      debug(DBG_ATTR, "turn_send_message failed\n");
    }

    iovec_free_data(iov, idx);
  }

  return 0;
}

/**
 * \brief Process a TURN request.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param message TURN message
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account account descriptor (may be NULL)
 * \param speer TLS peer, if not NULL the connection is in TLS so response is
 * also in TLS
 * \return 0 if success, -1 otherwise
 */
static int turnserver_process_turn(int transport_protocol, int sock,
    const struct turn_message* message, const struct sockaddr* saddr,
    const struct sockaddr* daddr, socklen_t saddr_size,
    struct list_head* allocation_list, struct account_desc* account,
    struct tls_peer* speer)
{
  uint16_t hdr_msg_type = 0;
  uint16_t method = 0;
  struct allocation_desc* desc = NULL;

  debug(DBG_ATTR, "Process a TURN message\n");

  hdr_msg_type = ntohs(message->msg->turn_msg_type);
  method = STUN_GET_METHOD(hdr_msg_type);

  /* process STUN binding request */
  if(STUN_IS_REQUEST(hdr_msg_type) && method == STUN_METHOD_BINDING)
  {
    return turnserver_process_binding_request(transport_protocol, sock, message,
        saddr, saddr_size, speer);
  }

  /* RFC6062 (TURN-TCP) */
  /* find right tuple for a TCP allocation (ConnectionBind case) */
  if(STUN_IS_REQUEST(hdr_msg_type) && method == TURN_METHOD_CONNECTIONBIND)
  {
    /* ConnectionBind is only for TCP or TLS over TCP <-> TCP */
    if(transport_protocol == IPPROTO_TCP)
    {
      return turnserver_process_connectionbind_request(transport_protocol, sock,
          message, saddr, saddr_size, speer, account, allocation_list);
    }
    else
    {
      return turnserver_send_error(transport_protocol, sock, method,
          message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
          account->key);
    }
  }

  /* check the 5-tuple except for an Allocate request */
  if(method != TURN_METHOD_ALLOCATE)
  {
    desc = allocation_list_find_tuple(allocation_list, transport_protocol,
        daddr, saddr, saddr_size);

    if(STUN_IS_REQUEST(hdr_msg_type))
    {
      /* check for the allocated username */
      if(desc && message->username && message->realm)
      {
        size_t len = ntohs(message->username->turn_attr_len);
        size_t rlen = ntohs(message->realm->turn_attr_len);
        if(len != strlen(desc->username) ||
           strncmp((char*)message->username->turn_attr_username,
             desc->username, len) ||
           rlen != strlen(desc->realm) ||
           strncmp((char*)message->realm->turn_attr_realm, desc->realm, rlen))
        {
          desc = NULL;
        }
      }
      else
      {
        desc = NULL;
      }
    }

    if(!desc)
    {
      /* reject with error 437 if it a request, ignored otherwise */
      /* the refresh function will handle this case */
      if(STUN_IS_REQUEST(hdr_msg_type))
      {
        /* allocation mismatch => error 437 */
        turnserver_send_error(transport_protocol, sock, method,
            message->msg->turn_msg_id, 437, saddr, saddr_size, speer,
            account->key);
        return 0;
      }

      debug(DBG_ATTR, "No valid 5-tuple match\n");
      return -1;
    }

    /* update allocation nonce */
    if(message->nonce)
    {
      memcpy(desc->nonce, message->nonce->turn_attr_nonce, 24);
    }
  }

  if(STUN_IS_REQUEST(hdr_msg_type))
  {
    if(method != TURN_METHOD_ALLOCATE)
    {
      /* check to prevent hijacking the client's allocation */
      size_t len = strlen(account->username);
      size_t rlen = strlen(account->realm);
      if(len != ntohs(message->username->turn_attr_len) ||
         strncmp((char*)message->username->turn_attr_username,
           account->username, len) ||
         rlen != ntohs(message->realm->turn_attr_len) ||
         strncmp((char*)message->realm->turn_attr_realm, account->realm, rlen))
      {
        /* credentials do not match with those used for allocation
         * => error 441
         */
        debug(DBG_ATTR, "Wrong credentials!\n");
        turnserver_send_error(transport_protocol, sock, method,
            message->msg->turn_msg_id, 441, saddr, saddr_size, speer,
            account->key);
        return 0;
      }
    }

    switch(method)
    {
      case TURN_METHOD_ALLOCATE:
        turnserver_process_allocate_request(transport_protocol, sock, message,
            saddr, daddr, saddr_size, allocation_list, account, speer);
        break;
      case TURN_METHOD_REFRESH:
        turnserver_process_refresh_request(transport_protocol, sock, message,
            saddr, saddr_size, allocation_list, desc, account, speer);
        break;
      case TURN_METHOD_CREATEPERMISSION:
        turnserver_process_createpermission_request(transport_protocol, sock,
            message, saddr, saddr_size, desc, speer);
        break;
      case TURN_METHOD_CHANNELBIND:
        /* ChannelBind is only for UDP relay */
        if(desc->relayed_transport_protocol == IPPROTO_UDP)
        {
          turnserver_process_channelbind_request(transport_protocol, sock,
              message, saddr, saddr_size, desc, speer);
        }
        else
        {
          turnserver_send_error(transport_protocol, sock, method,
              message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
              desc->key);
        }
        break;
      case TURN_METHOD_CONNECT: /* RFC6062 (TURN-TCP) */
        /* Connect is only for TCP or TLS over TCP <-> TCP */
        if(transport_protocol == IPPROTO_TCP &&
            desc->relayed_transport_protocol == IPPROTO_TCP)
        {
          turnserver_process_connect_request(transport_protocol, sock, message,
              saddr, saddr_size, desc, speer);
        }
        else
        {
          turnserver_send_error(transport_protocol, sock, method,
              message->msg->turn_msg_id, 400, saddr, saddr_size, speer,
              desc->key);
        }
        break;
      default:
        return -1;
        break;
    }
  }
  else if(STUN_IS_SUCCESS_RESP(hdr_msg_type) ||
      STUN_IS_ERROR_RESP(hdr_msg_type))
  {
    /* should not happen */
  }
  else if(STUN_IS_INDICATION(hdr_msg_type))
  {
    switch(method)
    {
      case TURN_METHOD_SEND:
        if(desc->relayed_transport_protocol == IPPROTO_UDP)
        {
          turnserver_process_send_indication(message, desc);
        }
        break;
      case TURN_METHOD_DATA:
        /* should not happen */
        return -1;
        break;
    }
  }

  return 0;
}

/**
 * \brief Receive and check basic validation of the message.
 * \param transport_protocol transport protocol used
 * \param sock socket
 * \param buf data received
 * \param buflen length of data
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account_list list of accounts
 * \param speer TLS peer if not NULL, the server accept TLS connection
 * \return 0 if message processed correctly, -1 otherwise
 */
static int turnserver_listen_recv(int transport_protocol, int sock,
    const char* buf, ssize_t buflen, const struct sockaddr* saddr,
    const struct sockaddr* daddr, socklen_t saddr_size,
    struct list_head* allocation_list, struct list_head* account_list,
    struct tls_peer* speer)
{
  struct turn_message message;
  uint16_t unknown[32];
  size_t unknown_size = sizeof(unknown) / sizeof(uint32_t);
  struct account_desc* account = NULL;
  uint16_t method = 0;
  uint16_t hdr_msg_type = 0;
  size_t total_len = 0;
  uint16_t type = 0;
  int turn_tcp = turnserver_cfg_turn_tcp();

  /* protocol mismatch */
  if(transport_protocol != IPPROTO_UDP && transport_protocol != IPPROTO_TCP)
  {
    debug(DBG_ATTR, "Transport protocol mismatch\n");
    return -1;
  }

  if(buflen < 4)
  {
    debug(DBG_ATTR, "Size too short\n");
    return -1;
  }

  memcpy(&type, buf, sizeof(uint16_t));
  type = ntohs(type);

  /* is it a ChannelData message (bit 0 and 1 are not set to 0) ? */
  if(TURN_IS_CHANNELDATA(type))
  {
    /* ChannelData */
    return turnserver_process_channeldata(transport_protocol, type, buf, buflen,
        saddr, daddr, saddr_size, allocation_list);
  }

  /* first parsing */
  if(turn_parse_message(buf, buflen, &message, unknown, &unknown_size) == -1)
  {
    debug(DBG_ATTR, "Parse message failed\n");
    return -1;
  }

  /* check if it is a STUN/TURN header */
  if(!message.msg)
  {
    debug(DBG_ATTR, "No STUN/TURN header\n");
    return -1;
  }

  /* convert into host byte order */
  hdr_msg_type = ntohs(message.msg->turn_msg_type);
  total_len = ntohs(message.msg->turn_msg_len) + sizeof(struct turn_msg_hdr);

  /* check that the two first bit of the STUN header are set to 0 */
  /*
     if((hdr_msg_type & 0xC000) != 0)
     {
     debug(DBG_ATTR, "Not a STUN-formated packet\n");
     return -1;
     }
   */

  /* check if it is a known class */
  if(!STUN_IS_REQUEST(hdr_msg_type) &&
     !STUN_IS_INDICATION(hdr_msg_type) &&
     !STUN_IS_SUCCESS_RESP(hdr_msg_type) &&
     !STUN_IS_ERROR_RESP(hdr_msg_type))
  {
    debug(DBG_ATTR, "Unknown message class\n");
    return -1;
  }

  method = STUN_GET_METHOD(hdr_msg_type);

  /* check that the method value is supported */
  if(method != STUN_METHOD_BINDING &&
     method != TURN_METHOD_ALLOCATE &&
     method != TURN_METHOD_REFRESH &&
     method != TURN_METHOD_CREATEPERMISSION &&
     method != TURN_METHOD_CHANNELBIND &&
     method != TURN_METHOD_SEND &&
     method != TURN_METHOD_DATA &&
     (method != TURN_METHOD_CONNECT || !turn_tcp) &&
     (method != TURN_METHOD_CONNECTIONBIND || !turn_tcp))
  {
    debug(DBG_ATTR, "Unknown method\n");
    return -1;
  }

  /* check the magic cookie */
  if(message.msg->turn_msg_cookie != htonl(STUN_MAGIC_COOKIE))
  {
    debug(DBG_ATTR, "Bad magic cookie\n");
    return -1;
  }

  /* check the fingerprint if present */
  if(message.fingerprint)
  {
    /* verify if CRC is valid */
    uint32_t crc = 0;

    crc = crc32_generate((const unsigned char*)buf,
        total_len - sizeof(struct turn_attr_fingerprint), 0);

    if(htonl(crc) != (message.fingerprint->turn_attr_crc ^ htonl(
            STUN_FINGERPRINT_XOR_VALUE)))
    {
      debug(DBG_ATTR, "Fingerprint mismatch\n");
      return -1;
    }
  }

  /* all this cases above discard silently the packets,
   * so now process the packet more in details
   */

  if(STUN_IS_REQUEST(hdr_msg_type) && method != STUN_METHOD_BINDING)
  {
    /* check long-term authentication for all requests except for a STUN
     * binding request
     */
    if(!message.message_integrity)
    {
      /* no messages integrity => error 401 */
      /* header, error-code, realm, nonce, software */
      struct iovec iov[12];
      uint8_t nonce[48];
      struct turn_msg_hdr* error = NULL;
      struct turn_attr_hdr* attr = NULL;
      char* key = NULL;
      size_t idx = 0;

      debug(DBG_ATTR, "No message integrity\n");

      key = turnserver_cfg_nonce_key();
      turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key,
          strlen(key));

      if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
              turnserver_cfg_realm(), nonce, sizeof(nonce), iov, &idx)))
      {
        turnserver_send_error(transport_protocol, sock, method,
            message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
        return -1;
      }

      /* software (not fatal if it cannot be allocated) */
      if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
              sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
      {
        error->turn_msg_len += iov[idx].iov_len;
        idx++;
      }

      turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

      /* convert to big endian */
      error->turn_msg_len = htons(error->turn_msg_len);

      if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
            ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
            idx) == -1)
      {
        debug(DBG_ATTR, "turn_send_message failed\n");
      }

      /* free sent data */
      iovec_free_data(iov, idx);
      return 0;
    }

    if(!message.username || !message.realm || !message.nonce)
    {
      /* missing username, realm or nonce => error 400 */
      turnserver_send_error(transport_protocol, sock, method,
          message.msg->turn_msg_id, 400, saddr, saddr_size, speer, NULL);
      return 0;
    }

    if(turn_nonce_is_stale(message.nonce->turn_attr_nonce,
          ntohs(message.nonce->turn_attr_len),
          (unsigned char*)turnserver_cfg_nonce_key(),
          strlen(turnserver_cfg_nonce_key())))
    {
      /* nonce staled => error 438 */
      /* header, error-code, realm, nonce, software */
      struct iovec iov[5];
      size_t idx = 0;
      struct turn_msg_hdr* error = NULL;
      struct turn_attr_hdr* attr = NULL;
      uint8_t nonce[48];
      char* realm = turnserver_cfg_realm();
      char* key = turnserver_cfg_nonce_key();

      turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key,
          strlen(key));
      idx = 0;

      if(!(error = turn_error_response_438(method, message.msg->turn_msg_id,
              realm, nonce, sizeof(nonce), iov, &idx)))
      {
        turnserver_send_error(transport_protocol, sock, method,
            message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
        return -1;
      }

      /* software (not fatal if it cannot be allocated) */
      if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
              sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
      {
        error->turn_msg_len += iov[idx].iov_len;
        idx++;
      }

      /* convert to big endian */
      error->turn_msg_len = htons(error->turn_msg_len);

      if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
            ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
            idx) == -1)
      {
        debug(DBG_ATTR, "turn_send_message failed\n");
      }

      /* free sent data */
      iovec_free_data(iov, idx);
      return 0;
    }

    /* find the desired username and password in the account list */
    {
      char username[514];
      char user_realm[256];
      size_t username_len = ntohs(message.username->turn_attr_len) + 1;
      size_t realm_len = ntohs(message.realm->turn_attr_len) + 1;

      if(username_len > 513 || realm_len > 256)
      {
        /* some attributes are too long */
        turnserver_send_error(transport_protocol, sock, method,
            message.msg->turn_msg_id, 400, saddr, saddr_size, speer, NULL);
        return -1;
      }

      strncpy(username, (char*)message.username->turn_attr_username,
          username_len);
      username[username_len - 1] = 0x00;
      strncpy(user_realm, (char*)message.realm->turn_attr_realm, realm_len);
      user_realm[realm_len - 1] = 0x00;

      /* search the account */
      account = account_list_find(account_list, username, user_realm);

      if(!account)
      {
        /* not valid username => error 401 */
        struct iovec iov[5]; /* header, error-code, realm, nonce, software */
        size_t idx = 0;
        struct turn_msg_hdr* error = NULL;
        struct turn_attr_hdr* attr = NULL;
        uint8_t nonce[48];
        char* realm = turnserver_cfg_realm();
        char* key = turnserver_cfg_nonce_key();

        debug(DBG_ATTR, "No account\n");

        turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)key,
            strlen(key));
        idx = 0;

        if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
                realm, nonce, sizeof(nonce), iov, &idx)))
        {
          turnserver_send_error(transport_protocol, sock, method,
              message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
          return -1;
        }

        /* software (not fatal if it cannot be allocated) */
        if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
                sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
        {
          error->turn_msg_len += iov[idx].iov_len;
          idx++;
        }

        turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

        /* convert to big endian */
        error->turn_msg_len = htons(error->turn_msg_len);

        if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
              ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
              idx) == -1)
        {
          debug(DBG_ATTR, "turn_send_message failed\n");
        }

        /* free sent data */
        iovec_free_data(iov, idx);
        return 0;
      }
    }

    /* compute HMAC-SHA1 and compare with the value in message_integrity */
    {
      uint8_t hash[20];

      if(message.fingerprint)
      {
        /* if the message contains a FINGERPRINT attribute, adjust the size */
        size_t len_save = message.msg->turn_msg_len;

        message.msg->turn_msg_len =
          ntohs(message.msg->turn_msg_len) - sizeof(
              struct turn_attr_fingerprint);

        message.msg->turn_msg_len = htons(message.msg->turn_msg_len);
        turn_calculate_integrity_hmac((const unsigned char*)buf,
            total_len - sizeof(struct turn_attr_fingerprint) -
            sizeof(struct turn_attr_message_integrity), account->key,
            sizeof(account->key), hash);

        /* restore length */
        message.msg->turn_msg_len = len_save;
      }
      else
      {
        turn_calculate_integrity_hmac((const unsigned char*)buf,
            total_len - sizeof(struct turn_attr_message_integrity),
            account->key, sizeof(account->key), hash);
      }

      if(memcmp(hash, message.message_integrity->turn_attr_hmac, 20) != 0)
      {
        /* integrity does not match => error 401 */
        struct iovec iov[5]; /* header, error-code, realm, nonce, software */
        size_t idx = 0;
        struct turn_msg_hdr* error = NULL;
        struct turn_attr_hdr* attr = NULL;
        uint8_t nonce[48];
        char* nonce_key = turnserver_cfg_nonce_key();

        debug(DBG_ATTR, "Hash mismatch\n");
#ifndef NDEBUG
        /* print computed hash and the one from the message */
        digest_print(hash, 20);
        digest_print(message.message_integrity->turn_attr_hmac, 20);
#endif
        turn_generate_nonce(nonce, sizeof(nonce), (unsigned char*)nonce_key,
            strlen(nonce_key));
        idx = 0;

        if(!(error = turn_error_response_401(method, message.msg->turn_msg_id,
                turnserver_cfg_realm(), nonce, sizeof(nonce), iov, &idx)))
        {
          turnserver_send_error(transport_protocol, sock, method,
              message.msg->turn_msg_id, 500, saddr, saddr_size, speer, NULL);
          return -1;
        }

        /* software (not fatal if it cannot be allocated) */
        if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
                sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
        {
          error->turn_msg_len += iov[idx].iov_len;
          idx++;
        }

        turn_add_fingerprint(iov, &idx); /* not fatal if not successful */

        /* convert to big endian */
        error->turn_msg_len = htons(error->turn_msg_len);

        if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
              ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
              idx) == -1)
        {
          debug(DBG_ATTR, "turn_send_message failed\n");
        }

        /* free sent data */
        iovec_free_data(iov, idx);
        return 0;
      }
    }
  }

  /* check if there are unknown comprehension-required attributes */
  if(unknown_size)
  {
    struct iovec iov[4]; /* header, error-code, unknown-attributes, software */
    size_t idx = 0;
    struct turn_msg_hdr* error = NULL;
    struct turn_attr_hdr* attr = NULL;

    /* if not a request, message is discarded */
    if(!STUN_IS_REQUEST(hdr_msg_type))
    {
      debug(DBG_ATTR, "message has unknown attribute and it is not a request, "
          "discard\n");
      return -1;
    }

    /* unknown attributes found => error 420 */
    if(!(error = turn_error_response_420(method, message.msg->turn_msg_id,
            unknown, unknown_size, iov, &idx)))
    {
      turnserver_send_error(transport_protocol, sock, method,
          message.msg->turn_msg_id, 500, saddr, saddr_size, speer,
          account ? account->key : NULL);
      return -1;
    }

    /* software (not fatal if it cannot be allocated) */
    if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
            sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
    {
      error->turn_msg_len += iov[idx].iov_len;
      idx++;
    }

    /* convert to big endian */
    error->turn_msg_len = htons(error->turn_msg_len);

    if(turn_send_message(transport_protocol, sock, speer, saddr, saddr_size,
          ntohs(error->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
        == -1)
    {
      debug(DBG_ATTR, "turn_send_message failed\n");
    }

    /* free sent data */
    iovec_free_data(iov, idx);
    return 0;
  }

  /* the basic checks are done,
   * now check that specific method requirement are OK
   */
  debug(DBG_ATTR, "OK basic validation are done, process the TURN message\n");

  return turnserver_process_turn(transport_protocol, sock, &message, saddr,
      daddr, saddr_size, allocation_list, account, speer);
}

/**
 * \brief Receive a message on an relayed address.
 * \param buf data received
 * \param buflen length of data
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param speer TLS peer, if not NULL, message is relayed in TLS
 * \return 0 if message processed correctly, -1 otherwise
 */
static int turnserver_relayed_recv(const char* buf, ssize_t buflen,
    const struct sockaddr* saddr, struct sockaddr* daddr, socklen_t saddr_size,
    struct list_head* allocation_list, struct tls_peer* speer)
{
  struct allocation_desc* desc = NULL;
  uint8_t peer_addr[16];
  uint16_t peer_port;
  uint32_t channel = 0;
  struct iovec iov[8]; /* header, peer-address, data */
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct turn_channel_data channel_data;
  uint32_t padding = 0;
  ssize_t nb = -1;
  size_t len = 0; /* for TLS */
  char str[INET6_ADDRSTRLEN];

  /* find the allocation associated with the relayed transport address */
  desc = allocation_list_find_relayed(allocation_list, daddr, saddr_size);
  if(!desc)
  {
    /* no allocation found, discard */
    debug(DBG_ATTR, "No allocation found\n");
    return -1;
  }

  switch(saddr->sa_family)
  {
    case AF_INET:
      memcpy(peer_addr, &((struct sockaddr_in*)saddr)->sin_addr, 4);
      peer_port = ntohs(((struct sockaddr_in*)saddr)->sin_port);
      break;
    case AF_INET6:
      memcpy(peer_addr, &((struct sockaddr_in6*)saddr)->sin6_addr, 16);
      peer_port = ntohs(((struct sockaddr_in6*)saddr)->sin6_port);
      break;
    default:
      return -1;
  }

  /* check if the peer has permission */
  if(!allocation_desc_find_permission_sockaddr(desc, saddr))
  {
    /* no permission, discard */
    inet_ntop(saddr->sa_family, peer_addr, str, INET6_ADDRSTRLEN);
    debug(DBG_ATTR, "No permission installed (%s)\n", str);
    return -1;
  }

  /* check bandwidth limit */
  if(turnserver_check_bandwidth_limit(desc, buflen, 0))
  {
    debug(DBG_ATTR, "Bandwidth quotas reached!\n");
    return -1;
  }

  /* see if a channel is bound to the peer */
  channel = allocation_desc_find_channel(desc, saddr->sa_family, peer_addr,
      peer_port);

  if(channel != 0)
  {
    len = sizeof(struct turn_channel_data);

    /* send it with ChannelData */
    channel_data.turn_channel_number = htons(channel);
    channel_data.turn_channel_len = htons(buflen); /* big endian */

    iov[idx].iov_base = &channel_data;
    iov[idx].iov_len = sizeof(struct turn_channel_data);
    idx++;

    if(buflen > 0)
    {
      iov[idx].iov_base = (void*)buf;
      iov[idx].iov_len = buflen;
      len += buflen;
      idx++;
    }

    /* add padding (MUST be included for TCP, MAY be included for UDP) */
    if(buflen % 4)
    {
      iov[idx].iov_base = &padding;
      iov[idx].iov_len = 4 - (buflen % 4);
      len += iov[idx].iov_len;
      idx++;
    }
  }
  else
  {
    /* send it with Data Indication */
    uint8_t id[12];

    turn_generate_transaction_id(id);
    if(!(hdr = turn_msg_data_indication_create(0, id, &iov[idx])))
    {
      return -1;
    }
    idx++;

    if(!(attr = turn_attr_xor_peer_address_create(saddr, STUN_MAGIC_COOKIE, id,
            &iov[idx])))
    {
      iovec_free_data(iov, idx);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    if(!(attr = turn_attr_data_create(buf, buflen, &iov[idx])))
    {
      iovec_free_data(iov, idx);
      return -1;
    }
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;

    len = hdr->turn_msg_len + sizeof(struct turn_msg_hdr);
    hdr->turn_msg_len = htons(hdr->turn_msg_len);
  }

  /* send it to the tuple (TURN client) */
  debug(DBG_ATTR, "Send data to client\n");

  if(speer) /* TLS */
  {
    nb = turn_tls_send(speer, (struct sockaddr*)&desc->tuple.client_addr,
        sockaddr_get_size(&desc->tuple.client_addr), len, iov, idx);
  }
  else if(desc->tuple.transport_protocol == IPPROTO_UDP) /* UDP */
  {
    int optval = 0;
    int save_val = 0;
    socklen_t optlen = sizeof(int);

#ifdef OS_SET_DF_SUPPORT
    /* RFC6156: If present, the DONT-FRAGMENT attribute MUST be ignored by the
     * server for IPv4-IPv6, IPv6-IPv6 and IPv6-IPv4 relays
     */
    if((desc->tuple.client_addr.ss_family == AF_INET ||
          (desc->tuple.client_addr.ss_family == AF_INET6 &&
           IN6_IS_ADDR_V4MAPPED(
             &((struct sockaddr_in6*)&desc->tuple.client_addr)->sin6_addr))) &&
       (saddr->sa_family == AF_INET || (saddr->sa_family == AF_INET6 &&
       IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr))))
    {
      /* only for IPv4-IPv4 relay */
      /* alternate behavior, set DF to 0 */
      optval = IP_PMTUDISC_DONT;

      if(!getsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
            &optlen))
      {
        setsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &optval,
            sizeof(int));
      }
      else
      {
        /* little hack for not setting the old value of *_MTU_DISCOVER after
         * sending message in case getsockopt failed
         */
        optlen = 0;
      }
    }
#else
    optlen = 0;
    optval = 0;
    save_val = 0;
#endif

    nb = turn_udp_send(desc->tuple_sock,
        (struct sockaddr*)&desc->tuple.client_addr,
        sockaddr_get_size(&desc->tuple.client_addr), iov, idx);

    /* if not an IPv4-IPv4 relay, optlen keep its default value 0 */
#ifdef OS_SET_DF_SUPPORT
    if(optlen)
    {
      /* restore original value */
      setsockopt(desc->tuple_sock, IPPROTO_IP, IP_MTU_DISCOVER, &save_val,
          sizeof(int));
    }
#endif
  }
  else /* TCP */
  {
    nb = turn_tcp_send(desc->tuple_sock, iov, idx);
  }

  if(nb == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  /* if use a channel, do not used dynamic allocation */
  if(!channel)
  {
    iovec_free_data(iov, idx);
  }

  return 0;
}

/**
 * \brief Process message(s) in a single TCP stream.
 * \param buf data received
 * \param nb length of data
 * \param sock socket
 * \param saddr source address of the message
 * \param daddr destination address of the message
 * \param saddr_size sizeof addr
 * \param allocation_list list of allocations
 * \param account_list list of accounts
 * \param speer TLS peer if not NULL, the server accept TLS connection
 */
static void turnserver_process_tcp_stream(const char* buf, ssize_t nb,
    struct socket_desc* sock, struct sockaddr* saddr, struct sockaddr* daddr,
    socklen_t saddr_size, struct list_head* allocation_list,
    struct list_head* account_list, struct tls_peer* speer)
{
  char* tmp_buf = NULL;
  size_t tmp_len = 0;
  size_t tmp_nb = (size_t)nb;

  /* maybe it is an incomplete message */
  if(sock->buf_pos)
  {
    tmp_buf = sock->buf;

    /* check for buffer size */
    if(sock->buf_pos + MIN(sizeof(sock->buf), tmp_nb) > sizeof(sock->buf))
    {
      /* discard message */
      debug(DBG_ATTR, "Buffer too small, discard TCP message.\n");
      sock->buf_pos = 0;
      sock->msg_len = 0;
      return;
    }

    /* concatenate bytes received */
    memcpy(tmp_buf + sock->buf_pos, buf, MIN(sizeof(sock->buf), tmp_nb));
    sock->buf_pos += tmp_nb;
    /* printf("Incomplete packet!\n"); */
    tmp_nb = sock->buf_pos;
  }
  else
  {
    tmp_buf = (char*)buf; /* after that don't modify buf */
  }

  /* printf("Received: %u, Have: %u\n", tmp_nb, tmp_nb); */

  while(tmp_nb)
  {
    if(tmp_nb < 4)
    {
      /* message too small, maybe
       * incomplete ones
       */
      sock->buf_pos = tmp_nb;

      if(sock->buf != tmp_buf)
      {
        memcpy(sock->buf, tmp_buf, sock->buf_pos);
      }
      break;
    }

    if(!sock->msg_len)
    {
      uint16_t type = 0;
      memcpy(&type, tmp_buf, 2);
      type = ntohs(type);

      if(TURN_IS_CHANNELDATA(type))
      {
        struct turn_channel_data* cdata = (struct turn_channel_data*)tmp_buf;
        tmp_len = ntohs(cdata->turn_channel_len);

        /* TCP, so padding mandatory */
        if(ntohs(cdata->turn_channel_len) % 4)
        {
          tmp_len += 4 - (tmp_len % 4);
        }

        /* size of ChannelData header */
        tmp_len += 4;
      }
      else if(STUN_IS_REQUEST(type) || STUN_IS_INDICATION(type))
      {
        struct turn_msg_hdr* hdr = (struct turn_msg_hdr*)tmp_buf;
        /* size of STUN header */
        tmp_len = ntohs(hdr->turn_msg_len) + 20;
      }
      else
      {
        debug(DBG_ATTR, "Not a STUN request or TURN ChannelData!\n");
        sock->buf_pos = 0;
        sock->msg_len = 0;
        break;
      }
    }
    else
    {
      /* next message length is already known */
      tmp_len = sock->msg_len;
    }

    /* printf("Received: %u, Need %u bytes, Have %u bytes\n", tmp_nb, tmp_len,
          tmp_len);
     */

    if(tmp_nb < tmp_len)
    {
      /* incomplete message */
      debug(DBG_ATTR, "Incomplete message\n");

      sock->msg_len = tmp_len;
      sock->buf_pos = MIN(sizeof(sock->buf), tmp_nb);
      if(sock->buf != tmp_buf)
      {
        memcpy(sock->buf, tmp_buf, sock->buf_pos);
      }

      /* printf("State, msg_len: %u, buf_pos: %u\n", sock->msg_len,
           sock->buf_pos);
      */
      break;
    }

    if(turnserver_listen_recv(IPPROTO_TCP, sock->sock, tmp_buf, tmp_len, saddr,
          daddr, saddr_size, allocation_list, account_list, speer) == -1)
    {
      debug(DBG_ATTR, "Bad STUN/TURN message or permission problem\n");
    }

    tmp_nb -= tmp_len;
    tmp_buf += tmp_len;
    sock->msg_len = 0;

    if(sock->buf_pos != 0)
    {
      /* decrement buffer position */
      sock->buf_pos -= tmp_len;
    }

    /* printf("tmp_nb: %u, sock->buf_pos: %u\n", tmp_nb, sock->buf_pos); */
  }
}

/**
 * \brief Check if server can relay specific address with its current
 * configuration.
 *
 * For example if IPv6 is disabled, the server will drop immediately packets
 * coming from an IPv6-only client.
 * \param listen_address IPv4 listen address
 * \param listen_addressv6 IPv6 listen_address (could be NULL if IPv6 is
 * disabled)
 * \param saddr source address of client
 * \return 1 if the server can relay data for this client,
 * 0 otherwise
 */
static int turnserver_check_relay_address(char* listen_address,
    char* listen_addressv6, struct sockaddr_storage* saddr)
{
  if((!listen_addressv6 && (saddr->ss_family == AF_INET6 && !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr))) ||
     (!listen_address && (saddr->ss_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)saddr)->sin6_addr))) ||
     (!listen_address && saddr->ss_family == AF_INET))
  {
    return 0;
  }

  return 1;
}

/**
 * \brief Handle state of remote peer asynchronous TCP connect() (RFC6062).
 * \param sock TCP socket
 * \param relay TCP relay descriptor
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL send data in TLS
 * \return -1 if timeout or error which means that server have to send
 * a 447 error, -2 if system error happens and 0 if connect() succeed
 */
static int turnserver_handle_tcp_connect(int sock,
    struct allocation_tcp_relay* relay, struct allocation_desc* desc,
    struct tls_peer* speer)
{
  int err = 0;
  socklen_t err_size = sizeof(int);
  struct iovec iov[8];
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct sockaddr* saddr = (struct sockaddr*)&desc->tuple.client_addr;
  socklen_t saddr_size = sockaddr_get_size(&desc->tuple.client_addr);
  long flags = 0;
  int ret = 0;

  if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_size) == -1)
  {
    return -2;
  }

  if(err != 0)
  {
    return -1;
  }

  if(!(hdr = turn_msg_connect_response_create(0, relay->connect_msg_id,
          &iov[idx])))
  {
    return -2;
  }
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(!(attr = turn_attr_connection_id_create(relay->connection_id,
          &iov[idx])))
  {
    iovec_free_data(iov, idx);
    return -2;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
      == -1)
  {
    iovec_free_data(iov, idx);
    return -2;
  }

  /* send message */
  ret = turn_send_message(IPPROTO_TCP, desc->tuple_sock, speer, saddr,
      saddr_size, ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov,
      idx);

  iovec_free_data(iov, idx);

  if(ret == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
    return -2;
  }
  else
  {
    /* back to blocking mode */
    if((flags = fcntl(sock, F_GETFL, NULL)) == -1)
    {
      return -2;
    }

    flags &= (~O_NONBLOCK);

    if(fcntl(sock, F_SETFL, flags) == -1)
    {
      return -2;
    }

    /* connect() succeed, mark as ready */
    relay->ready = 1;
  }

  return 0;
}

/**
 * \brief Handle incoming TCP connection (RFC6062).
 * \param sock TCP listen socket
 * \param desc allocation descriptor
 * \param speer TLS peer, if not NULL send data in TLS
 */
static void turnserver_handle_tcp_incoming_connection(int sock,
    struct allocation_desc* desc, struct tls_peer* speer)
{
  int family = 0;
  uint8_t peer_addr[16];
  uint16_t peer_port = 0;
  uint32_t id = 0;
  uint8_t msg_id[12]; /* for ConnectionAttempt message ID */
  size_t idx = 0;
  struct turn_msg_hdr* hdr = NULL;
  struct turn_attr_hdr* attr = NULL;
  struct iovec iov[8];
  int rsock = -1;
  struct sockaddr_storage saddr;
  socklen_t saddr_size = sizeof(struct sockaddr_storage);
  size_t buffer_size = turnserver_cfg_tcp_buffer_userspace() ?
    turnserver_cfg_tcp_buffer_size() : 0;

  rsock = accept(sock, (struct sockaddr*)&saddr, &saddr_size);

  if(rsock == -1)
  {
    debug(DBG_ATTR,
        "Cannot process incoming TCP connection on listening socket.\n");
    return;
  }

  if(!allocation_desc_find_permission_sockaddr(desc, (struct sockaddr*)&saddr))
  {
    /* no permission installed so close socket */
    close(rsock);
    return;
  }

  /* generate unique ID */
  random_bytes_generate((uint8_t*)&id, 4);

  turn_generate_transaction_id(msg_id);

  switch(saddr.ss_family)
  {
    case AF_INET:
      family = AF_INET;
      memcpy(peer_addr, &((struct sockaddr_in*)&saddr)->sin_addr, 4);
      peer_port = ntohs(((struct sockaddr_in*)&saddr)->sin_port);
      break;
    case AF_INET6:
      family = AF_INET6;
      memcpy(peer_addr, &((struct sockaddr_in6*)&saddr)->sin6_addr, 16);
      peer_port = ntohs(((struct sockaddr_in6*)&saddr)->sin6_port);
      break;
    default:
      return;
      break;
  }

  /* add it to allocation */
  if(allocation_desc_add_tcp_relay(desc, id, rsock, family, peer_addr,
        peer_port, TURN_DEFAULT_TCP_RELAY_TIMEOUT, buffer_size, NULL) == -1)
  {
    close(rsock);
    return;
  }

  /* now send ConnectionAttempt to client */
  if(!(hdr = turn_msg_connectionattempt_indication_create(0, msg_id,
          &iov[idx])))
  {
    /* ignore ? */
    close(rsock);
    return;
  }
  idx++;

  /* software (not fatal if it cannot be allocated) */
  if((attr = turn_attr_software_create(SOFTWARE_DESCRIPTION,
          sizeof(SOFTWARE_DESCRIPTION) - 1, &iov[idx])))
  {
    hdr->turn_msg_len += iov[idx].iov_len;
    idx++;
  }

  if(!(attr = turn_attr_connection_id_create(id, &iov[idx])))
  {
    close(rsock);
    iovec_free_data(iov, idx);
    return;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  if(!(attr = turn_attr_xor_peer_address_create((struct sockaddr*)&saddr,
          STUN_MAGIC_COOKIE, msg_id, &iov[idx])))
  {
    close(rsock);
    iovec_free_data(iov, idx);
    return;
  }
  hdr->turn_msg_len += iov[idx].iov_len;
  idx++;

  if(turn_add_message_integrity(iov, &idx, desc->key, sizeof(desc->key), 1)
      == -1)
  {
    close(rsock);
    iovec_free_data(iov, idx);
    return;
  }

  /* send message */
  if(turn_send_message(IPPROTO_TCP, desc->tuple_sock, speer,
        (struct sockaddr*)&desc->tuple.client_addr,
        sockaddr_get_size(&desc->tuple.client_addr),
        ntohs(hdr->turn_msg_len) + sizeof(struct turn_msg_hdr), iov, idx)
      == -1)
  {
    debug(DBG_ATTR, "turn_send_message failed\n");
  }

  iovec_free_data(iov, idx);
  return;
}

/**
 * \brief Handle TCP or TLS over TCP accept().
 * \param sock listen TCP or TLS socket
 * \param tcp_socket_list list of remote TCP sockets
 * \param tls if socket use TLS (connect on TLS port)
 */
static void turnserver_handle_tcp_accept(int sock,
    struct list_head* tcp_socket_list, int tls)
{
  struct socket_desc* sdesc = NULL;
  struct sockaddr_storage saddr;
  socklen_t saddr_size = 0;
  char* listen_address = turnserver_cfg_listen_address();
  char* listen_addressv6 = turnserver_cfg_listen_addressv6();
  char* proto = NULL;
  int rsock = accept(sock, (struct sockaddr*)&saddr, &saddr_size);

  (void)proto; /* avoid compilation warning in release mode */

  if(rsock > 0)
  {
    if(!turnserver_check_relay_address(listen_address, listen_addressv6,
          &saddr))
    {
      /* don't relay the specified address family so close connection */
      proto = (saddr.ss_family == AF_INET6 &&
          !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))
        ? "IPv6" : "IPv4";
      debug(DBG_ATTR, "Do not relay family: %s\n", proto);
      close(rsock);
    }
    else
    {
      if(!(sdesc = malloc(sizeof(struct socket_desc))))
      {
        close(rsock);
      }
      else
      {
        /* initialize */
        sdesc->buf_pos = 0;
        sdesc->msg_len = 0;
        sdesc->tls = tls;
        sdesc->sock = rsock;

        /* add it to the list */
        LIST_ADD(&sdesc->list, tcp_socket_list);
      }
    }
  }
}

/**
 * \brief Wait messages and process it.
 * \param sockets all listen sockets
 * \param tcp_socket_list list of TCP sockets
 * \param allocation_list list of allocations
 * \param account_list list of accounts
 */
static void turnserver_main(struct listen_sockets* sockets,
    struct list_head* tcp_socket_list, struct list_head* allocation_list,
    struct list_head* account_list)
{
  struct list_head* n = NULL;
  struct list_head* get = NULL;
  struct timespec tv;
  int nsock = -1;
  int ret = -1;
  sfd_set fdsr;
  sfd_set fdsw;
  long max_fd = 0;
  char error_str[1024];
  sigset_t mask;
  char buf[8192];
  struct sockaddr_storage saddr;
  socklen_t saddr_size = sizeof(struct sockaddr_storage);
  struct sockaddr_storage daddr;
  socklen_t daddr_size = sizeof(struct sockaddr_storage);
  ssize_t nb = -1;
  char* proto = NULL;
  char* listen_address = turnserver_cfg_listen_address();
  char* listen_addressv6 = turnserver_cfg_listen_addressv6();

  (void)proto;

  max_fd = SFD_SETSIZE;

  if(max_fd <= 0)
  {
    /* should not happen on a POSIX.1 compliant-system */
    g_run = 0;
    debug(DBG_ATTR, "Cannot determine max open files for this system!\n");
    return;
  }

  SFD_ZERO(&fdsr);
  SFD_ZERO(&fdsw);

  /* ensure that FD_SET will not overflow */
  if(sockets->sock_udp >= max_fd || sockets->sock_tcp >= max_fd ||
     (sockets->sock_tls && (sockets->sock_tls->sock >= max_fd)))
  {
    g_run = 0;
    debug(DBG_ATTR, "Listen sockets cannot be set for select() (FD_SETSIZE "
        "overflow)\n");
    return;
  }

  /* UDP and TCP listen socket */
  SFD_SET(sockets->sock_udp, &fdsr);
  SFD_SET(sockets->sock_tcp, &fdsr);

  nsock = MAX(sockets->sock_udp, sockets->sock_tcp);

  /* TLS socket */
  if(turnserver_cfg_tls() && sockets->sock_tls)
  {
    SFD_SET(sockets->sock_tls->sock, &fdsr);
    nsock = MAX(nsock, sockets->sock_tls->sock);
  }

  /* DTLS socket */
  if(turnserver_cfg_dtls() && sockets->sock_dtls)
  {
    SFD_SET(sockets->sock_dtls->sock, &fdsr);
    nsock = MAX(nsock, sockets->sock_dtls->sock);
  }

  /* add UDP and TCP relayed sockets */
  list_iterate_safe(get, n, allocation_list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
    struct list_head* get2 = NULL;
    struct list_head* n2 = NULL;

    if(tmp->relayed_sock < max_fd)
    {
      SFD_SET(tmp->relayed_sock, &fdsr);
      nsock = MAX(nsock, tmp->relayed_sock);
    }

    /* RFC6062 (TURN-TCP) */
    /* add peer and client data connection sockets */
    list_iterate_safe(get2, n2, &tmp->tcp_relays)
    {
      struct allocation_tcp_relay* tmp2 = list_get(get2,
          struct allocation_tcp_relay, list);

      if(tmp2->peer_sock > 0 && tmp2->peer_sock < max_fd)
      {
        /* if asynchronous connect() has not succeed yet,
         * check again and send a Connect success
         * response if socket is connected
         */
        if(tmp2->peer_sock != -1 && tmp2->ready != 1)
        {
          /* check if connect() timeout (with value define in RFC6062) */
          if((tmp2->created + TURN_DEFAULT_TCP_CONNECT_TIMEOUT) <= time(NULL))
          {
            debug(DBG_ATTR, "TCP connect() timeout\n");

            /* send error and remove relay */
            turnserver_send_error(IPPROTO_TCP, tmp->tuple_sock,
                TURN_METHOD_CONNECT, tmp2->connect_msg_id, 447,
                (struct sockaddr*)&tmp->tuple.client_addr,
                sockaddr_get_size(&tmp->tuple.client_addr), sockets->sock_tls,
                NULL);

            /* protect the removing of the expired list if any */
            turnserver_block_realtime_signal();
            allocation_tcp_relay_set_timer(tmp2, 0); /* stop timeout */
            /* in case TCP relay has expired during this statement */
            LIST_DEL(&tmp2->list2);
            turnserver_unblock_realtime_signal();
            allocation_tcp_relay_list_remove(&tmp->tcp_relays, tmp2);
            continue;
          }
          else
          {
            /* add to select for write operations */
            SFD_SET(tmp2->peer_sock, &fdsw);
            nsock = MAX(nsock, tmp2->peer_sock);
          }
        }

        /* if client has not send its ConnectionBind yet, or if userspace
         * buffering is not enable, OS will perform buffering
         */
        if(tmp2->client_sock != -1 || turnserver_cfg_tcp_buffer_userspace())
        {
          SFD_SET(tmp2->peer_sock, &fdsr);
          nsock = MAX(nsock, tmp2->peer_sock);
        }
        else
        {
          /* here, buffering is done in OS
           * but see if TCP receive buffer size does
           * not exceed the limit.
           */
          uint32_t val = 0;

          /* use FIONREAD (same as SIOCINQ) to see how much
           * ready-to-read bytes are in TCP receive queue
           */
          if(ioctl(tmp2->peer_sock, FIONREAD, &val) >= 0)
          {
            if(val > turnserver_cfg_tcp_buffer_size())
            {
              /* limit exceeded, remove TCP relay */
              debug(DBG_ATTR, "Exceed TCP buffer size limit (OS buffering)!\n");

              /* protect the removing of the expired list if any */
              turnserver_block_realtime_signal();
              allocation_tcp_relay_set_timer(tmp2, 0); /* stop timeout */
              /* in case TCP relay has expired during this statement */
              LIST_DEL(&tmp2->list2);
              turnserver_unblock_realtime_signal();
              allocation_tcp_relay_list_remove(&tmp->tcp_relays, tmp2);
              continue;
            }
          }
        }
      }

      if(tmp2->client_sock > 0 && tmp2->client_sock < max_fd)
      {
        SFD_SET(tmp2->client_sock, &fdsr);
        nsock = MAX(nsock, tmp2->client_sock);
      }
    }
  }

  /* add TCP remote sockets */
  list_iterate_safe(get, n, tcp_socket_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);

    /* TCP remote socket */
    if(tmp->sock < max_fd && tmp->sock > 0)
    {
      SFD_SET(tmp->sock, &fdsr);
      nsock = MAX(nsock, tmp->sock);
    }
    else
    {
      /* TCP connection after ConnectionBind, must be removed */
      LIST_DEL(&tmp->list);
      free(tmp);
    }
  }

  /* mod_tmpuser */
  if(turnserver_cfg_mod_tmpuser())
  {
    int tmpuser_sock = tmpuser_get_socket();
    struct list_head* tmpuser_list = tmpuser_get_tcp_clients();

    /* listen socket */
    if(tmpuser_sock < max_fd && tmpuser_sock > 0)
    {
      SFD_SET(tmpuser_sock, &fdsr);
      nsock = MAX(nsock, tmpuser_sock);
    }

    /* add mod_tmpuser's TCP remote sockets */
    list_iterate_safe(get, n, tmpuser_list)
    {
      struct socket_desc* tmp = list_get(get, struct socket_desc, list);

      if(tmp->sock < max_fd && tmp->sock > 0)
      {
        SFD_SET(tmp->sock, &fdsr);
        nsock = MAX(nsock, tmp->sock);
      }
    }
  }

  nsock++;

  /* timeout */
  tv.tv_sec = 1;
  tv.tv_nsec = 0;

  /* signal blocked */
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGPIPE);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  sigaddset(&mask, SIGRT_EXPIRE_ALLOCATION);
  sigaddset(&mask, SIGRT_EXPIRE_PERMISSION);
  sigaddset(&mask, SIGRT_EXPIRE_CHANNEL);
  sigaddset(&mask, SIGRT_EXPIRE_TOKEN);

  ret = pselect(nsock, (fd_set*)(void*)&fdsr, (void*)&fdsw, NULL, &tv, &mask);

  if(ret > 0)
  {
    /* main UDP listen socket */
    if(sfd_has_data(sockets->sock_udp, max_fd, &fdsr))
    {
      debug(DBG_ATTR, "Received UDP on listening address\n");
      saddr_size = sizeof(struct sockaddr_storage);
      daddr_size = sizeof(struct sockaddr_storage);

      getsockname(sockets->sock_udp, (struct sockaddr*)&daddr, &daddr_size);
      nb = recvfrom(sockets->sock_udp, buf, sizeof(buf), 0,
          (struct sockaddr*)&saddr, &saddr_size);

      if(nb > 0)
      {
        if(!turnserver_check_relay_address(listen_address, listen_addressv6,
              &saddr))
        {
          proto = (saddr.ss_family == AF_INET6 &&
              !IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6*)&saddr)->sin6_addr))
            ? "IPv6" : "IPv4";
          debug(DBG_ATTR, "Do not relay family: %s\n", proto);
        }
        else if(turnserver_listen_recv(IPPROTO_UDP, sockets->sock_udp, buf, nb,
                (struct sockaddr*)&saddr, (struct sockaddr*)&daddr,
                saddr_size, allocation_list, account_list, NULL) == -1)
        {
          debug(DBG_ATTR, "Bad STUN/TURN message or permission problem\n");
        }
      }
      else
      {
        get_error(errno, error_str, sizeof(error_str));
        debug(DBG_ATTR, "Error: %s\n", error_str);
      }
    }

    /* main DTLS listen socket */
    if(sockets->sock_dtls && sfd_has_data(sockets->sock_dtls->sock, max_fd,
          &fdsr))
    {
      debug(DBG_ATTR, "Received DTLS on listening address\n");
      saddr_size = sizeof(struct sockaddr_storage);
      daddr_size = sizeof(struct sockaddr_storage);

      getsockname(sockets->sock_dtls->sock, (struct sockaddr*)&daddr,
          &daddr_size);
      nb = recvfrom(sockets->sock_dtls->sock, buf, sizeof(buf), 0,
          (struct sockaddr*)&saddr, &saddr_size);

      if(nb > 0 && tls_peer_is_encrypted(buf, nb))
      {
        char buf2[1500];
        ssize_t nb2 = -1;

        if((nb2 = tls_peer_udp_read(sockets->sock_dtls, buf, nb, buf2,
                sizeof(buf2), (struct sockaddr*)&saddr, saddr_size)) > 0)
        {
          if(!turnserver_check_relay_address(listen_address, listen_addressv6,
                &saddr))
          {
            proto = (saddr.ss_family == AF_INET6 &&
                !IN6_IS_ADDR_V4MAPPED(
                  &((struct sockaddr_in6*)&saddr)->sin6_addr))
              ? "IPv6" : "IPv4";
            debug(DBG_ATTR, "Do not relay family: %s\n", proto);
          }
          else if(turnserver_listen_recv(IPPROTO_UDP, sockets->sock_dtls->sock,
                buf2, nb2, (struct sockaddr*)&saddr, (struct sockaddr*)&daddr,
                saddr_size, allocation_list, account_list, sockets->sock_dtls)
              == -1)
          {
            debug(DBG_ATTR, "Bad STUN/TURN message or permission problem\n");
          }
        }
      }
      else
      {
        get_error(errno, error_str, sizeof(error_str));
        debug(DBG_ATTR, "Error: %s\n", error_str);
      }
    }

    /* remote TCP sockets */
    list_iterate_safe(get, n, tcp_socket_list)
    {
      struct socket_desc* tmp = list_get(get, struct socket_desc, list);

      if(sfd_has_data(tmp->sock, max_fd, &fdsr))
      {
        debug(DBG_ATTR, "Received data from %s client\n", !tmp->tls
            ? "TCP" : "TLS");

        if((getpeername(tmp->sock, (struct sockaddr*)&saddr,
                &saddr_size) == -1) ||
           (getsockname(tmp->sock, (struct sockaddr*)&daddr,
                        &daddr_size) == -1))
        {
          close(tmp->sock);
          LIST_DEL(&tmp->list);
          free(tmp);
          continue;
        }

        nb = recv(tmp->sock, buf, sizeof(buf), 0);

        if(nb > 0)
        {
          if(tmp->tls && sockets->sock_tls && tls_peer_is_encrypted(buf, nb))
          {
            char buf2[1500];
            ssize_t nb2 = -1;

            /* decode TLS data */
            if((nb2 = tls_peer_tcp_read(sockets->sock_tls, buf, nb, buf2,
                    sizeof(buf2), (struct sockaddr*)&saddr, saddr_size,
                    tmp->sock)) > 0)
            {
              /* TLS over TCP stream may contain multiple STUN/TURN messages */
              turnserver_process_tcp_stream(buf2, nb2, tmp,
                  (struct sockaddr*)&saddr, (struct sockaddr*)&daddr,
                  saddr_size, allocation_list, account_list, sockets->sock_tls);
            }
            else
            {
              get_error(errno, error_str, sizeof(error_str));
              debug(DBG_ATTR, "Error: %s\n", error_str);
            }
          }
          else /* non-encrypted TCP data */
          {
            /* TCP stream may contain multiple STUN/TURN messages */
            turnserver_process_tcp_stream(buf, nb, tmp,
                (struct sockaddr*)&saddr, (struct sockaddr*)&daddr, saddr_size,
                allocation_list, account_list, NULL);
          }
        }
        else
        {
          /* 0: disconnection case
           * -1: error
           */
          get_error(errno, error_str, sizeof(error_str));
          debug(DBG_ATTR, "Error: %s\n", error_str);
          close(tmp->sock);
          tmp->sock = -1;
          LIST_DEL(&tmp->list);
          free(tmp);
        }
      }
    }

    /* main TCP listen socket */
    if(sfd_has_data(sockets->sock_tcp, max_fd, &fdsr))
    {
      debug(DBG_ATTR, "Received TCP on listening address\n");
      turnserver_handle_tcp_accept(sockets->sock_tcp, tcp_socket_list, 0);
    }

    /* main TLS listen socket */
    if(sockets->sock_tls && sfd_has_data(sockets->sock_tls->sock, max_fd,
          &fdsr))
    {
      debug(DBG_ATTR, "Received TLS on listening address\n");
      turnserver_handle_tcp_accept(sockets->sock_tls->sock, tcp_socket_list, 1);
    }

    /* relayed UDP-based addresses and TCP-based relayed listen addresses */
    list_iterate_safe(get, n, allocation_list)
    {
      struct allocation_desc* tmp = list_get(get, struct allocation_desc, list);
      struct list_head* get2 = NULL;
      struct list_head* n2 = NULL;

      /* relayed address */
      if(sfd_has_data(tmp->relayed_sock, max_fd, &fdsr))
      {
        /* UDP relay is described in RFC 5766
         * and TCP relay is described in RFC6062
         */
        if(tmp->relayed_transport_protocol == IPPROTO_UDP)
        {
          debug(DBG_ATTR, "Received UDP on a relayed address\n");
          saddr_size = sizeof(struct sockaddr_storage);
          daddr_size = sizeof(struct sockaddr_storage);

          getsockname(tmp->relayed_sock, (struct sockaddr*)&daddr, &daddr_size);
          nb = recvfrom(tmp->relayed_sock, buf, sizeof(buf), 0,
              (struct sockaddr*)&saddr, &saddr_size);

          if(nb > 0)
          {
            struct tls_peer* speer = NULL;

            if(tmp->relayed_tls)
            {
              speer = sockets->sock_tls;
            }
            else if(tmp->relayed_dtls)
            {
              speer = sockets->sock_dtls;
            }

            turnserver_relayed_recv(buf, nb, (struct sockaddr*)&saddr,
                (struct sockaddr*)&daddr, saddr_size, allocation_list, speer);
          }
          else
          {
            get_error(errno, error_str, sizeof(error_str));
          }
        }
        else if(tmp->relayed_transport_protocol == IPPROTO_TCP)
        {
          /* RFC6062 (TURN-TCP) */
          /* handle incoming TCP connection on relayed address */
          debug(DBG_ATTR, "Received incoming connection on a listening TCP "
              "relayed address\n");
          turnserver_handle_tcp_incoming_connection(tmp->relayed_sock, tmp,
              tmp->relayed_tls ? sockets->sock_tls : NULL);
        }
      }

      /* RFC6062 (TURN-TCP) */
      /* relayed TCP-based addresses */
      list_iterate_safe(get2, n2, &tmp->tcp_relays)
      {
        struct allocation_tcp_relay* tmp2 = list_get(get2,
            struct allocation_tcp_relay, list);

        if(!tmp2->ready && sfd_has_data(tmp2->peer_sock, max_fd, &fdsw))
        {
          int ret_connect = turnserver_handle_tcp_connect(tmp2->peer_sock, tmp2,
              tmp, tmp->relayed_tls ? sockets->sock_tls : NULL);

          if(ret_connect == -1)
          {
            /* connect() failed */
            debug(DBG_ATTR, "connect() failed!\n");

            turnserver_send_error(IPPROTO_TCP, tmp->tuple_sock,
                TURN_METHOD_CONNECT, tmp2->connect_msg_id, 447,
                (struct sockaddr*)&tmp->tuple.client_addr,
                sockaddr_get_size(&tmp->tuple.client_addr),
                tmp->relayed_tls ? sockets->sock_tls : NULL, tmp->key);

            /* bring back relayed_tcp_sock to permit again TCP connect
             * request
             */
            tmp->relayed_sock_tcp = tmp2->peer_sock;
            tmp2->peer_sock = -1;
          }
          else if(ret_connect == -2)
          {
            /* a system error happens */
            debug(DBG_ATTR, "connect() success but system error!\n");

            turnserver_send_error(IPPROTO_TCP, tmp->tuple_sock,
                TURN_METHOD_CONNECT, tmp2->connect_msg_id, 500,
                (struct sockaddr*)&tmp->tuple.client_addr,
                sockaddr_get_size(&tmp->tuple.client_addr),
                tmp->relayed_tls ? sockets->sock_tls : NULL, tmp->key);

            /* bring back relayed_tcp_sock to permit again TCP connect
             * request
             */
            tmp->relayed_sock_tcp = tmp2->peer_sock;
            tmp2->peer_sock = -1;
          }
        }
        else if(sfd_has_data(tmp2->peer_sock, max_fd, &fdsr))
        {
          debug(DBG_ATTR, "Receive data from TCP peer\n");

          /* relay data from peer to client */
          nb = recv(tmp2->peer_sock, buf, sizeof(buf), 0);

          if(nb > 0)
          {
            /* client has not send ConnectionBind yet,
             * buffer data
             */
            if(tmp2->client_sock == -1)
            {
              debug(DBG_ATTR, "Buffer data from peer (TURN-TCP)\n");
              if((size_t)nb <= (tmp2->buf_size - tmp2->buf_len))
              {
                memcpy(tmp2->buf + tmp2->buf_len, buf, nb);
                tmp2->buf_len += nb;
              }
              else
              {
                /* limit exceeded, remove TCP relay */
                debug(DBG_ATTR, "Exceed TCP buffer size limit (userspace "
                    "buffering)!\n");

                /* protect the removing of the expired list if any */
                turnserver_block_realtime_signal();
                allocation_tcp_relay_set_timer(tmp2, 0); /* stop timeout */
                /* in case TCP relay has expired during this statement */
                LIST_DEL(&tmp2->list2);
                turnserver_unblock_realtime_signal();
                allocation_tcp_relay_list_remove(&tmp->tcp_relays, tmp2);
              }

              /* client_sock is not set so process next TCP relay */
              continue;
            }

            /* send just received data to client */
            if(send(tmp2->client_sock, buf, nb, 0) == -1)
            {
              debug(DBG_ATTR, "Error sending data from peer to client "
                  "(TURN-TCP)\n");
            }
          }
          else
          {
            /* problem on the socket, remove relay */
            debug(DBG_ATTR, "Error TCP relay: %s\n",
                get_error(errno, error_str, sizeof(error_str)));

            /* protect the removing of the expired list if any */
            turnserver_block_realtime_signal();
            allocation_tcp_relay_set_timer(tmp2, 0); /* stop timeout */
            /* in case TCP relay has expired during this statement */
            LIST_DEL(&tmp2->list2);
            turnserver_unblock_realtime_signal();
            allocation_tcp_relay_list_remove(&tmp->tcp_relays, tmp2);

            /* if relay is removed no need to test client_sock
             * since it is removed!
             */
            continue;
          }
        }

        if(sfd_has_data(tmp2->client_sock, max_fd, &fdsr))
        {
          /* case when peer connect first */
          if(tmp2->new)
          {
            tmp2->new = 0;
            continue;
          }

          debug(DBG_ATTR, "Receive data from TCP client to TCP peer\n");

          /* relay data from client to peer */
          nb = recv(tmp2->client_sock, buf, sizeof(buf), 0);

          if(nb > 0)
          {
            /* send just received data to peer */
            if(send(tmp2->peer_sock, buf, nb, 0) == -1)
            {
              debug(DBG_ATTR, "Error sending data from client to peer "
                  "(TURN-TCP)\n");
            }
          }
          else
          {
            /* problem on the socket, remove relay */
            debug(DBG_ATTR, "Error TCP relay: %s\n",
                get_error(errno, error_str, sizeof(error_str)));

            /* protect the removing of the expired list if any */
            turnserver_block_realtime_signal();
            allocation_tcp_relay_set_timer(tmp2, 0); /* stop timeout */
            /* in case TCP relay has expired during this statement */
            LIST_DEL(&tmp2->list2);
            turnserver_unblock_realtime_signal();
            allocation_tcp_relay_list_remove(&tmp->tcp_relays, tmp2);
          }
        }
      }
    }

    /* mod_tmpuser */
    if(turnserver_cfg_mod_tmpuser())
    {
      /* listen socket */
      if(sfd_has_data(tmpuser_get_socket(), max_fd, &fdsr))
      {
        int fd = accept(tmpuser_get_socket(), NULL, NULL);

        if(fd > 0)
        {
          struct socket_desc* desc = malloc(sizeof(struct socket_desc));

          if(desc)
          {
            desc->sock = fd;
            tmpuser_add_tcp_client(desc);
          }
        }
      }

      /* remote TCP client */
      list_iterate_safe(get, n, tmpuser_get_tcp_clients())
      {
        struct socket_desc* tmp = list_get(get, struct socket_desc, list);

        if(sfd_has_data(tmp->sock, max_fd, &fdsr))
        {
          nb = recv(tmp->sock, buf, sizeof(buf), 0);

          if(nb > 0)
          {
            int r = tmpuser_process_msg(buf, nb);

            if(!r)
            {
              send(tmp->sock, "success", sizeof("success"), 0);
            }
            else
            {
              send(tmp->sock, "error", sizeof("error"), 0);
            }
          }
          else
          {
            close(tmp->sock);
            LIST_DEL(&tmp->list);
            free(tmp);
          }
        }
      }
    }
  }
  else if(ret == -1)
  {
    get_error(errno, error_str, sizeof(error_str));
    debug(DBG_ATTR, "select() failed: %s\n", error_str);
  }
}

/**
 * \brief Cleanup function used when fork() to correctly free() ressources.
 * \param arg argument, in this case it is the account_list pointer
 */
static void turnserver_cleanup(void* arg)
{
  struct list_head* get = NULL;
  struct list_head* n = NULL;

  /* account_list */
  list_head* accounts = arg;

  /* configuration file */
  turnserver_cfg_free();

  if(accounts)
  {
    account_list_free(accounts);
  }

  /* free the denied address list */
  list_iterate_safe(get, n, &g_denied_address_list)
  {
    struct denied_address* tmp = list_get(get, struct denied_address, list);
    LIST_DEL(&tmp->list);
    free(tmp);
  }
}

/**
 * \brief Write pid in a file.
 * \param pidfile pidfile pathname
 */
static void turnserver_write_pidfile(const char *pidfile)
{
  if(pidfile)
  {
    FILE *f = fopen(pidfile, "w");

    if(!f)
    {
      syslog(LOG_ERR, "Can't open %s for write: %s", pidfile, strerror(errno));
    }
    else
    {
      fprintf(f, "%d\n", getpid());
      fclose(f);
    }
  }
}

/**
 * \brief Remove pidfile.
 * \param pidfile pidfile pathname
 */
static void turnserver_remove_pidfile(const char* pidfile)
{
  if(pidfile)
  {
    unlink(pidfile);
  }
}

/**
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of argument
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
  struct list_head allocation_list;
  struct list_head account_list;
  struct list_head* n = NULL;
  struct list_head* get = NULL;
  struct listen_sockets sockets;
  char* configuration_file = NULL;
  char* pid_file = NULL;
  char* listen_addr = NULL;
  struct sigaction sa;

  /* initialize lists */
  INIT_LIST(allocation_list);
  INIT_LIST(account_list);
  INIT_LIST(g_tcp_socket_list);
  INIT_LIST(g_token_list);
  INIT_LIST(g_denied_address_list);

  /* initialize expired lists */
  INIT_LIST(g_expired_allocation_list);
  INIT_LIST(g_expired_permission_list);
  INIT_LIST(g_expired_channel_list);
  INIT_LIST(g_expired_token_list);
  INIT_LIST(g_expired_tcp_relay_list);

  /* initialize sockets */
  sockets.sock_udp = -1;
  sockets.sock_tcp = -1;
  sockets.sock_tls = NULL;
  sockets.sock_dtls = NULL;

#ifdef NDEBUG
  /* disable core dump in release mode */
  debug(DBG_ATTR, "Disable core dump\n");
  turnserver_disable_core_dump();
#endif

  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  /* catch signals that usealy stop application
   * without performing cleanup such as SIGINT
   * (i.e CTRL-C break) and SIGTERM
   * (i.e kill -TERM command)
   */
  if(sigaction(SIGINT, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGINT will not be catched\n");
  }

  if(sigaction(SIGTERM, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGTERM will not be catched\n");
  }

  if(sigaction(SIGPIPE, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGPIPE will not be catched\n");
  }

  /* catch SIGHUP to reload credentials */
  if(sigaction(SIGHUP, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGHUP will not be catched\n");
  }

  /* catch SIGUSR1 and SIGUSR2 to avoid being killed
   * if someone send these signals
   */
  if(sigaction(SIGUSR1, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGUSR1 will not be catched\n");
  }

  if(sigaction(SIGUSR2, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGUSR2 will not be catched\n");
  }

  /* realtime handler */
  sa.sa_handler = NULL;
  sa.sa_sigaction = realtime_signal_handler;
  sa.sa_flags = SA_SIGINFO;

  /* as TurnServer uses these signals for expiration
   * stuff, exit if they cannot be handled by signal handler
   */
  if(sigaction(SIGRT_EXPIRE_ALLOCATION, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_ALLOCATION will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_PERMISSION, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_PERMISSION will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_CHANNEL, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_CHANNEL will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_TOKEN, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_TOKEN will not be catched\n");
    exit(EXIT_FAILURE);
  }

  if(sigaction(SIGRT_EXPIRE_TCP_RELAY, &sa, NULL) == -1)
  {
    debug(DBG_ATTR, "SIGRT_EXPIRE_TCP_RELAY will not be catched\n");
    exit(EXIT_FAILURE);
  }

  /* parse the arguments */
  turnserver_parse_cmdline(argc, argv, &configuration_file, &pid_file);

  if(!configuration_file)
  {
    configuration_file = DEFAULT_CONFIGURATION_FILE;
  }

  /* parse configuration file */
  if(turnserver_cfg_parse(configuration_file, &g_denied_address_list) != 0)
  {
    fprintf(stderr, "Parse configuration error, exiting...\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

#ifndef NDEBUG
  turnserver_cfg_print();
#endif

  /* check configuration */
  if(!turnserver_cfg_listen_address() && !turnserver_cfg_listen_addressv6())
  {
    fprintf(stderr, "Configuration error: must configure listen_address and/or "
        "listen_addressv6 in configuration file.\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

  if((turnserver_cfg_max_port() == 0 || turnserver_cfg_min_port() == 0) ||
     (turnserver_cfg_max_port() - turnserver_cfg_min_port() < 0))
  {
    fprintf(stderr, "Configuration error: allocation minimum/maximum port "
        "number must not be equals to 0 and max_port must be greater"
        "or equal than min_port.\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

  if(strcmp(turnserver_cfg_account_method(), "file") != 0)
  {
    /* for the moment only file method is implemented */
    fprintf(stderr, "Configuration error: method \"%s\" not implemented, "
        "exiting...\n", turnserver_cfg_account_method());
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

  /* check if certificates and key stuff are in configuration file
   * if TLS is used
   */
  if((turnserver_cfg_tls() || turnserver_cfg_dtls()) &&
      (!turnserver_cfg_ca_file() || !turnserver_cfg_cert_file() ||
       !turnserver_cfg_private_key_file()))
  {
    fprintf(stderr, "Configuration error: TLS and/or DTLS enabled but some "
        "elements are missing (cert file, ...).\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

  if(!turnserver_cfg_nonce_key())
  {
    fprintf(stderr, "Configuration error: nonce_key attribute is missing.\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

  /* map the account in memory */
  if(account_parse_file(&account_list, turnserver_cfg_account_file()) == -1)
  {
    fprintf(stderr, "Failed to parse account file, exiting...\n");
    turnserver_cleanup(NULL);
    exit(EXIT_FAILURE);
  }

#if 0
  /* print account information */
  list_iterate_safe(get, n, &account_list)
  {
    struct account_desc* tmp = list_get(get, struct account_desc, list);
    printf("%s %s\n", tmp->username, tmp->realm);
  }
#endif

  if(turnserver_cfg_daemon())
  {
    /* run as daemon, we take care to cleanup existing allocated memory such
     * as account and denied address list of the father process before _exit()
     */
    if(go_daemon("/", 0, turnserver_cleanup, &account_list) == -1)
    {
      fprintf(stderr, "Failed to start daemon, exiting...\n");
      turnserver_cleanup(&account_list);
      exit(EXIT_FAILURE);
    }

    /* write pid file */
    turnserver_write_pidfile(pid_file);
  }

  debug(DBG_ATTR, "TurnServer start\n");

  /* syslog system */
  openlog("TurnServer", LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "TurnServer start");

  /* mod_tmpuser */
  if(turnserver_cfg_mod_tmpuser())
  {
    tmpuser_init(&account_list);
  }

  /* Some versions of getaddrinfo do not prefer IPv6+IPv4 addresses over
   * IPv4 only when passing NULL as "node" parameter.
   *
   * Here is a work around this problem. If TurnServer is configured to use IPv6
   * relaying, force listen to IPv6+IPv4 by passing "::" address,
   * otherwise force IPv4 only by passing "0.0.0.0" address.
   *
   * Note that for *BSD, disable IPV6ONLY socket option (see tls_peer.c)
   * to enable IPv6+IPv4 mode, else "::" address only listen on all IPv6
   * addresses.
   */
  listen_addr = turnserver_cfg_listen_addressv6() ? "::" : "0.0.0.0";

  /* initialize listen sockets */
  /* UDP socket */
  sockets.sock_udp = socket_create(IPPROTO_UDP, listen_addr,
      turnserver_cfg_udp_port(), 0, 0);

  if(sockets.sock_udp == -1)
  {
    debug(DBG_ATTR, "UDP socket creation failed\n");
    syslog(LOG_ERR, "UDP socket creation failed");
  }

  /* TCP socket */
  sockets.sock_tcp = socket_create(IPPROTO_TCP, listen_addr,
      turnserver_cfg_tcp_port(), 1, 1);

  if(sockets.sock_tcp > 0)
  {
    if(listen(sockets.sock_tcp, 5) == -1)
    {
      char error_str[256];
      get_error(errno, error_str, sizeof(error_str));
      debug(DBG_ATTR, "TCP socket failed to listen(): %s\n", error_str);
      syslog(LOG_ERR, "TCP socket failed to listen(): %s", error_str);
      close(sockets.sock_tcp);
      sockets.sock_tcp = -1;
    }
  }

  if(sockets.sock_tcp == -1)
  {
    char error_str[256];
    get_error(errno, error_str, sizeof(error_str));
    debug(DBG_ATTR, "TCP socket creation failed: %s\n", error_str);
    syslog(LOG_ERR, "TCP socket creation failed: %s", error_str);
  }

  if(turnserver_cfg_tls() || turnserver_cfg_dtls())
  {
    struct tls_peer* speer = NULL;

    /* libssl initialization */
    LIBSSL_INIT;

    if(turnserver_cfg_tls())
    {
      /* TLS over TCP socket */
      speer = tls_peer_new(IPPROTO_TCP, listen_addr, turnserver_cfg_tls_port(),
          turnserver_cfg_ca_file(), turnserver_cfg_cert_file(),
          turnserver_cfg_private_key_file(), NULL);

      if(speer)
      {
        if(listen(speer->sock, 5) == -1)
        {
          char error_str[256];
          get_error(errno, error_str, sizeof(error_str));
          debug(DBG_ATTR, "TLS socket failed to listen(): %s\n", error_str);
          syslog(LOG_ERR, "TLS socket failed to listen(): %s", error_str);
          tls_peer_free(&speer);
          speer = NULL;
        }

        sockets.sock_tls = speer;
      }
      else
      {
        debug(DBG_ATTR, "TLS initialization failed\n");
      }
    }

    if(turnserver_cfg_dtls())
    {
      /* TLS over UDP socket */
      speer = tls_peer_new(IPPROTO_UDP, listen_addr, turnserver_cfg_tls_port(),
          turnserver_cfg_ca_file(), turnserver_cfg_cert_file(),
          turnserver_cfg_private_key_file(), NULL);

      if(speer)
      {
        sockets.sock_dtls = speer;
      }
      else
      {
        debug(DBG_ATTR, "DTLS initialization failed\n");
        syslog(LOG_ERR, "DTLS initialization failed");
      }
    }
  }

  if(sockets.sock_tcp == -1 || sockets.sock_udp == -1 ||
     (turnserver_cfg_tls() && !sockets.sock_tls) ||
     (turnserver_cfg_dtls() && !sockets.sock_dtls))
  {
    debug(DBG_ATTR, "Problem creating listen sockets, exiting\n");
    syslog(LOG_ERR, "Problem creating listen sockets");
    g_run = 0;
  }
  else
  {
    g_run = 1;
  }

  /* initialize rand() */
  srand(time(NULL) + getpid());

  /* drop privileges if program runs as root */
  if(geteuid() == 0 && uid_drop_privileges(getuid(), getgid(), geteuid(),
        getegid(), turnserver_cfg_unpriv_user()) == -1)
  {
    debug(DBG_ATTR, "Cannot drop privileges\n");
  }

  debug(DBG_ATTR, "Run with uid_real=%u gid_real=%u uid_eff=%u gid_eff=%u\n",
      getuid(), getgid(), geteuid(), getegid());

  while(g_run)
  {
    if(!g_run)
    {
      break;
    }

    if(g_reinit)
    {
      struct list_head tmp_list;
      INIT_LIST(tmp_list);

      /* map the account in memory */
      if(account_parse_file(&tmp_list, turnserver_cfg_account_file()) == -1)
      {
        debug(DBG_ATTR, "Reload account file failed!\n");
        syslog(LOG_ERR, "Reload account file failed!");
      }
      else
      {
        struct list_head* n2 = NULL;
        struct list_head* get2 = NULL;
        struct allocation_desc* allocation = NULL;

        /* find the removed account and close TURN sessions */
        list_iterate_safe(get, n, &account_list)
        {
          struct account_desc* tmp = list_get(get, struct account_desc, list);
          int found = 0;

          list_iterate_safe(get2, n2, &tmp_list)
          {
            struct account_desc* tmp2 = list_get(get2, struct account_desc,
                list);

            if(!strcmp(tmp->username, tmp2->username) && !strcmp(tmp->realm, tmp2->realm))
            {
              /* found it, try next iteration of account_list */
              found = 1;
              break;
            }
          }

          /* many allocation can used same username */
          if(!found)
          {
            while((allocation = allocation_list_find_username(&allocation_list,
                    tmp->username, tmp->realm)))
            {
              allocation_list_remove(&allocation_list, allocation);
            }
          }
        }

        /* reload successful */
        /* free the account list and copy new list of accounts */
        account_list_free(&account_list);

        memcpy(&account_list, &tmp_list, sizeof(struct list_head));
        /* specific to list_head implementation:
         * The extremities of a list MUST be its pointer
         */
        account_list.next->prev = &account_list;
        account_list.prev->next = &account_list;

        debug(DBG_ATTR, "Reload account file successful!\n");
        syslog(LOG_INFO, "Reload account file successful");

#if 0
        /* print account information */
        list_iterate_safe(get, n, &account_list)
        {
          struct account_desc* tmp = list_get(get, struct account_desc, list);
          printf("%s %s\n", tmp->username, tmp->realm);
        }
#endif
      }

      g_reinit = 0;
    }

    /* avoid signal handling during purge */
    turnserver_block_realtime_signal();

    /* purge lists if needed */
    if(g_expired_allocation_list.next)
    {
      list_iterate_safe(get, n, &g_expired_allocation_list)
      {
        struct allocation_desc* tmp = list_get(get, struct allocation_desc,
            list2);

        /* find the account and decrement allocations */
        struct account_desc* desc = account_list_find(&account_list,
            tmp->username, tmp->realm);
        if(desc)
        {
          desc->allocations--;
          debug(DBG_ATTR, "Account %s, allocations used: %u\n", desc->username,
              desc->allocations);

          /* in case it is a temporary account remove it */
          if(desc->allocations == 0 && desc->is_tmp)
          {
            account_list_remove(&account_list, desc);
          }
        }

        /* remove it from the list of valid allocations */
        debug(DBG_ATTR, "Free an allocation_desc\n");
        LIST_DEL(&tmp->list);
        LIST_DEL(&tmp->list2);
        allocation_desc_free(&tmp);
      }
    }

    if(g_expired_permission_list.next)
    {
      list_iterate_safe(get, n, &g_expired_permission_list)
      {
        struct allocation_permission* tmp =
          list_get(get, struct allocation_permission, list2);

        /* remove it from the list of valid permissions */
        LIST_DEL(&tmp->list);
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_permission\n");
        timer_delete(tmp->expire_timer);
        free(tmp);
      }
    }

    if(g_expired_channel_list.next)
    {
      list_iterate_safe(get, n, &g_expired_channel_list)
      {
        struct allocation_channel* tmp =
          list_get(get, struct allocation_channel, list2);

        /* remove it from the list of valid channels */
        LIST_DEL(&tmp->list);
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_channel\n");
        timer_delete(tmp->expire_timer);
        free(tmp);
      }
    }

    if(g_expired_token_list.next)
    {
      list_iterate_safe(get, n, &g_expired_token_list)
      {
        struct allocation_token* tmp =
          list_get(get, struct allocation_token, list2);

        /* remove it from the list of valid tokens */
        LIST_DEL(&tmp->list);
        LIST_DEL(&tmp->list2);
        debug(DBG_ATTR, "Free an allocation_token\n");
        if(tmp->sock > 0)
        {
          close(tmp->sock);
        }
        allocation_token_free(&tmp);
      }
    }

    list_iterate_safe(get, n, &g_expired_tcp_relay_list)
    {
      struct allocation_tcp_relay* tmp =
        list_get(get, struct allocation_tcp_relay, list2);
      allocation_tcp_relay_list_remove(&g_expired_tcp_relay_list, tmp);
    }

    /* re-enable realtime signal */
    turnserver_unblock_realtime_signal();

    /* wait messages and processing */
    turnserver_main(&sockets, &g_tcp_socket_list, &allocation_list,
        &account_list);
  }

  fprintf(stderr, "\n");
  debug(DBG_ATTR,"Exiting\n");

  syslog(LOG_NOTICE, "TurnServer stop");
  closelog();

  /* avoid signal handling during cleanup */
  turnserver_block_realtime_signal();

  /* free the expired allocation list (warning: special version use ->list2) */
  list_iterate_safe(get, n, &g_expired_allocation_list)
  {
    struct allocation_desc* tmp = list_get(get, struct allocation_desc, list2);

    /* note: don't care about decrementing account, after all program exits */
    LIST_DEL(&tmp->list);
    LIST_DEL(&tmp->list2);
    allocation_desc_free(&tmp);
  }

  list_iterate_safe(get, n, &g_expired_token_list)
  {
    struct allocation_token* tmp =
      list_get(get, struct allocation_token, list2);
    LIST_DEL(&tmp->list);
    LIST_DEL(&tmp->list2);
    if(tmp->sock > 0)
    {
      close(tmp->sock);
    }
    allocation_token_free(&tmp);
  }

  list_iterate_safe(get, n, &g_expired_tcp_relay_list)
  {
    struct allocation_tcp_relay* tmp =
      list_get(get, struct allocation_tcp_relay, list2);
    allocation_tcp_relay_list_remove(&g_expired_tcp_relay_list, tmp);
  }

  /* close UDP and TCP sockets */
  if(sockets.sock_udp > 0)
  {
    close(sockets.sock_udp);
  }

  if(sockets.sock_tcp > 0)
  {
    close(sockets.sock_tcp);
  }

  /* close remote TCP client sockets */
  list_iterate_safe(get, n, &g_tcp_socket_list)
  {
    struct socket_desc* tmp = list_get(get, struct socket_desc, list);
    close(tmp->sock);
    LIST_DEL(&tmp->list);
    free(tmp);
  }

  /* close TLS and DTLS sockets */
  if(turnserver_cfg_tls() || turnserver_cfg_dtls())
  {
    /* close TLS socket */
    if(sockets.sock_tls)
    {
      tls_peer_free(&sockets.sock_tls);
    }

    if(sockets.sock_dtls)
    {
      tls_peer_free(&sockets.sock_dtls);
    }

    /* cleanup SSL lib */
    LIBSSL_CLEANUP;
  }

  /* free the valid allocation list */
  allocation_list_free(&allocation_list);

  /* free the account list */
  account_list_free(&account_list);

  /* free mod_tmpuser */
  if(turnserver_cfg_mod_tmpuser())
  {
    tmpuser_destroy();
  }

  /* free the token list */
  allocation_token_list_free(&g_token_list);

  /* free the denied address list */
  list_iterate_safe(get, n, &g_denied_address_list)
  {
    struct denied_address* tmp = list_get(get, struct denied_address, list);
    LIST_DEL(&tmp->list);
    free(tmp);
  }

  if(turnserver_cfg_daemon())
  {
    turnserver_remove_pidfile(pid_file);
  }

  /* free the configuration parser */
  turnserver_cfg_free();

  return EXIT_SUCCESS;
}

