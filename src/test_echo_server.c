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
 * \file test_echo_server.c
 * \brief Simple UDP echo server.
 * \author Sebastien Vincent
 * \date 2008-2009
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "tls_peer.h"

/**
 * \var g_run
 * \brief Running state of the program.
 */
static volatile sig_atomic_t g_run = 0;

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
 * \brief Entry point of the program.
 * \param argc number of argument
 * \param argv array of arguments
 * \return EXIT_SUCCESS or EXIT_FAILURE
 */
int main(int argc, char** argv)
{
  int sock = -1;
  struct sockaddr_storage addr;
  socklen_t addr_size = sizeof(struct sockaddr_storage);
  char buf[2500];
  ssize_t nb = -1;
  uint16_t port = 0;

  (void)argc; /* avoid compilation warning */

  signal(SIGUSR1, signal_handler);
  signal(SIGUSR2, signal_handler);
  signal(SIGPIPE, signal_handler);
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  port = argv[1] ? atol(argv[1]) : 4588;

  /* incorrect value */
  if(port == 0)
  {
    port = 4588;
  }

  /* try to bind on all addresses (IPv6+IPv4 mode) */
  sock = socket_create(IPPROTO_UDP, "::", port, 0, 0);

  if(sock == -1)
  {
    perror("socket");
    fprintf(stderr, "Maybe IPv6 is not available, try IPv4 only mode\n");
    sock = socket_create(IPPROTO_UDP, "0.0.0.0", port, 0, 1);
  }

  if(sock == -1)
  {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  memset(&addr, 0x00, sizeof(struct sockaddr));
  memset(buf, 0x00, sizeof(buf));

  g_run = 1;

  fprintf(stdout, "UDP Echo server started on port %u\n", port);

  while(g_run)
  {
    fd_set fdsr;
    int nsock = sock;

    FD_ZERO(&fdsr);
    FD_SET(sock, &fdsr);

    nsock++;

    if(select(nsock, &fdsr, NULL, NULL, NULL) > 0)
    {
      if(FD_ISSET(sock, &fdsr))
      {
        nb = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&addr,
            &addr_size);
      }
    }
    else
    {
      perror("select");
      continue;
    }

    if(nb)
    {
      /* echo data received */
      if(sendto(sock, buf, nb, 0, (struct sockaddr*)&addr, addr_size) == -1)
      {
        perror("sendto");
      }
    }
    else
    {
      perror("recvfrom");
    }
  }

  close(sock);

  fprintf(stdout, "Exiting\n");

  return EXIT_SUCCESS;
}

