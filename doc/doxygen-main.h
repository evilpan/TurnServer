/**
 * \file doxygen-main.h
 * \brief Documentation main page.
 * \author Sebastien Vincent
 * \date 2008-2010
 */

/**
 * \mainpage TurnServer Documentation
 *
 * \section section-intro Introduction
 *
 * This is the API documentation of TurnServer, an open-source implementation of
 * RFC5766 "Traversal Using Relay NAT (TURN)".
 *
 * The TURN protocol allows a client to obtain IP addresses and ports from such
 * a relay. It is most useful for elements behind symmetric NATs or firewalls
 * that wish to be on the receiving end of a connection to a single peer.
 *
 * TURN clients can connect to TurnServer with the following protocols: UDP, TCP
 * and TLS over TCP. Experimental DTLS support is also provided. Relaying data
 * can be done with UDP or TCP protocol.
 *
 * TurnServer supports also RFC5389 (STUN Binding request), RFC6062 (relay data
 * with TCP protocol) and RFC6156 (relay IPv6-IPv6, IPv4-IPv6 and IPv6-IPv4).
 *
 * \section section-modules Modules
 *
 * The API is decomposed in several modules:
 * - STUN/TURN headers and attributes (turn.h);
 * - Header/attribute generation (protocol.c, protocol.h);
 * - Allocation management (allocation.c, allocation.h);
 * - Account management (account.c, account.h);
 * - Server configuration parsing (conf.c, conf.h);
 * - Asynchronous Transport Layer Security (TLS) (tls_peer.c, tls_peer.h);
 * - Some utils functions (dbg.c, dbg.h, util_sys.c, util_sys.h, util_crypto.c,
 *   util_crypto.h, list.h).
 *
 * There are basics unit tests in test directory of source tree. Note that you
 * have to install <a href="http://check.sourceforge.net/">check</a> framework
 * in order to use it.
 *
 * We provide also a "test" client application (test_turn_client) that can
 * generate a suite of TURN packets (Allocate request, wait for an answer,
 * Refresh requests, ...) using the modules above. It can connect to TURN server
 * with UDP, TCP, TLS over TCP or DTLS.
 *
 * Note that TurnServer uses <a href="http://www.openssl.org/">OpenSSL</a>
 * (for cryptographics and TLS stuff) and
 * <a href="http://www.nongnu.org/confuse/">Confuse</a> (for parsing
 * configuration file), so you need to have these libraries on your system.
 *
 * \section section-standard Standards
 *
 * TurnServer is written in C language which respects the following standards:
 * - ISO/IEC 9899 (C99);
 * - IEEE 1003.1 (POSIX).
 *
 * It also uses some realtime capabilities of POSIX.1b. Thus systems have to
 * support these standards and capabilities to compile and use TurnServer.
 *
 * TurnServer is known to run on the following systems:
 * - GNU/Linux 2.6;
 * - FreeBSD 7.x, 8.
 *
 * \section section-license License
 *
 * TurnServer is licensed under the
 * <a href="http://www.gnu.org/licenses/gpl-3.0.html">GPL version 3</a> (with an
 * exception for OpenSSL).
 *
 */

