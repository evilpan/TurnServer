TurnServer
==========
A fork from [http://turnserver.sourceforge.net](http://turnserver.sourceforge.net/index.php?n=Main.HomePage)

TurnServer is an open-source implementation of Traversal Using Relays around NAT
(TURN) protocol. It aims to be compliant with RFC5766 (TURN) and RFC5389 (STUN).

The TURN protocol allows a client to obtain IP addresses and ports from such a
relay. It is most useful for elements behind symmetric NATs or firewalls that
wish to be on the receiving end of a connection to a single peer.

TURN clients can connect to TurnServer with the following protocols: UDP, TCP
and TLS over TCP. Experimental DTLS support is also provided. Relaying data can
be done with UDP or TCP protocol.

TurnServer supports also RFC5389 (STUN Binding request), RFC6062 (relay data
with TCP protocol) and RFC6156 (relay IPv6-IPv6, IPv4-IPv6 and IPv6-IPv4).

TurnServer is known to work on the following systems:
- GNU/Linux 2.6;
- FreeBSD 7.x, 8.x.

1) Build / install
------------------

TurnServer requires following libraries:
- libconfuse development files (version >= 2.6);
- libssl development files;
- librt (normally included in Linux and *BSD distribution*).

TurnServer is written in pure C according to the C99 and POSIX + XSI standards.
Thus it should be compiled on all POSIX systems which have realtime signals
support.

Note for *BSD* users, install the required libconfuse ports in /usr/ prefix,
otherwise you have to set the PKG_CONFIG_PATH variable or make symlinks before
running ./configure script:

    ln -sf /usr/local/lib/libconfuse.so /usr/lib/ && \
    ln -sf /usr/local/include/confuse.h /usr/include/

To build TurnServer, run following commands:

    $ autoreconf -i
    $ ./configure
    $ make
    $ make install

./configure can take options:

    --enable-debug-build                 : allow to compile with debug informations
                                           default=no
    --enable-fdsetsize=number            : allow to preconfigure FD_SETSIZE macro
                                           (must be a number >=32) default=no
    --enable-xor-peer-address-max=number : allow to preconfigure
                                           XOR_PEER_ADDRESS_MAX macro (must be a
                                           number > 0) default=5

Copy the template configuration file (extra/turnserver.conf.template) and
template accounts database file (extra/turnusers.txt) to a directory of your
choice (i.e. /etc/ or /usr/local/etc/).
Do not forget, the accounts database file pathname has to be populated in
configuration file (attribute account_file). See next sections to know how to
setup configuration and accounts files.

To generate the API documentation:

    $ make doxygen-run

The HTML generated documentation is located in doc/html/ directory of TurnServer sources.

Launch the server:

    $ turnserver -c /path/to/config/file

2) Configuration file
---------------------

In extra/ directory you will find a configuration template file
(turnserver.conf.template). Change settings according to your environment.

Here are important parameters,
- listen_address        : public IPv4 address;
- listen_addressv6      : public IPv6 address;
- realm                 : realm (i.e. domain.org) of the server;
- account_file          : specify the location of the accounts database file;
- tcp_port and udp_port : bind the service on the specified port;
- tls                   : enable TLS support;
- tls_port              : bind the secure service on the specified port.
- ca_file               : Certification Authority (must set if tls = true)
- cert_file             : server certificate (must set if tls = true)
- private_key_file      : server private key (must set if tls = true)
- turn_tcp              : enable TURN-TCP extension
- tcp_buffer_userspace  : enable userspace buffering for TURN-TCP extension, if
                          false OS buffering will be used
- tcp_buffer_size       : maximum amount of bytes that can be buffered for
                          TURN-TCP (RFC6062) extension

Other parameters such as allocations number quota or experimental features are
documented in manpages:

    $ man turnserver.conf

3) Accounts database file
--------------------------

TurnServer uses (for the moment) a basic text file which contains accounts
information.

The format of each line is:

    login:password:realm:state

The state can be "authorized", "refused" or "restricted". The "restricted" state
means the account has bandwidth restrictions.

Note: realm have to match realm parameter defined in TurnServer configuration
file. The ":" character is also forbidden in login, password or realm fields.

4) Security
------------

If TurnServer is launched as root or set-uid root, it is possible to drop
privileges.

One possibility is to create a special user (which have less privileges). To
create such a user named turnserver:

    adduser --system --group turnserver

Then you have to tell configuration file to choose this user:

    unpriv_user = turnserver

If TurnServer is set-uid root and unpriv_user is not set, TurnServer will drop
privileges to the user who launched the binary.

**Note**: if turnserver is launched as root and unpriv_user not set, the program
will not loose its root privileges.

5) How-to test simply turnserver
--------------------------------

TurnServer is shipped with two test tools: test_turn_client and 
test_echo_server. The first one is a minimal TURN client and test_echo_server
is a simple UDP echo server.

To test TurnServer simply:
- configure turnserver.conf;
- configure turnusers.txt ;
- launch "turnserver -c /path/to/turnserver.conf";
- launch "test_echo_server 8086";
- launch "test_turn_client -t udp -s turnserver_address -p turnserver_address -w 8086 -u user -g password -d domain.org".

The turnserver_address parameter should be the address configured in
turnserver.conf's listen_address or listen_addressv6. if you want to use
localhost here, you should configure listen_address to 127.0.0.1 _and_ 
listen_addressv6 to ::1. The user, password and domain.org parameters are the
ones from turnusers.txt.

It is not necessary to run the server and the test tools on different computers
but it is recommended just to be sure everything work as in real use-case.

