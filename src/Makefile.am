AM_CFLAGS = -std=c99 -Wall -Wextra -Werror -Wstrict-prototypes -Wredundant-decls -Wshadow -pedantic -fno-strict-aliasing -D_POSIX_C_SOURCE=200112L -D_XOPEN_SOURCE=600 -O2 -D_SVID_SOURCE

if ENABLE_DEBUG_BUILD
AM_CFLAGS += -g 
else
AM_CFLAGS += -DNDEBUG
endif

INCLUDE = -I.
sbin_PROGRAMS = turnserver
bin_PROGRAMS = test_turn_client test_echo_server
noinst_HEADERS = turnserver.h \
								 turn.h \
								 protocol.h \
								 dbg.h \
								 util_sys.h \
								 util_crypto.h \
								 list.h \
								 tls_peer.h \
								 allocation.h \
								 account.h \
								 conf.h \
								 mod_tmpuser.h

turnserver_SOURCES = turnserver.c \
										 protocol.c \
										 dbg.c \
										 util_sys.c \
										 util_crypto.c \
										 tls_peer.c \
										 allocation.c \
										 account.c \
										 conf.c \
										 mod_tmpuser.c

test_turn_client_SOURCES = test_turn_client.c \
											protocol.c \
											util_crypto.c \
											tls_peer.c \
											util_sys.c

test_echo_server_SOURCES = test_echo_server.c \
													 tls_peer.c

valgrind-run:
	@echo 'Running with valgrind'
	valgrind --leak-check=full --show-reachable=yes $(top_builddir)/src/turnserver -c $(top_builddir)/extra/turnserver.conf

