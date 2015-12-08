TESTS = check_turn check_allocation check_account
check_PROGRAMS = check_turn check_allocation check_account

# TURN messages and attributes unit tests
check_turn_SOURCES = check_turn.c \
											$(top_builddir)/src/turn.h \
											$(top_builddir)/src/protocol.c \
											$(top_builddir)/src/protocol.h \
											$(top_builddir)/src/util_sys.h \
											$(top_builddir)/src/util_sys.c \
											$(top_builddir)/src/util_crypto.h \
											$(top_builddir)/src/util_crypto.c \
											$(top_builddir)/src/tls_peer.h \
											$(top_builddir)/src/tls_peer.c

check_turn_CFLAGS = @CHECK_CFLAGS@
check_turn_LDADD = @CHECK_LIBS@

# allocation unit tests
check_allocation_SOURCES = check_allocation.c \
										 $(top_builddir)/src/allocation.h \
										 $(top_builddir)/src/allocation.c
check_allocation_CFLAGS = @CHECK_CFLAGS@
check_allocation_LDADD = @CHECK_LIBS@

# account unit tests
check_account_SOURCES = check_account.c \
										 $(top_builddir)/src/account.h \
										 $(top_builddir)/src/account.c \
										 $(top_builddir)/src/protocol.h \
										 $(top_builddir)/src/protocol.c \
										 $(top_builddir)/src/util_sys.h \
										 $(top_builddir)/src/util_sys.c \
										 $(top_builddir)/src/util_crypto.h \
										 $(top_builddir)/src/util_crypto.c \
										 $(top_builddir)/src/tls_peer.h \
										 $(top_builddir)/src/tls_peer.c
check_account_CFLAGS = @CHECK_CFLAGS@
check_account_LDADD = @CHECK_LIBS@

