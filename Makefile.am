# Adding doxygen support
include aminclude.am

SUBDIRS = src man test doc
SUBDIRS += extra

EXTRA_DIST = Doxyfile aminclude.am	acinclude.m4
EXTRA_DIST += LICENSE
EXTRA_DIST += LICENSE.OpenSSL

# valgrind
valgrind-run:
	@echo 'Running with valgrind'
	valgrind --leak-check=full --show-reachable=yes $(top_builddir)/src/turnserver -c $(top_builddir)/extra/turnserver.conf

