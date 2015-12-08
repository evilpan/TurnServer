dist_man1_MANS = turnserver.man
dist_man5_MANS = turnserver.conf.man
BUILT_SOURCES = $(dist_man1_MANS) $(dist_man5_MANS)
CLEANFILES = $(dist_man1_MANS) $(dist_man5_MANS)
EXTRA_DIST=turnserver.tmpl turnserver.conf.tmpl

turnserver.man: turnserver.tmpl
	$(SED) -e 's#%DATE%#@PACKAGE_DATE@#' \
		-e 's#%VERSION%#@PACKAGE_VERSION@#' \
		-e 's#%etc%#@sysconfdir@#' $< > $@

turnserver.conf.man: turnserver.conf.tmpl
	$(SED) -e 's#%DATE%#@PACKAGE_DATE@#' \
		-e 's#%VERSION%#@PACKAGE_VERSION@#' \
		-e 's#%etc%#@sysconfdir@#' $< > $@

