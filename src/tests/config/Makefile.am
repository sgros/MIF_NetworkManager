AM_CPPFLAGS = \
	-I$(top_srcdir)/shared \
	-I$(top_builddir)/shared \
	-I$(top_srcdir)/libnm-core \
	-I$(top_builddir)/libnm-core \
	-I$(top_srcdir)/src/ \
	-I$(top_srcdir)/src/devices \
	-I${top_srcdir}/src/platform \
	-I${top_srcdir}/src/netns \
	-DG_LOG_DOMAIN=\""NetworkManager"\" \
	-DNETWORKMANAGER_COMPILATION=NM_NETWORKMANAGER_COMPILATION_INSIDE_DAEMON \
	-DNM_VERSION_MAX_ALLOWED=NM_VERSION_NEXT_STABLE \
	$(GLIB_CFLAGS) \
	-DSRCDIR=\""$(srcdir)"\" \
	-DBUILDDIR=\""$(builddir)"\"

noinst_PROGRAMS = \
	test-config

test_config_SOURCES = \
	nm-test-device.c \
	nm-test-device.h \
	test-config.c

test_config_LDADD = \
	$(top_builddir)/src/libNetworkManager.la

@VALGRIND_RULES@
TESTS = test-config

EXTRA_DIST = \
	NetworkManager.conf \
	bad.conf \
	global-dns-invalid.conf \
	conf.d/00-overrides.conf \
	conf.d/10-more.conf \
	conf.d/20-config-enable-1.conf \
	conf.d/90-last.conf
