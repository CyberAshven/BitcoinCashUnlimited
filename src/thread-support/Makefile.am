ACLOCAL_AMFLAGS = -I build-aux/m4

include_HEADERS = \
	include/promotable_shared_mutex.h \
	include/recursive_shared_mutex.h

libthreadsupport_la_SOURCES = \
	lib/promotable_shared_mutex.cpp \
	lib/recursive_shared_mutex.cpp \
	$(include_HEADERS)

libthreadsupport_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libthreadsupport_la_CPPFLAGS = $(AM_CPPFLAGS)
libthreadsupport_la_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/include

lib_LTLIBRARIES = libthreadsupport.la

CLEANFILES = lib/*.gcda lib/*.gcno

if ENABLE_TESTS
bin_PROGRAMS = test/test_threadsupport
TEST_BINARY = test/test_threadsupport$(EXEEXT)

test_test_threadsupport_SOURCES = \
	test/test_threadsupport.cpp \
	test/psm_promotion_tests.cpp \
	test/psm_simple_tests.cpp \
	test/psm_starvation_tests.cpp \
	test/rsm_promotion_tests.cpp \
	test/rsm_simple_tests.cpp \
	test/rsm_starvation_tests.cpp \
	test/test_threadsupport.h \
	test/timer.cpp \
	test/timer.h \
	$(libthreadsupport_la_SOURCES)

test_test_threadsupport_CPPFLAGS = $(AM_CPPFLAGS) $(BOOST_CPPFLAGS) $(TESTDEFS)
test_test_threadsupport_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/include -pthread
test_test_threadsupport_LDFLAGS = -static $(LIBTOOL_APP_LDFLAGS)
test_test_threadsupport_LDADD = $(BOOST_LIBS)

CLEAN_THREADSUPPORT_TEST = test/*.gcda test/*.gcno

CLEANFILES += $(CLEAN_THREADSUPPORT_TEST)

threadsupport_test: $(TEST_BINARY)

threadsupport_test_check: $(TEST_BINARY) FORCE
	$(MAKE) check-TESTS TESTS=$^

threadsupport_test_clean : FORCE
	rm -f $(CLEAN_THREADSUPPORT_TEST) $(TEST_BINARY)
endif

dist_noinst_SCRIPTS = autogen.sh
