
#######################################
# The list of libraries we are building separated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

#######################################
# Build information for each library


library_include_aes_mindir=$(includedir)/@PACKAGE_NAME@-@PACKAGE_VERSION@
library_include_aes_min_HEADERS = aes.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES = aes.c
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += aes-sbox.c aes-mul.c aes-inv.c
#lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += aes-sbox-small.c
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_SOURCES += aes-sbox.h aes-mul.h aes-mul2.h aes-inv.h
lib@PACKAGE_NAME@_@PACKAGE_VERSION@_la_LDFLAGS = -version-info @LIB_SO_VERSION@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc


#######################################
# Tests

TESTS = aes-sbox-test aes-inv-test

check_PROGRAMS = aes-sbox-test aes-inv-test

aes_sbox_test_SOURCES = tests/aes-sbox-test.c  aes-print-block.h
aes_sbox_test_LDADD = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la

aes_inv_test_SOURCES = tests/aes-inv-test.c  aes-print-block.h
aes_inv_test_LDADD = lib@PACKAGE_NAME@-@PACKAGE_VERSION@.la
