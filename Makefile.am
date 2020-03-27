
#######################################
# The list of libraries we are building separated by spaces.
# The 'lib_' indicates that these build products will be installed
# in the $(libdir) directory. For example /usr/lib
lib_LTLIBRARIES = lib@PACKAGE_NAME@.la

#######################################
# Build information for each library


library_include_aes_mindir=$(includedir)/@PACKAGE_NAME@
library_include_aes_min_HEADERS = aes-min.h gcm-mul.h
lib@PACKAGE_NAME@_la_SOURCES = aes-min.c
lib@PACKAGE_NAME@_la_SOURCES += gcm-mul.c
if ENABLE_SBOX_SMALL
lib@PACKAGE_NAME@_la_CFLAGS = -DENABLE_SBOX_SMALL
endif
lib@PACKAGE_NAME@_la_LDFLAGS = -version-info @LIB_SO_VERSION@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = @PACKAGE_NAME@.pc


#######################################
# Tests

TESTS = aes-sbox-test aes-inv-test aes-key-schedule-test aes-encrypt-test aes-vectors-test gcm-test

check_PROGRAMS = aes-sbox-test aes-inv-test aes-key-schedule-test aes-encrypt-test aes-vectors-test gcm-test

aes_sbox_test_SOURCES = tests/aes-sbox-test.c aes-print-block.h
aes_sbox_test_LDADD = lib@PACKAGE_NAME@.la

aes_inv_test_SOURCES = tests/aes-inv-test.c aes-print-block.h
aes_inv_test_LDADD = lib@PACKAGE_NAME@.la
aes_inv_test_CFLAGS = $(AM_CFLAGS)

aes_key_schedule_test_SOURCES = tests/aes-key-schedule-test.c aes-print-block.h
aes_key_schedule_test_LDADD = lib@PACKAGE_NAME@.la

aes_encrypt_test_SOURCES = tests/aes-encrypt-test.c aes-print-block.h
aes_encrypt_test_LDADD = lib@PACKAGE_NAME@.la

aes_vectors_test_SOURCES = tests/aes-vectors-test.c tests/aes-test-vectors.h aes-print-block.h
aes_vectors_test_LDADD = lib@PACKAGE_NAME@.la

gcm_test_SOURCES = tests/gcm-test.c tests/gcm-test-vectors.c tests/gcm-test-vectors.h gcm-mul.h aes-print-block.h
gcm_test_LDADD = lib@PACKAGE_NAME@.la
