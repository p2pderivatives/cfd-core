TESTS=cfdcore_test
noinst_PROGRAMS=cfdcore_test

# for common
if DEBUG
OPT = -g3 -O0
else
OPT = -O3
endif
CFLAGS= -Wall $(OPT)
CPPFLAGS= $(CFLAGS) -std=c++11
CXXFLAGS= $(CFLAGS) -std=c++11

cfd_all: all

cfd_clean: clean

include Makefile.srclist

if TARGET_WINDOWS
# Windows option
LIB_OPTS= googletest/googletest/lib/.libs/libgtest.a googletest/googletest/lib/.libs/libgtest_main.a \
          googletest/googlemock/lib/.libs/libgmock.a googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lwinpthread -lssp \
           -L../src/hidapi_local/windows/.libs -lhidapi-0 \
           -L../src/libwally/src/.libs -lwallycore-0 \
           -L../src/univalue/.libs -lunivalue-0 \
           -L../src/curl_local/lib/.libs -lcurl-4 \
           -L../src/zlib_local -lz \
           -L../src/.libs -lcfdcore-0
cfdcore_test_CFLAGS_OPT= 
else
if TARGET_DARWIN
# mac option
LIB_OPTS= googletest/googletest/lib/.libs/libgtest.a googletest/googletest/lib/.libs/libgtest_main.a \
          googletest/googlemock/lib/.libs/libgmock.a googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lpthread \
           -L../src/hidapi_local/mac/.libs -lhidapi \
           -L../src/libwally/src/.libs -lwallycore \
           -L../src/univalue/.libs -lunivalue \
           -L../src/curl_local/lib/.libs -lcurl \
           -L../src/zlib_local -lz \
           -L../src/.libs -lcfdcore
cfdcore_test_CFLAGS_OPT=
else
# other(linux, etc.) option
LIB_OPTS= googletest/googletest/lib/.libs/libgtest.a googletest/googletest/lib/.libs/libgtest_main.a \
          googletest/googlemock/lib/.libs/libgmock.a googletest/googlemock/lib/.libs/libgmock_main.a
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lpthread \
           -L"../src/hidapi_local/linux/.libs" -lhidapi-hidraw -L"../src/hidapi_local/libusb/.libs" -lhidapi-libusb \
           -L../src/libwally/src/.libs -lwallycore \
           -L../src/univalue/.libs -lunivalue \
           -L../src/curl_local/lib/.libs -lcurl \
           -L../src/zlib_local -lz \
           -L../src/.libs -lcfdcore
cfdcore_test_CFLAGS_OPT=
endif
endif

# for cfdcore_test
cfdcore_test_LDFLAGS=$(LINK_OPTS)
#cfdcore_test_OBJECTS=$(wildcard src/*.o)
cfdcore_test_LDADD=$(LIB_OPTS)
#cfdcore_test_LIBADD=$(LIB_OPTS)
cfdcore_test_CFLAGS= -I"." -I../include -I../src/include -I../src -I../src/univalue/include \
    -Igoogletest/googlemock/include \
    -Igoogletest/googletest/include \
    $(cfdcore_test_CFLAGS_OPT)
cfdcore_test_CXXFLAGS= $(cfdcore_test_CFLAGS)
cfdcore_test_SOURCES= $(TEST_CFDCORE_SOURCES) $(TEST_CFDCORE_STATIC_SOURCES)


