noinst_LTLIBRARIES =
lib_LTLIBRARIES = libcfdcore.la

# for common
if DEBUG
OPT = -g3 -O0
else
OPT = -O3
endif
CFLAGS= -Wall -Wextra $(OPT)
CPPFLAGS= $(CFLAGS) -std=c++11
CXXFLAGS= $(CFLAGS) -std=c++11

cfd_all: all

cfd_clean: clean

include Makefile.srclist

# include_HEADERS = $(CFDCORE_INCLUDE_HEADERS)

if TARGET_WINDOWS
# Windows(MinGW) option
LINK_OPTS= -fstack-protector -static -lstdc++ -lgcc -lwinpthread -lssp
cfdcore_CFLAGS_OPT=
if SHARED_BUILD_ENABLED
cfdcore_LDFLAGS_OPT= -shared -no-undefined
else
cfdcore_LDFLAGS_OPT= -no-undefined
endif
LIB_OPTS = -L"libwally/src/.libs" -lwallycore-0 -L"univalue/.libs" -lunivalue-0
else
if TARGET_DARWIN
# mac option
LINK_OPTS= -fstack-protector -lstdc++ -lgcc -lpthread
cfdcore_CFLAGS_OPT=
cfdcore_LDFLAGS_OPT=
LIB_OPTS = -L"libwally/src/.libs" -lwallycore -L"univalue/.libs" -lunivalue
else
# other(linux, etc.) option
LINK_OPTS= -fstack-protector -lstdc++ -lgcc -lpthread
cfdcore_CFLAGS_OPT=
cfdcore_LDFLAGS_OPT=
LIB_OPTS = -L"libwally/src/.libs" -lwallycore -L"univalue/.libs" -lunivalue
endif
endif

# libwally support. (wally_tx_input/wally_tx_output size changed by BUILD_ELEMENTS macro)
if BUILD_ELEMENTS
BUILD_ELEMENTS_OPT= -DBUILD_ELEMENTS=1
else
BUILD_ELEMENTS_OPT=
endif

# for cfdcore
libcfdcore_la_LDFLAGS= $(cfdcore_LDFLAGS_OPT) $(LINK_OPTS)
#libcfdcore_la_LDADD=$(LIB_OPTS)
#libcfdcore_la_LDADD = $(noinst_LTLIBRARIES)
libcfdcore_la_LIBADD=$(LIB_OPTS)
libcfdcore_la_CFLAGS= -DCFD_CORE_BUILD=1 $(BUILD_ELEMENTS_OPT) \
    -I"../include" -I"./include" -I"." \
    -I"libwally/include" -I"libwally/src/secp256k1/include" -I"univalue/include" \
    $(cfdcore_CFLAGS_OPT) $(AM_CFLAGS)
libcfdcore_la_CXXFLAGS= $(libcfdcore_la_CFLAGS)
libcfdcore_la_SOURCES= $(CFDCORE_SOURCES)

