#!/bin/sh

rm -rf /usr/local/include/wally.hpp /usr/local/include/wally_*.h /usr/local/include/secp256k1*.h
rm -rf /usr/local/include/cfdcore /usr/local/include/univalue.h
rm -rf /usr/local/include/cfd /usr/local/include/cfdc
rm -rf /usr/local/lib/libwally.* /usr/local/lib/libwallycore.*
rm -rf /usr/local/lib/libcfdcore.* /usr/local/lib/libunivalue.*
rm -rf /usr/local/lib/libcfd.*
rm -rf /usr/local/lib/pkgconfig/wallycore.pc /usr/local/lib/pkgconfig/wally.pc
rm -rf /usr/local/lib/pkgconfig/libunivalue.pc /usr/local/lib/pkgconfig/libunivalue-uninstalled.pc
rm -rf /usr/local/lib/pkgconfig/univalue.pc /usr/local/lib/pkgconfig/univalue-uninstalled.pc
rm -rf /usr/local/lib/pkgconfig/cfd.pc /usr/local/lib/pkgconfig/cfd-core.pc
rm -rf /usr/local/cmake/cfd*.cmake /usr/local/cmake/univalue-*.cmake
rm -rf /usr/local/cmake/wally-*.cmake /usr/local/cmake/wallycore-*.cmake
