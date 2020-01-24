#!/bin/sh
cd `git rev-parse --show-toplevel`

rm -rf build
rm -rf external/libwally-core
rm -rf external/googletest
