#!/bin/sh
cd `git rev-parse --show-toplevel`

clang-format -i --style=file src/*.cpp src/*.h src/include/cfdcore/*.h include/cfdcore/*.h
