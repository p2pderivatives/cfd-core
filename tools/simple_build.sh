#!/bin/sh
cd `git rev-parse --show-toplevel`

cmake -S . -B build -G "Unix Makefiles"

cmake -DENABLE_SHARED=off -DENABLE_TESTS=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Release -DTARGET_RPATH=./build/Release --build build

cmake --build build --config Release --parallel 4
