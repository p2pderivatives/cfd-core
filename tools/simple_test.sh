#!/bin/sh
cd `git rev-parse --show-toplevel`

cd build && ctest -C Release --output-on-failure
