setlocal
@echo off

if exist "simple_test.bat" (
  cd ..
)

cd build

ctest -C Release --output-on-failure

cd ..
