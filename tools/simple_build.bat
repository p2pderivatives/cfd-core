setlocal
@echo off

if exist "simple_build.bat" (
  cd ..
)

CALL cmake -S . -B build -G "Visual Studio 16 2019"

CALL cmake -DENABLE_SHARED=on -DENABLE_TESTS=on -DENABLE_ELEMENTS=on -DCMAKE_BUILD_TYPE=Release --build build

CALL cmake --build build --config Release --parallel 4
