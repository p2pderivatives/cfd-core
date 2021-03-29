@echo off

if exist "format.bat" (
  cd ..
)

call clang-format -i --style=file src/*.cpp src/*.h src/include/cfdcore/*.h include/cfdcore/*.h
