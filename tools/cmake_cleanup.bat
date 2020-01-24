setlocal
@echo off

if exist "cmake_cleanup.bat" (
  cd ..
)

rmdir /S /Q build

rmdir /S /Q external\libwally-core

