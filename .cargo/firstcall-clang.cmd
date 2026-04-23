@echo off
setlocal

call "%~dp0resolve-llvm-mingw.cmd" x86_64-w64-mingw32-clang.exe TOOL
if errorlevel 1 exit /b 1

"%TOOL%" %*
