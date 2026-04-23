@echo off
setlocal

call "%~dp0resolve-llvm-mingw.cmd" llvm-ar.exe TOOL
if errorlevel 1 exit /b 1

"%TOOL%" %*
