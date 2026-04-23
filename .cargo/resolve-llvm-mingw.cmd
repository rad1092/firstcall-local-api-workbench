@echo off
setlocal

if "%~1"=="" (
  echo FirstCall tool resolver expected a tool name. 1>&2
  exit /b 1
)

set "TOOL_NAME=%~1"
set "OUT_VAR=%~2"
if not defined OUT_VAR set "OUT_VAR=FOUND_TOOL"
set "FOUND_TOOL="
set "WINGET_ROOT=%LOCALAPPDATA%\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe"

if defined FIRSTCALL_LLVM_MINGW_BIN (
  if exist "%FIRSTCALL_LLVM_MINGW_BIN%\%TOOL_NAME%" (
    set "FOUND_TOOL=%FIRSTCALL_LLVM_MINGW_BIN%\%TOOL_NAME%"
  )
)

if not defined FOUND_TOOL (
  if exist "%WINGET_ROOT%" (
    for /f "delims=" %%D in ('dir /b /ad "%WINGET_ROOT%\llvm-mingw-*" 2^>nul') do (
      if exist "%WINGET_ROOT%\%%D\bin\%TOOL_NAME%" (
        set "FOUND_TOOL=%WINGET_ROOT%\%%D\bin\%TOOL_NAME%"
        goto :found
      )
    )
  )
)

if not defined FOUND_TOOL (
  if exist "%ProgramFiles%\LLVM\bin\%TOOL_NAME%" (
    set "FOUND_TOOL=%ProgramFiles%\LLVM\bin\%TOOL_NAME%"
  )
)

if not defined FOUND_TOOL (
  if exist "%ProgramFiles%\llvm-mingw\bin\%TOOL_NAME%" (
    set "FOUND_TOOL=%ProgramFiles%\llvm-mingw\bin\%TOOL_NAME%"
  )
)

if not defined FOUND_TOOL (
  if exist "%ProgramFiles(x86)%\LLVM\bin\%TOOL_NAME%" (
    set "FOUND_TOOL=%ProgramFiles(x86)%\LLVM\bin\%TOOL_NAME%"
  )
)

if not defined FOUND_TOOL (
  for /f "delims=" %%F in ('where %TOOL_NAME% 2^>nul') do (
    if not defined FOUND_TOOL (
      set "FOUND_TOOL=%%~fF"
      goto :found
    )
  )
)

:found
if not defined FOUND_TOOL (
  echo Could not find %TOOL_NAME%. Install llvm-mingw and either add it to PATH or set FIRSTCALL_LLVM_MINGW_BIN. 1>&2
  exit /b 1
)

endlocal & set "%OUT_VAR%=%FOUND_TOOL%"
exit /b 0
