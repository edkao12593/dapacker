@echo off
setlocal enabledelayedexpansion
pushd "%~dp0"

echo [regenstub] Ensuring folders...
if not exist ".\bin"        mkdir ".\bin"
if not exist ".\obj\stub"   mkdir ".\obj\stub"

set "VSCMD="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
    if exist "%%I\Common7\Tools\VsDevCmd.bat" set "VSCMD=%%I\Common7\Tools\VsDevCmd.bat"
  )
)

if not defined VSCMD (
  for %%E in (Community Professional Enterprise) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\Tools\VsDevCmd.bat" (
      set "VSCMD=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\Tools\VsDevCmd.bat"
    )
  )
)
if not defined VSCMD (
  for %%E in (Community Professional Enterprise) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%E\Common7\Tools\VsDevCmd.bat" (
      set "VSCMD=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%E\Common7\Tools\VsDevCmd.bat"
    )
  )
)

if defined VSCMD (
  echo [regenstub] Using VS env: "%VSCMD%"
  call "%VSCMD%" -arch=x64
) else (
  echo [regenstub] WARNING: VsDevCmd.bat not found. Will rely on current environment PATH...
)

where cl >nul 2>nul
if errorlevel 1 (
  echo [regenstub] ERROR: cl.exe not found.
  echo          -> Please run this from "x64 Native Tools Command Prompt for VS"
  echo             or install the "Desktop development with C++" workload.
  popd
  exit /b 1
)

chcp 65001 >nul

echo [regenstub] Compiling stub_template.exe ...
cl /nologo /EHsc /O2 /utf-8 /std:c++17 ^
  /Fo".\obj\stub\\" /Fd".\obj\stub\vc.pdb" ^
  stub_main.cpp aesgcm.cpp ^
  /Fe:".\bin\stub_template.exe" ^
  /link /SUBSYSTEM:WINDOWS /INCREMENTAL:NO Bcrypt.lib Shell32.lib User32.lib
if errorlevel 1 (
  echo [regenstub] ERROR: Stub build failed.
  popd
  exit /b 2
)

echo [regenstub] Emitting stub_bytes.h from bin\stub_template.exe ...
set "TMPPS=%TEMP%\stub2h_%RANDOM%.ps1"
> "%TMPPS%" echo param([string]$In=".\bin\stub_template.exe",[string]$Out="stub_bytes.h")
>>"%TMPPS%" echo $b=[IO.File]::ReadAllBytes($In)
>>"%TMPPS%" echo $hex = ($b ^| ForEach-Object { "0x{0:X2}" -f $_ }) -join ", "
>>"%TMPPS%" echo @(
>>"%TMPPS%" echo   '#pragma once'
>>"%TMPPS%" echo   "static const unsigned char STUB[] = { $hex };"
>>"%TMPPS%" echo   "static const size_t STUB_SIZE = $($b.Length);"
>>"%TMPPS%" echo ) ^| Set-Content -Encoding UTF8 $Out
powershell -NoProfile -ExecutionPolicy Bypass -File "%TMPPS%"
set ERRCODE=%ERRORLEVEL%
del /q "%TMPPS%" >nul 2>nul
if not %ERRCODE%==0 (
  echo [regenstub] ERROR: Failed to generate stub_bytes.h
  popd
  exit /b 3
)

echo [regenstub] Done: .\bin\stub_template.exe and .\stub_bytes.h
popd
exit /b 0
