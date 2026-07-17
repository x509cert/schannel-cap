@echo off
REM Build the standalone Schannel ETW consumer. No Detours, no arch-matching --
REM ETW is out-of-process, so any arch build captures every process.
REM Run from a VS Native Tools prompt, or just have cl on PATH.
setlocal
pushd "%~dp0"

where cl >nul 2>nul || (echo [!] cl not on PATH - open a VS Native Tools prompt & popd & exit /b 1)

cl /nologo /O2 /MT /W4 /GS /guard:cf /Qspectre /sdl /std:c++20 /permissive- /EHsc /D_CRT_SECURE_NO_WARNINGS schannel_etw.cpp /Fe"schannel_etw.exe" /link /DYNAMICBASE /NXCOMPAT /guard:cf tdh.lib advapi32.lib iphlpapi.lib ws2_32.lib
if errorlevel 1 (echo [!] schannel_etw build FAILED & popd & exit /b 1)

cl /nologo /O2 /MT /W3 /D_CRT_SECURE_NO_WARNINGS tls_group.c /Fe"tls_group.exe"
if errorlevel 1 (echo [!] tls_group build FAILED & popd & exit /b 1)

del /q *.obj 2>nul
echo === OK: schannel_etw.exe  tls_group.exe
popd
