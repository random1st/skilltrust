@echo off
rem Windows counterpart of the POSIX shim. Claude Code puts bin/ on PATH, and .cmd is what
rem Windows resolves when a hook says `skillctl`.
setlocal
set "here=%~dp0"
if exist "%here%skillctl-windows-amd64.exe" (
  "%here%skillctl-windows-amd64.exe" %*
  exit /b %errorlevel%
)
echo skilltrust: no skillctl build for windows-amd64 in %here% 1>&2
exit /b 0
