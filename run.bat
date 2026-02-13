@echo off
if not exist "%~dp0run.ps1" (
  echo [Runner] run.ps1 not found in "%~dp0"
  exit /b 1
)
powershell -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
