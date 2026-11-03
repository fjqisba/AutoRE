@echo off
rem Double-click starts the PowerShell launcher; arguments are forwarded unchanged.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-IdaMcp.ps1" %*
if errorlevel 1 pause
