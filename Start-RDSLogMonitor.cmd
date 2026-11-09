@echo off
rem Launches RDS Log Monitor without a console window. The script asks for elevation if needed.
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0RDSLogMonitor.ps1"
