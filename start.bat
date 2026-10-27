@echo off
rem Double-click to start the dashboard. Runs start.ps1 without changing PowerShell's script policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
