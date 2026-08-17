@echo off
rem Auto-Shark GUI launcher for Windows desktops.
rem Requires: Python 3.11, an Auto-Shark install with the gui extra, and TShark.
rem Optional: set AUTO_SHARK_TSHARK to your tshark.exe before launching.

where auto-shark >nul 2>nul
if errorlevel 1 (
    echo error: auto-shark is not on PATH. Install it first:
    echo   pipx install "auto-shark[gui]"
    exit /b 2
)
auto-shark gui %*
