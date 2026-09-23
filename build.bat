@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
title CleanIP Builder
cd /d "%~dp0"

where go >nul 2>&1
if errorlevel 1 (
    echo [X] Go is not installed.
    pause
    exit /b 1
)

echo [1/4] go mod tidy...
go mod tidy >nul 2>&1
echo [2/4] Cleaning...
if exist cleanip.exe del /f /q cleanip.exe
echo [3/4] Building...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags="-s -w -H windowsgui" -o cleanip.exe .
if errorlevel 1 (
    echo [X] Build FAILED.
    pause
    exit /b 1
)
echo [4/4] Done: cleanip.exe
pause
