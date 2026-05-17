@echo off
:: setup-githooks.bat
:: Configures Git to use the .githooks directory for this repository.
:: Run this once after cloning: setup-githooks.bat

setlocal

echo.
echo [setup-githooks] Configuring Git hooks directory...

:: Verify we are inside a Git repository
git rev-parse --git-dir >nul 2>&1
if errorlevel 1 (
    echo [setup-githooks] ERROR: Not inside a Git repository.
    echo                  Run this script from the root of the pyqualify repo.
    exit /b 1
)

:: Point Git at the .githooks folder
git config core.hooksPath .githooks
if errorlevel 1 (
    echo [setup-githooks] ERROR: Failed to set core.hooksPath.
    exit /b 1
)

echo [setup-githooks] core.hooksPath set to .githooks

:: On Windows, Git runs hook scripts through sh.exe (Git Bash / MSYS2).
:: The files do not need the executable bit set, but we verify they exist.
echo.
echo [setup-githooks] Verifying hook files...

set HOOKS=pre-commit commit-msg pre-push prepare-commit-msg
set MISSING=0

for %%H in (%HOOKS%) do (
    if exist ".githooks\%%H" (
        echo   [OK] .githooks\%%H
    ) else (
        echo   [MISSING] .githooks\%%H
        set MISSING=1
    )
)

if "%MISSING%"=="1" (
    echo.
    echo [setup-githooks] WARNING: One or more hook files are missing.
    echo                  Make sure you have the full .githooks directory.
) else (
    echo.
    echo [setup-githooks] All hooks are in place.
)

echo.
echo [setup-githooks] Done. Git hooks are active for this repository.
echo.

endlocal
