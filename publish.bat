@echo off
REM Publish script for PyQualify to PyPI and Docker Hub

echo ========================================
echo PyQualify Publish Script
echo ========================================
echo.

REM Check if we're in the correct directory
if not exist pyproject.toml (
    echo ERROR: pyproject.toml not found. Please run this script from the project root directory.
    pause
    exit /b 1
)

REM Get version from pyproject.toml
for /f "tokens=2 delims==" %%a in ('findstr /r "version = " pyproject.toml') do set VERSION=%%a
set VERSION=%VERSION: =%
set VERSION=%VERSION:"=%
echo Current version: %VERSION%
echo.

REM Build and publish to PyPI
echo [1/3] Building package...
python -m build

if errorlevel 1 (
    echo ERROR: Failed to build package
    pause
    exit /b 1
)

echo.
echo [2/3] Publishing to PyPI...
twine upload dist/*

if errorlevel 1 (
    echo ERROR: Failed to publish to PyPI
    pause
    exit /b 1
)

echo.
echo [3/3] Building and pushing Docker image...
docker build -t enzox0/pyqualify:%VERSION% -t enzox0/pyqualify:latest .

if errorlevel 1 (
    echo ERROR: Failed to build Docker image
    pause
    exit /b 1
)

docker push enzox0/pyqualify:%VERSION%
docker push enzox0/pyqualify:latest

if errorlevel 1 (
    echo ERROR: Failed to push Docker image
    pause
    exit /b 1
)

echo.
echo ========================================
echo Publish complete!
echo ========================================
echo.
echo - PyPI package published
echo - Docker images pushed:
echo   * enzox0/pyqualify:%VERSION%
echo   * enzox0/pyqualify:latest
echo.
pause
