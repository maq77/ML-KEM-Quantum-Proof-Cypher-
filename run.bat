@echo off
setlocal

REM -------------------------------------------------------
REM Run ML-KEM-512 Quantum-Safe GUI (NO BUILD REQUIRED)
REM Assumes mlkem512.dll is already inside cpp/
REM -------------------------------------------------------

cd /d "%~dp0"

echo ============================================
echo   ML-KEM-512 Quantum-Safe Encryption Demo
echo ============================================
echo.

REM --- Check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

REM --- Check DLL ---
if not exist "cpp\mlkem512.dll" (
    echo [ERROR] cpp\mlkem512.dll not found.
    echo The project was shared without the pre-built DLL.
    echo Please ask for the full version with the DLL included.
    pause
    exit /b 1
)

REM --- Run the GUI ---
echo [INFO] Starting ML-KEM GUI...
echo.

python main.py

echo.
echo [INFO] Application closed.
pause
endlocal
