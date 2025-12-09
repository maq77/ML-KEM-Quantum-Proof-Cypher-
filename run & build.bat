
---

## 3️⃣ Auto build & run script: `run_mlkem_gui.bat`

Create `run_mlkem_gui.bat` in the **project root (ML-KEM)**:

```bat
@echo off
setlocal

REM ------------------------------------------------------------------
REM Auto-build ML-KEM-512 C++ DLL and run the Python GUI
REM ------------------------------------------------------------------

REM Go to the directory where this script is located (project root)
cd /d "%~dp0"

echo [INFO] Project root: %CD%

REM Check that cpp directory exists
if not exist "cpp" (
    echo [ERROR] 'cpp' folder not found. Make sure this script is in the ML-KEM project root.
    goto end
)

REM ------------------------------------------------------------------
REM 1) Build ML-KEM-512 DLL
REM ------------------------------------------------------------------
echo [1/3] Building ML-KEM-512 C++ library (mlkem512.dll)...

cd cpp

REM Assumes g++ is in PATH (e.g., C:\mingw64\bin)
g++ -std=c++20 -O2 -shared ^
 -I ./include ^
 -I ./include/ml_kem ^
 -I ./include/sha3 ^
 -I ./include/subtle ^
 -I ./include/randomshake ^
 src/mlkem_512_c_api.cpp ^
 -o mlkem512.dll

if errorlevel 1 (
    echo [ERROR] C++ build failed. Check your g++ installation and include paths.
    cd ..
    goto end
)

cd ..

echo [2/3] C++ library built successfully: cpp\mlkem512.dll

REM ------------------------------------------------------------------
REM 2) Run the Python GUI
REM ------------------------------------------------------------------
echo [3/3] Starting Python GUI...
echo.

python main.py

if errorlevel 1 (
    echo [ERROR] Python exited with an error. Check the traceback above.
    goto end
)

:end
echo.
echo Done.
pause
endlocal
