@echo off
REM APKSeeker launcher for Windows — setup, scan, test, doctor, build-apk, menu.
REM Pure Python: works on Windows with no Android tools installed.
setlocal
set HERE=%~dp0
if "%1"=="" goto usage
if "%1"=="setup" (
    if not exist "%HERE%venv\Scripts\python.exe" (
        echo [*] Creating virtual environment (first time only)...
        python -m venv "%HERE%venv"
    )
    echo [*] APKSeeker needs no packages (standard library only).
    echo [+] Setup done. Test it: run.bat scan test_apks\test_bad.apk
    exit /b 0
)
if exist "%HERE%venv\Scripts\python.exe" (
    set PY=%HERE%venv\Scripts\python.exe
) else (
    set PY=python
)
if "%1"=="scan" (
    shift
    %PY% "%HERE%apkseeker.py" %*
    exit /b %ERRORLEVEL%
)
if "%1"=="test" (
    %PY% "%HERE%test_apkseeker.py"
    exit /b %ERRORLEVEL%
)
if "%1"=="doctor" (
    %PY% "%HERE%apkseeker.py" --check
    exit /b %ERRORLEVEL%
)
if "%1"=="build-apk" (
    %PY% "%HERE%build_test_apk.py"
    exit /b %ERRORLEVEL%
)
if "%1"=="menu" (
    %PY% "%HERE%apkseeker.py" --menu
    exit /b %ERRORLEVEL%
)
echo [!] Unknown command: %1
:usage
echo Usage: run.bat [setup ^| scan ^<apk^> [flags] ^| test ^| doctor ^| build-apk ^| menu]
exit /b 2
