@echo off
setlocal
cd /d "%~dp0"

set "PYTHON_CMD="
where py >nul 2>nul && set "PYTHON_CMD=py -3"
if not defined PYTHON_CMD where python >nul 2>nul && set "PYTHON_CMD=python"

if not defined PYTHON_CMD (
    echo Python non e stato trovato.
    echo Installalo da https://www.python.org/downloads/ abilitando "Add Python to PATH".
    pause
    exit /b 1
)

if not exist "auracrack2.py" (
    echo Il file auracrack2.py non e presente in questa cartella.
    pause
    exit /b 1
)

%PYTHON_CMD% -c "import customtkinter, scapy, psutil" >nul 2>nul
if errorlevel 1 (
    echo Installazione delle dipendenze necessarie...
    %PYTHON_CMD% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo Impossibile installare le dipendenze.
        pause
        exit /b 1
    )
)

%PYTHON_CMD% auracrack2.py
if errorlevel 1 (
    echo.
    echo AuraCrack 2 si e chiuso con un errore.
    pause
)

endlocal
