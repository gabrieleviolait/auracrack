@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul || (echo Python non trovato.& pause & exit /b 1)
py -3 -c "import customtkinter, psutil, scapy" >nul 2>nul || py -3 -m pip install -r requirements.txt
py -3 main.py
if errorlevel 1 pause
endlocal
