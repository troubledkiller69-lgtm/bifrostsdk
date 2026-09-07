@echo off
rem BIFROST SDK - one-click dev launcher (double-click me)
rem Uses the Python the backend was built for, then boots vite + Electron.
cd /d "%~dp0gui"
set "PATH=C:\Users\howar\AppData\Local\Python\pythoncore-3.14-64;%PATH%"
call npm.cmd run dev
