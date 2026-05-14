@echo off
REM Avvia VeriPhoto senza richiedere che "streamlit" sia nel PATH di Windows.
cd /d "%~dp0"
python -m streamlit run main.py
if errorlevel 1 pause
