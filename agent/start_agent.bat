@echo off
:loop
pythonw agent.py
timeout /t 10 > nul
goto loop
