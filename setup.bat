@echo off
echo ====================================
echo ScoreLock - Setup Script
echo ====================================
echo.

echo [1/4] Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)
echo Done!
echo.

echo [2/4] Checking for .env file...
if not exist .env (
    echo Creating .env from template...
    copy .env.example .env
    echo.
    echo IMPORTANT: Please edit .env file with your MySQL credentials!
    echo Press any key to open .env file in notepad...
    pause >nul
    notepad .env
    echo.
) else (
    echo .env file already exists
)
echo.

echo [3/4] Database Setup
echo.
echo Please ensure MySQL/MariaDB is running and you have created the database:
echo   CREATE DATABASE scorelock;
echo.
echo Press any key when ready to initialize database tables...
pause >nul
python init_db.py
if errorlevel 1 (
    echo Error: Database initialization failed
    echo Check your database credentials in .env file
    pause
    exit /b 1
)
echo.

echo [4/4] Setup Complete!
echo.
echo ====================================
echo To start the application, run:
echo   python main.py
echo.
echo Then open your browser to:
echo   http://localhost:5000
echo ====================================
echo.
pause

