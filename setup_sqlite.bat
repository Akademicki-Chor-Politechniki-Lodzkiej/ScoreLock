@echo off
REM Quick setup script for ScoreLock with SQLite database

echo ================================================
echo ScoreLock - Quick Setup with SQLite
echo ================================================
echo.

REM Check if .env exists
if exist .env (
    echo .env file already exists.
    echo.
    choice /C YN /M "Do you want to backup and create a new .env with SQLite configuration"
    if errorlevel 2 goto :skip_env
    if errorlevel 1 goto :backup_env
) else (
    goto :create_env
)

:backup_env
echo Backing up existing .env to .env.backup...
copy .env .env.backup
echo Backup created: .env.backup
echo.

:create_env
echo Creating .env file with SQLite configuration...
for /f "usebackq delims=" %%K in (`python -c "import secrets; print(secrets.token_hex(32))"`) do set "SECRET_KEY=%%K"
REM Validate SECRET_KEY generation
if "%SECRET_KEY%"=="" (
    echo.
    echo Error: Failed to generate SECRET_KEY.
    echo Ensure Python is installed and that the command
    echo   python -c "import secrets; print(secrets.token_hex(32))"
    echo executes successfully from this environment.
    echo.
    pause
    exit /b 1
)
(
    echo SECRET_KEY=%SECRET_KEY%
    echo DATABASE_URL=sqlite:///scorelock.db
    echo UPLOAD_FOLDER=scores
) > .env
echo .env file created with SQLite database configuration.
echo.
echo NOTE: SECRET_KEY was generated automatically and written to .env.
echo If you prefer to use your own key, edit .env and set SECRET_KEY to a secure value.
echo.
goto :continue

:skip_env
echo Keeping existing .env file.
echo.

:continue
REM Create upload folder
if not exist scores (
    echo Creating scores folder...
    mkdir scores
    echo Scores folder created.
) else (
    echo Scores folder already exists.
)
echo.

REM Install dependencies
echo Installing Python dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Error: Failed to install dependencies.
    echo Please ensure Python and pip are installed correctly.
    pause
    exit /b 1
)
echo.

REM Test database configuration
echo Testing database configuration...
python test_database.py
if errorlevel 1 (
    echo.
    echo Warning: Database test failed.
    echo Please check the error messages above.
    pause
)
echo.

REM Initialize database
echo.
choice /C YN /M "Do you want to initialize the database now"
if errorlevel 2 goto :skip_init
if errorlevel 1 goto :init_db

:init_db
echo.
echo Initializing database...
python init_db.py
if errorlevel 1 (
    echo.
    echo Error: Failed to initialize the database.
    echo Please check the error messages above, fix the issue, and run 'python init_db.py' again.
    pause
    exit /b 1
)
echo.
goto :finish

:skip_init
echo.
echo Skipping database initialization.
echo You can run 'python init_db.py' later to initialize the database.
echo.

:finish
echo ================================================
echo Setup Complete!
echo ================================================
echo.
echo Your ScoreLock is configured with SQLite database.
echo.
echo Next steps:
echo 1. If you skipped it, run: python init_db.py
echo 2. Start the application: python main.py
echo 3. Open http://localhost:5000 in your browser
echo.
echo To switch to MySQL, edit your .env file and change DATABASE_URL.
echo See DATABASE_CONFIG.md for detailed instructions.
echo.
pause
