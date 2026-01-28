#!/bin/bash
# Quick setup script for ScoreLock with SQLite database

echo "================================================"
echo "ScoreLock - Quick Setup with SQLite"
echo "================================================"
echo ""

# Check if .env exists
if [ -f .env ]; then
    echo ".env file already exists."
    echo ""
    read -p "Do you want to backup and create a new .env with SQLite configuration? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Backing up existing .env to .env.backup..."
        cp .env .env.backup
        echo "Backup created: .env.backup"
        echo ""
        create_env=true
    else
        echo "Keeping existing .env file."
        echo ""
        create_env=false
    fi
else
    create_env=true
fi

# Create .env file
if [ "$create_env" = true ]; then
    echo "Creating .env file with SQLite configuration..."

    # Generate SECRET_KEY using Python; fall back to openssl if necessary
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || true)
    if [ -z "$SECRET_KEY" ]; then
        if command -v openssl >/dev/null 2>&1; then
            SECRET_KEY=$(openssl rand -hex 32 2>/dev/null || true)
        fi
    fi

    if [ -z "$SECRET_KEY" ]; then
        echo "Error: Failed to generate SECRET_KEY."
        echo "Please ensure Python 3 (with the 'secrets' module) or 'openssl' is installed."
        exit 1
    fi

    cat > .env << EOF
SECRET_KEY=$SECRET_KEY
DATABASE_URL=sqlite:///scorelock.db
UPLOAD_FOLDER=scores
EOF
    echo ".env file created with SQLite database configuration."
    echo ""
fi

# Create upload folder
if [ ! -d "scores" ]; then
    echo "Creating scores folder..."
    mkdir -p scores
    echo "Scores folder created."
else
    echo "Scores folder already exists."
fi
echo ""

# Install dependencies
echo "Installing Python dependencies..."
if ! command -v pip3 >/dev/null 2>&1; then
    echo "Error: pip3 is not installed or not found in your PATH."
    echo "Please ensure Python 3 and pip are installed correctly."
    exit 1
fi
pip3 install -r requirements.txt
if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Failed to install dependencies."
    echo "Please ensure Python 3 and pip are installed correctly."
    exit 1
fi
echo ""

# Test database configuration
echo "Testing database configuration..."
python3 test_database.py
if [ $? -ne 0 ]; then
    echo ""
    echo "Warning: Database test failed."
    echo "Please check the error messages above."
fi
echo ""

# Initialize database
read -p "Do you want to initialize the database now? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Initializing database..."
    python3 init_db.py
    if [ $? -ne 0 ]; then
        echo ""
        echo "Error: Database initialization failed."
        echo "Please review the error messages above and fix any issues before running 'python3 init_db.py' again."
    else
        echo ""
        echo "Database initialized successfully."
    fi
    echo ""
else
    echo ""
    echo "Skipping database initialization."
    echo "You can run 'python3 init_db.py' later to initialize the database."
    echo ""
fi

echo "================================================"
echo "Setup Complete!"
echo "================================================"
echo ""
echo "Your ScoreLock is configured with SQLite database."
echo ""
echo "Next steps:"
echo "1. If you skipped it, run: python3 init_db.py"
echo "2. Start the application: python3 main.py"
echo "3. Open http://localhost:5000 in your browser"
echo ""
echo "To switch to MySQL, edit your .env file and change DATABASE_URL."
echo "See DATABASE_CONFIG.md for detailed instructions."
echo ""
