-- ScoreLock Database Setup Script
-- Run this in MySQL/MariaDB to create the database

-- Create database
CREATE DATABASE IF NOT EXISTS scorelock CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create dedicated user (optional but recommended)
CREATE USER IF NOT EXISTS 'scorelock_user'@'localhost' IDENTIFIED BY 'change_this_password';
GRANT ALL PRIVILEGES ON scorelock.* TO 'scorelock_user'@'localhost';
FLUSH PRIVILEGES;

-- Use the database
USE scorelock;

-- Note: The actual tables will be created automatically by init_db.py
-- This script just sets up the database and user

-- After running this script:
-- 1. Update your .env file with the database credentials
-- 2. Run: python init_db.py

