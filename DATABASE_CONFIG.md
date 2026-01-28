# Database Configuration Guide

## Switching Between Database Types

ScoreLock supports both SQLite and MySQL/MariaDB databases. You can easily switch between them by modifying your `.env` file.

## SQLite Configuration (Recommended for Development)

### Advantages
- ✅ No separate database server needed
- ✅ Zero configuration
- ✅ Single file database (easy to backup)
- ✅ Perfect for development and small deployments
- ✅ Built into Python (no extra dependencies)

### Setup Steps

1. **Edit your `.env` file:**
   ```env
   DATABASE_URL=sqlite:///scorelock.db
   ```

2. **Initialize the database:**
   ```bash
   python init_db.py
   ```

3. **Run the application:**
   ```bash
   python main.py
   ```

That's it! The SQLite database file (`scorelock.db`) will be created automatically in your project directory.

### Custom Database Location

You can specify a custom path for the SQLite database:

```env
# Relative path (will be created in project directory)
DATABASE_URL=sqlite:///data/mydb.db

# Absolute path (Windows)
DATABASE_URL=sqlite:///C:/path/to/database.db

# Absolute path (Linux/Mac)
DATABASE_URL=sqlite:////absolute/path/to/database.db
```

**Note:** Four slashes (`////`) are needed for absolute paths on Unix systems.

## MySQL/MariaDB Configuration (Recommended for Production)

### Advantages
- ✅ Better performance with concurrent users
- ✅ Advanced features and optimizations
- ✅ Industry-standard for production
- ✅ Better scalability

### Setup Steps

1. **Create the database:**
   ```sql
   CREATE DATABASE scorelock CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'scorelock_user'@'localhost' IDENTIFIED BY 'your_password';
   GRANT ALL PRIVILEGES ON scorelock.* TO 'scorelock_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

2. **Edit your `.env` file:**
   ```env
   DATABASE_URL=mysql+pymysql://scorelock_user:your_password@localhost/scorelock
   ```

3. **Initialize the database:**
   ```bash
   python init_db.py
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

### Remote MySQL Server

If your MySQL server is on a different host:

```env
DATABASE_URL=mysql+pymysql://username:password@remote-host.com:3306/scorelock
```

## Testing Your Configuration

Run the database test script to verify your configuration:

```bash
python test_database.py
```

This will:
- Display your current database configuration
- Test the connection
- Verify tables are created correctly
- Show the number of admin users

## Migrating Between Databases

### From MySQL to SQLite

1. **Export your data** (if you want to keep it):
   ```bash
   # This is a manual process - export each table as needed
   # Consider using SQLAlchemy migrations or custom scripts
   ```

2. **Change `.env` to SQLite:**
   ```env
   DATABASE_URL=sqlite:///scorelock.db
   ```

3. **Reinitialize:**
   ```bash
   python init_db.py
   ```

### From SQLite to MySQL

1. **Backup your SQLite database:**
On windows:
   ```bash
   copy scorelock.db scorelock.db.backup
   ```
On Linux/Mac:
   ```bash
    cp scorelock.db scorelock.db.backup
   ```

2. **Create MySQL database** (see MySQL setup steps above)

3. **Change `.env` to MySQL:**
   ```env
   DATABASE_URL=mysql+pymysql://user:password@localhost/scorelock
   ```

4. **Reinitialize:**
   ```bash
   python init_db.py
   ```

**Note:** Direct data migration between database types requires custom scripts or tools. The above steps create fresh databases. For production migrations with data preservation, consider using database migration tools like Alembic.

## Troubleshooting

### SQLite Issues

**Permission Denied:**
- Ensure the application directory is writable
- Check file permissions on the database file

**Database is locked:**
- SQLite doesn't handle many concurrent writes well
- Consider switching to MySQL for high-traffic deployments

### MySQL Issues

**Connection Refused:**
- Verify MySQL server is running
- Check host and port in DATABASE_URL
- Ensure firewall allows connections

**Access Denied:**
- Verify username and password
- Check user permissions with `SHOW GRANTS FOR 'user'@'host';`
- Ensure user has privileges on the database

**Database doesn't exist:**
- Run `CREATE DATABASE scorelock;` in MySQL
- Verify database name matches DATABASE_URL

## Best Practices

### Development
- Use **SQLite** for simplicity and ease of setup
- Database file is easily portable

### Production
- Use **MySQL/MariaDB** for better performance and scalability
- Set up regular backups
- Use connection pooling for better performance
- Consider using a managed database service

### Backup Strategies

**SQLite:**
On Windows (PowerShell):
```powershell
# Simple file copy
Copy-Item .\scorelock.db ("backups\scorelock_{0:yyyyMMdd}.db" -f (Get-Date))
```
On Linux/Mac:
```bash
# Simple file copy
cp scorelock.db backups/scorelock_$(date +%Y%m%d).db
```

**MySQL:**
```bash
# Using mysqldump
mysqldump -u username -p scorelock > backup.sql
```

## Environment Variables Reference

```env
# Required
SECRET_KEY=your-secret-key-here

# Database (choose one)
DATABASE_URL=sqlite:///scorelock.db                                    # SQLite
DATABASE_URL=mysql+pymysql://user:pass@localhost/scorelock            # MySQL Local
DATABASE_URL=mysql+pymysql://user:pass@remote.com:3306/scorelock      # MySQL Remote

# Optional
UPLOAD_FOLDER=scores                                                   # Upload directory
```
