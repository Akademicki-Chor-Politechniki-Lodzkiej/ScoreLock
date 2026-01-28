"""
Quick script to test database connectivity for both SQLite and MySQL options.
"""
import os
from dotenv import load_dotenv

load_dotenv()

def test_database_config():
    """Test the database configuration"""
    # Test current configuration
    db_url = os.getenv('DATABASE_URL', 'sqlite:///scorelock.db')
    print("=" * 60)
    print("ScoreLock Database Configuration Test")
    print("=" * 60)

    # Mask sensitive information in the URL (particularly passwords)
    from urllib.parse import urlparse, urlunparse
    try:
        parsed = urlparse(db_url)
        if parsed.password:
            # Reconstruct URL with masked password
            masked_netloc = f"{parsed.username}:****@{parsed.hostname}"
            if parsed.port:
                masked_netloc += f":{parsed.port}"
            masked_url = urlunparse((
                parsed.scheme,
                masked_netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment
            ))
            print(f"\nCurrent DATABASE_URL: {masked_url}")
        else:
            print(f"\nCurrent DATABASE_URL: {db_url}")
    except Exception:
        # If parsing fails, just print as-is (likely SQLite)
        print(f"\nCurrent DATABASE_URL: {db_url}")

    if db_url.startswith('sqlite:'):
        print("\n✓ Using SQLite database")
        print("  - No separate database server required")
        print("  - Database file will be created automatically")

        # Extract database path
        if db_url.startswith('sqlite:///'):
            db_path = db_url.replace('sqlite:///', '')
            if not os.path.isabs(db_path):
                db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_path)
            print(f"  - Database file path: {db_path}")

            # Check if directory is writable or can be created
            db_dir = os.path.dirname(db_path)
            if os.path.exists(db_dir):
                if os.access(db_dir, os.W_OK):
                    print("  ✓ Directory is writable")
                else:
                    print("  ⚠ Warning: Directory is not writable")
            else:
                parent_dir = os.path.dirname(db_dir) or os.getcwd()
                if os.access(parent_dir, os.W_OK):
                    print("  ✓ Directory does not exist but can be created (parent is writable)")
                else:
                    print("  ⚠ Warning: Directory may not be creatable (parent is not writable)")

    elif 'mysql' in db_url or 'mariadb' in db_url:
        print("\n✓ Using MySQL/MariaDB database")
        print("  - Requires separate database server")
        print("  - Ensure database exists and credentials are correct")

        # Try to parse connection details (without exposing password)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(db_url)
            print(f"  - Host: {parsed.hostname or 'localhost'}")
            print(f"  - Port: {parsed.port or 3306}")
            print(f"  - Database: {parsed.path.lstrip('/')}")
            print(f"  - Username: {parsed.username}")
        except Exception as e:
            print(f"  ⚠ Could not parse URL: {e}")
    else:
        print("\n⚠ Unknown database type")

    print("\n" + "=" * 60)
    print("To switch database types, edit your .env file:")
    print("\nFor SQLite:")
    print("  DATABASE_URL=sqlite:///scorelock.db")
    print("\nFor MySQL:")
    print("  DATABASE_URL=mysql+pymysql://user:pass@host/dbname")
    print("=" * 60)

    # Test actual connection
    print("\nTesting database connection...")
    try:
        from main import app
        from models import db

        with app.app_context():
            # Try to create tables
            db.create_all()
            print("✓ Successfully connected to database!")
            print("✓ Database tables created/verified")

            # Check if we can query
            from models import Admin
            admin_count = Admin.query.count()
            print(f"✓ Found {admin_count} admin user(s)")

    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False

    return True

if __name__ == '__main__':
    success = test_database_config()
    exit(0 if success else 1)
