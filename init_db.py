from main import app
from models import db, Admin
import sys

def init_db():
    """Initialize the database and create tables"""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created successfully!")

        # Check if admin exists
        admin_count = Admin.query.count()
        if admin_count == 0:
            print("\nNo admin users found. Let's create the first admin account.")
            username = input("Enter admin username: ")
            password = input("Enter admin password: ")

            admin = Admin(username=username)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()

            print(f"✓ Admin user '{username}' created successfully!")
        else:
            print(f"\n✓ Found {admin_count} existing admin user(s)")

        print("\n✓ Database initialization complete!")
        print("\nYou can now run the application with: python main.py")

def create_admin():
    """Create a new admin user"""
    with app.app_context():
        username = input("Enter admin username: ")

        # Check if username exists
        existing = Admin.query.filter_by(username=username).first()
        if existing:
            print(f"Error: User '{username}' already exists!")
            sys.exit(1)

        password = input("Enter admin password: ")

        admin = Admin(username=username)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()

        print(f"✓ Admin user '{username}' created successfully!")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'create-admin':
        create_admin()
    else:
        init_db()

