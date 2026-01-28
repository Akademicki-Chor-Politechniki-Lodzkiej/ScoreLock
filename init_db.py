from main import app
from models import db, Admin, SiteSettings, Policy
import sys, getpass

def init_db():
    """Initialize the database and create tables"""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created successfully!")

        # Initialize Site Settings
        settings = SiteSettings.query.first()
        if not settings:
            settings = SiteSettings(site_name='ScoreLock')
            db.session.add(settings)
            db.session.commit()
            print("✓ Site settings initialized with default values")
        else:
            print(f"✓ Site settings already exist (Site name: {settings.site_name})")

        # Check if admin exists
        admin_count = Admin.query.count()
        if admin_count == 0:
            print("\nNo admin users found. Let's create the first admin account.")
            username = input("Enter admin username: ")
            password = getpass.getpass("Enter admin password: ")

            admin = Admin(username=username)
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()

            print(f"✓ Admin user '{username}' created successfully!")
        else:
            print(f"\n✓ Found {admin_count} existing admin user(s)")

        # Check policies
        policy_count = Policy.query.count()
        if policy_count == 0:
            print("\n✓ No policies found (you can create them in the admin panel)")
        else:
            active_count = Policy.query.filter_by(is_active=True).count()
            print(f"\n✓ Found {policy_count} policy/policies ({active_count} active)")

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

        password = getpass.getpass("Enter admin password: ")

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
