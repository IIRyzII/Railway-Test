"""
Run this once to create the first admin account.
Usage: python create_admin.py
"""
from App import app, db, User

with app.app_context():

    # Create all tables first (safe to run on existing DB too)
    db.create_all()

    # Now verify the schema looks right
    import sqlalchemy as sa
    inspector = sa.inspect(db.engine)
    existing_columns = [c["name"] for c in inspector.get_columns("user")]
    required_columns = ["id", "username", "email", "password", "role", "totp_secret"]
    missing = [c for c in required_columns if c not in existing_columns]

    if missing:
        print("⚠️  Schema still missing columns:", ', '.join(missing))
        print("   Delete instance/secure_future.db and run this script again.")
        exit(1)

    # Create the admin account
    print("=== Create Admin Account ===")
    username = input("Username : ").strip()
    email    = input("Email    : ").strip()
    password = input("Password : ")

    if len(password) < 8:
        print("❌ Password must be at least 8 characters.")
        exit(1)

    if User.query.filter_by(username=username).first():
        print("❌ Username already exists.")
        exit(1)

    if User.query.filter_by(email=email).first():
        print("❌ Email already exists.")
        exit(1)

    admin = User(username=username, email=email, role="admin")
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()

    print(f"✅ Admin account '{username}' created successfully!")
    print("   You can now log in at /LoginPage")
