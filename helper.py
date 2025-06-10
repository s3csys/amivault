#!/usr/bin/env python3
"""
Admin User Creation Script
Run this script to create or update admin users for the Flask application.

Usage:
    python3 helper.py
    python3 helper.py username password email
    python3 helper.py --list
    python3 helper.py --recreate-db
    
You can modify the user details in the script or pass them as arguments.
"""

import sys
import os
import getpass
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


try:
    from app import app, db, User
except ImportError as e:
    print(f"❌ Error importing from app.py or models.py: {e}")
    print("Make sure you're running this script from the same directory as app.py and models.py")
    sys.exit(1)

# Create Flask application context
app.app_context().push()

def validate_email(email):
    """Validate email format using regex."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is strong"

def get_secure_password(prompt="Enter password: "):
    """Get password with validation and confirmation."""
    while True:
        password = getpass.getpass(prompt)
        if not password:
            print("❌ Password cannot be empty")
            continue
            
        is_valid, message = validate_password(password)
        if not is_valid:
            print(f"❌ {message}")
            continue
            
        # Confirm password
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("❌ Passwords do not match")
            continue
            
        return password

def create_admin_user(username=None, password=None, email=None, profile_pic_url=None, interactive=True):
    """
    Create or update an admin user.
    
    Args:
        username (str): Username for the admin
        password (str): Password for the admin
        email (str): Email for the admin
        profile_pic_url (str, optional): Profile picture URL
        interactive (bool): Whether to prompt for input interactively
    """
    
    # Get user input if not provided
    if not username:
        if interactive:
            username = input("Enter username (default: admin): ").strip() or "admin"
        else:
            username = "admin"
    
    if not email:
        if interactive:
            while True:
                email = input("Enter email: ").strip()
                if email and validate_email(email):
                    break
                print("❌ Please enter a valid email address")
        else:
            email = "admin@example.com"  # Default for non-interactive mode
    
    if not password:
        if interactive:
            print("Password requirements:")
            print("- At least 8 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter") 
            print("- At least one number")
            print("- At least one special character")
            password = get_secure_password()
        else:
            print("❌ Password must be provided for non-interactive mode")
            return None
    
    # Validate inputs
    if not username.strip():
        print("❌ Username cannot be empty")
        return None
        
    if not validate_email(email):
        print(f"❌ Invalid email format: {email}")
        return None
    
    is_valid, message = validate_password(password)
    if not is_valid:
        print(f"❌ {message}")
        return None
    
    try:
        with app.app_context():
            # Ensure tables exist
            db.create_all()
            
            # Check if user already exists
            existing_user = User.query.filter_by(username=username).first()
            
            if existing_user:
                print(f"👤 User '{username}' already exists.")
                
                if interactive:
                    # Ask if user wants to update password
                    update = input("Do you want to update the password? (y/N): ").lower().strip()
                    if update in ['y', 'yes']:
                        existing_user.set_password(password)
                        # Update email if different
                        if existing_user.email != email:
                            existing_user.email = email
                        # Reset last_login if the field exists
                        if hasattr(existing_user, 'last_login'):
                            existing_user.last_login = None
                        db.session.commit()
                        print(f"✅ User '{username}' updated successfully!")
                        return existing_user
                    else:
                        print("❌ No changes made.")
                        return existing_user
                else:
                    print("❌ User already exists. Use interactive mode to update.")
                    return None
            
            # Create new user
            print(f"🔨 Creating new user '{username}'...")
            
            # Create user object
            user = User(
                username=username,
                email=email
            )
            
            # Set password (this will hash it)
            user.set_password(password)
            
            # Set profile picture if provided
            if profile_pic_url:
                if hasattr(user, 'profile_pic_url'):
                    user.profile_pic_url = profile_pic_url
                else:
                    print("⚠️  Warning: User model doesn't have profile_pic_url field")
            
            # Add to database
            db.session.add(user)
            db.session.commit()
            
            print(f"✅ User '{username}' created successfully!")
            print(f"   📧 Email: {email}")
            print(f"   🔑 Password: {'*' * len(password)}")  # Don't show actual password
            if hasattr(user, 'created_at') and user.created_at:
                print(f"   📅 Created: {user.created_at}")
            
            return user
            
    except Exception as e:
        print(f"❌ Error creating user: {e}")
        try:
            db.session.rollback()
        except:
            pass
        return None

def list_users():
    """List all existing users."""
    try:
        with app.app_context():
            users = User.query.all()
            if not users:
                print("📋 No users found in database.")
                return
            
            print(f"📋 Found {len(users)} user(s):")
            print("-" * 80)
            print(f"{'Username':<15} | {'Email':<30} | {'Status':<10} | {'Last Login':<20}")
            print("-" * 80)
            
            for user in users:
                # Safely check for attributes that might not exist
                if hasattr(user, 'is_active'):
                    status = "🟢 Active" if user.is_active else "🔴 Inactive"
                else:
                    status = "🟡 Unknown"
                
                if hasattr(user, 'last_login') and user.last_login:
                    last_login = user.last_login.strftime("%Y-%m-%d %H:%M")
                else:
                    last_login = "Never"
                
                print(f"{user.username:<15} | {user.email:<30} | {status:<10} | {last_login:<20}")
            
            print("-" * 80)
            
    except Exception as e:
        print(f"❌ Error listing users: {e}")

def delete_user(username):
    """Delete a user by username."""
    if not username:
        print("❌ Username cannot be empty")
        return False
        
    try:
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if not user:
                print(f"❌ User '{username}' not found.")
                return False
            
            # Show user details before deletion
            print(f"User to delete: {user.username} ({user.email})")
            
            # Confirm deletion
            confirm = input(f"⚠️  Are you sure you want to delete user '{username}'? (y/N): ").lower().strip()
            if confirm not in ['y', 'yes']:
                print("❌ Deletion cancelled.")
                return False
            
            # Final confirmation
            final_confirm = input("Type 'DELETE' to confirm: ").strip()
            if final_confirm != 'DELETE':
                print("❌ Deletion cancelled.")
                return False
            
            db.session.delete(user)
            db.session.commit()
            print(f"✅ User '{username}' deleted successfully.")
            return True
            
    except Exception as e:
        print(f"❌ Error deleting user: {e}")
        try:
            db.session.rollback()
        except:
            pass
        return False

def recreate_database(interactive=True):
    """Recreate the database (drops all tables and recreates them)."""
    try:
        with app.app_context():
            if interactive:
                print("⚠️  WARNING: This will delete ALL data in the database!")
                confirm = input("Are you sure you want to recreate the database? (y/N): ").lower().strip()
                
                if confirm not in ['y', 'yes']:
                    print("❌ Database recreation cancelled.")
                    return False
                
                # Final confirmation
                final_confirm = input("Type 'RECREATE' to confirm: ").strip()
                if final_confirm != 'RECREATE':
                    print("❌ Database recreation cancelled.")
                    return False
            
            print("🗑️  Dropping all tables...")
            db.drop_all()
            
            print("🔨 Creating all tables...")
            db.create_all()
            
            # Import required functions
            from app import schedule_all_instance_backups, scheduler
            
            # Start scheduler if not running
            if not scheduler.running:
                scheduler.start()
                print("✅ Scheduler started successfully")
            
            # Schedule backups for active instances
            try:
                schedule_all_instance_backups()
                print("✅ Instance backups scheduled successfully")
            except Exception as e:
                print(f"⚠️  Warning: Failed to schedule instance backups: {e}")
            
            print("✅ Database recreated successfully!")
            print("📝 Note: All previous data has been lost.")
            return True
            
    except Exception as e:
        print(f"❌ Error recreating database: {e}")
        return False

def main():
    """Main function with interactive menu."""
    print("🔧 Admin User Management Tool")
    print("=" * 40)
    
    while True:
        print("\nOptions:")
        print("1. Create new admin user")
        print("2. Create custom user")
        print("3. List all users")
        print("4. Delete user")
        print("5. Recreate database (⚠️  DANGER ZONE)")
        print("6. Exit")
        
        choice = input("\nSelect option (1-6): ").strip()
        
        if choice == '1':
            # Create admin user with default username
            user = create_admin_user(username="admin", interactive=True)
            if user:
                print("\n⚠️  SECURITY REMINDER:")
                print("- Make sure to use a strong, unique password")
                print("- Consider enabling two-factor authentication if available")
                print("- Regularly update your password")
        
        elif choice == '2':
            # Create custom user
            print("\nCreating custom user...")
            user = create_admin_user(interactive=True)
        
        elif choice == '3':
            # List users
            list_users()
        
        elif choice == '4':
            # Delete user
            username = input("Enter username to delete: ").strip()
            if username:
                delete_user(username)
            else:
                print("❌ Username is required.")
        
        elif choice == '5':
            # Recreate database
            recreate_database()
        
        elif choice == '6':
            print("👋 Goodbye!")
            break
        
        else:
            print("❌ Invalid option. Please try again.")

if __name__ == "__main__":
    # Check if running with command line arguments
    if len(sys.argv) == 4:
        # Usage: python3 admin_user.py username password email
        username, password, email = sys.argv[1], sys.argv[2], sys.argv[3]
        print(f"Creating user from command line arguments...")
        create_admin_user(username, password, email, interactive=False)
    elif len(sys.argv) == 2:
        if sys.argv[1] == '--list':
            # Usage: python3 admin_user.py --list
            list_users()
        elif sys.argv[1] == '--recreate-db':
            # Usage: python3 admin_user.py --recreate-db
            recreate_database(interactive=False)
        else:
            print("❌ Unknown argument. Available options:")
            print("  --list: List all users")
            print("  --recreate-db: Recreate database")
    else:
        # Interactive mode
        main()