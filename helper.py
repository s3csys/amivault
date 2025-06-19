#!/usr/bin/env python3
"""
AMIVault Administration Helper Tool

A professional utility for managing AMIVault - the enterprise-grade AWS AMI backup solution.
This tool provides administrative functions for user management, database operations,
and system maintenance.

Usage:
    python helper.py                      - Interactive mode with menu
    python helper.py --help               - Display this help message
    python helper.py --list               - List all users in the system
    python helper.py --recreate-db        - Recreate database (warning: deletes all data)
    python helper.py --check-system       - Check system health and configuration
    python helper.py --backup-config      - Backup system configuration
    python helper.py --restore-config     - Restore system configuration
    python helper.py --version            - Display version information
    python helper.py username password email - Create/update a user non-interactively

For more information, visit: https://github.com/s3csys/amivault
"""

import sys
import os
import getpass
import re
import platform
import json
import shutil
import datetime
import logging
from pathlib import Path
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import io

# Suppress startup log messages
class LogSuppressor:
    def __init__(self):
        self.original_stderr = sys.stderr
        self.original_stdout = sys.stdout
        self.stderr_buffer = io.StringIO()
        self.stdout_buffer = io.StringIO()
    
    def __enter__(self):
        # Redirect both stderr and stdout during app import
        # This will capture all logging messages
        sys.stderr = self.stderr_buffer
        sys.stdout = self.stdout_buffer
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original streams
        sys.stderr = self.original_stderr
        sys.stdout = self.original_stdout
        # Optionally store logs for debugging
        self.captured_stderr = self.stderr_buffer.getvalue()
        self.captured_stdout = self.stdout_buffer.getvalue()

# Configure logging
logging.basicConfig(
    level=logging.ERROR,  # Changed from INFO to ERROR to reduce unnecessary logging
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('amivault-helper')

# Import Flask app and database models with suppressed logs
# Suppress both stderr and stdout during import
with LogSuppressor():
    try:
        from app import app, db
        from models import User, BackupSettings, Instance, Backup, AWSCredential
        # Create Flask application context
        app.app_context().push()
    except ImportError as e:
        # We'll handle this outside the suppressor
        import_error = e

# Check if there was an import error
if 'import_error' in locals():
    logger.error(f"Error importing Flask app: {import_error}")
    print(f"❌ Error importing Flask app: {import_error}")
    print("Make sure you're running this script from the correct directory.")
    sys.exit(1)

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
    
    # Get user input if not provided, check environment variables first
    if not username:
        # Check environment variable first
        env_username = os.environ.get('ADMIN_USERNAME')
        if env_username:
            username = env_username
        elif interactive:
            username = input("Enter username (default: admin): ").strip() or "admin"
        else:
            username = "admin"
    
    if not email:
        # Check environment variable first
        env_email = os.environ.get('ADMIN_EMAIL')
        if env_email and validate_email(env_email):
            email = env_email
        elif interactive:
            while True:
                email = input("Enter email: ").strip()
                if email and validate_email(email):
                    break
                print("❌ Please enter a valid email address")
        else:
            email = "admin@example.com"  # Default for non-interactive mode
    
    if not password:
        # Check environment variable first
        env_password = os.environ.get('ADMIN_PASSWORD')
        if env_password and validate_password(env_password)[0]:
            password = env_password
        elif interactive:
            print("Password requirements:")
            print("- At least 8 characters")
            print("- At least one uppercase letter")
            print("- At least one lowercase letter") 
            print("- At least one number")
            print("- At least one special character")
            password = get_secure_password()
        else:
            print("❌ Password must be provided for non-interactive mode or in ADMIN_PASSWORD environment variable")
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
            # print(f"   🔑 Password: Amiv@u1t")  # Don't show actual password
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

            # #print("Creating the admin user with default password ...")
            # create_admin_user(
            #     username='amivault',
            #     password='Amiv@u1t',
            #     email='admin@example.com',
            #     interactive=False
            # )
            
            # Import required functions
            from app import schedule_all_instance_backups, scheduler
            
            # Get default backup settings from environment variables
            default_backup_frequency = os.environ.get('DEFAULT_BACKUP_FREQUENCY', '0 2 * * *')
            default_retention_days = int(os.environ.get('DEFAULT_RETENTION_DAYS', '7'))
            
            # Create default backup settings
            from models import BackupSettings
            default_settings = BackupSettings(
                backup_frequency=default_backup_frequency,
                retention_days=default_retention_days
            )
            db.session.add(default_settings)
            db.session.commit()
            print(f"✅ Default backup settings created: frequency='{default_backup_frequency}', retention={default_retention_days} days")
            
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

def display_logo():
    """Display the AMIVault ASCII logo."""
    logo = """
    █████╗ ███╗   ███╗██╗██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
   ██╔══██╗████╗ ████║██║██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
   ███████║██╔████╔██║██║██║   ██║███████║██║   ██║██║     ██║   
   ██╔══██║██║╚██╔╝██║██║╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
   ██║  ██║██║ ╚═╝ ██║██║ ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
   ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
    """
    version_info = "v1.0.0 - Professional AWS AMI Backup Management Solution"
    print(logo)
    print(f"{version_info:^70}")
    print("=" * 70)

def get_system_info():
    """Get system information for diagnostics."""
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "cpu_architecture": platform.machine(),
        "timestamp": datetime.now().isoformat()
    }
    
    # Add Flask app info if available
    try:
        with app.app_context():
            info["database_uri"] = app.config.get("SQLALCHEMY_DATABASE_URI", "Unknown").split("://")[0] + "://****"
            info["debug_mode"] = app.config.get("DEBUG", False)
            info["testing_mode"] = app.config.get("TESTING", False)
            info["user_count"] = User.query.count()
            info["instance_count"] = Instance.query.count()
            info["backup_count"] = Backup.query.count()
    except Exception as e:
        logger.warning(f"Could not get complete system info: {e}")
        
    return info

def check_system():
    """Check system health and configuration."""
    print("🔍 Checking AMIVault system health...")
    print("-" * 70)
    
    # Get system info
    system_info = get_system_info()
    print(f"📊 System Information:")
    print(f"  • Operating System: {system_info['os']} {system_info['os_version']}")
    print(f"  • Python Version: {system_info['python_version']}")
    print(f"  • Hostname: {system_info['hostname']}")
    print(f"  • Architecture: {system_info['cpu_architecture']}")
    
    # Check database connection
    print("\n📁 Database Check:")
    try:
        with app.app_context():
            # Use SQLAlchemy text() function to properly handle SQL expressions
            from sqlalchemy import text
            db.session.execute(text("SELECT 1"))
            print("  ✅ Database connection successful")
            
            # Check tables
            user_count = User.query.count()
            instance_count = Instance.query.count()
            backup_count = Backup.query.count()
            
            print(f"  • Users: {user_count}")
            print(f"  • Instances: {instance_count}")
            print(f"  • Backups: {backup_count}")
    except Exception as e:
        print(f"  ❌ Database connection failed: {e}")
    
    # Check file permissions
    print("\n🔒 File Permissions:")
    app_dir = os.path.dirname(os.path.abspath(__file__))
    for check_dir in [app_dir, os.path.join(app_dir, 'static'), os.path.join(app_dir, 'templates')]:
        if os.path.exists(check_dir):
            readable = os.access(check_dir, os.R_OK)
            writable = os.access(check_dir, os.W_OK)
            executable = os.access(check_dir, os.X_OK)
            print(f"  • {check_dir}: {'✅' if readable and executable else '❌'} Read/Execute {'✅' if writable else '❌'} Write")
    
    # Check environment variables
    print("\n🔐 Environment Variables:")
    required_vars = ['SECRET_KEY']
    database_vars = ['DATABASE_URL', 'SQLALCHEMY_DATABASE_URI']
    optional_vars = ['ADMIN_USERNAME', 'ADMIN_EMAIL', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
    
    for var in required_vars:
        if var in os.environ:
            print(f"  ✅ {var}: Set")
        else:
            print(f"  ❌ {var}: Not set (Required)")
    
    # Check for either DATABASE_URL or SQLALCHEMY_DATABASE_URI
    if any(var in os.environ for var in database_vars):
        print(f"  ✅ Database URI: Set")
    else:
        print(f"  ❌ Database URI: Not set (Required)")
    
    for var in optional_vars:
        if var in os.environ:
            print(f"  ✅ {var}: Set")
        else:
            print(f"  ⚠️  {var}: Not set (Optional)")
    
    print("\n✅ System check completed")
    return True

def backup_config():
    """Backup system configuration to an organized folder structure."""
    try:
        # Create main backups directory if it doesn't exist
        main_backup_dir = "backups"
        os.makedirs(main_backup_dir, exist_ok=True)
        
        # Check for existing backups in root directory and migrate them
        root_backups = [d for d in os.listdir('.') 
                       if d.startswith('amivault_config_backup_') 
                       and os.path.isdir(d)]
        
        if root_backups:
            print(f"📦 Found {len(root_backups)} existing backups in root directory")
            print(f"📦 Migrating to organized backup structure in '{main_backup_dir}'...")
            
            for old_backup in root_backups:
                # Create destination path
                dest_path = os.path.join(main_backup_dir, old_backup)
                
                # Skip if already exists in destination
                if os.path.exists(dest_path):
                    print(f"  ⚠️  Skipping {old_backup} (already exists in {main_backup_dir})")
                    continue
                
                # Move the backup folder
                shutil.move(old_backup, dest_path)
                print(f"  ✅ Migrated {old_backup} to {main_backup_dir}")
        
        # Create human-readable timestamped subfolder for this backup
        current_time = datetime.now()
        date_str = current_time.strftime("%Y-%m-%d")
        time_str = current_time.strftime("%I-%M-%S-%p")  # 12-hour format with AM/PM
        backup_subfolder = f"amivault_config_backup_{date_str}_{time_str}"
        backup_dir = os.path.join(main_backup_dir, backup_subfolder)
        os.makedirs(backup_dir, exist_ok=True)
        
        print(f"📦 Creating configuration backup in {backup_dir}...")
        
        # Backup database if SQLite
        with app.app_context():
            db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
            if db_uri.startswith("sqlite"):
                db_path = db_uri.replace("sqlite:///", "")
                if os.path.exists(db_path):
                    shutil.copy2(db_path, os.path.join(backup_dir, "database.sqlite"))
                    print(f"  ✅ Database backed up")
        
        # Backup .env file if exists
        if os.path.exists(".env"):
            shutil.copy2(".env", os.path.join(backup_dir, ".env"))
            print(f"  ✅ Environment variables backed up")
        
        # Backup user data
        with app.app_context():
            users = User.query.all()
            user_data = [{
                "username": user.username,
                "email": user.email,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "password_hash": user.password_hash,
                "two_factor_enabled": user.two_factor_enabled,
                "two_factor_secret": user.two_factor_secret
            } for user in users]
            
            with open(os.path.join(backup_dir, "users.json"), "w") as f:
                json.dump(user_data, f, indent=2)
            print(f"  ✅ User data backed up")
            
            # Backup settings
            settings = BackupSettings.query.all()
            settings_data = [{
                "id": setting.id,
                "retention_days": setting.retention_days,
                "backup_frequency": setting.backup_frequency,
                "created_at": setting.created_at.isoformat() if hasattr(setting, 'created_at') and setting.created_at else None,
                "updated_at": setting.updated_at.isoformat() if hasattr(setting, 'updated_at') and setting.updated_at else None
            } for setting in settings]
            
            with open(os.path.join(backup_dir, "settings.json"), "w") as f:
                json.dump(settings_data, f, indent=2)
            print(f"  ✅ Settings backed up")
        
        print(f"\n✅ Configuration backup completed successfully")
        print(f"📂 Backup location: {os.path.abspath(backup_dir)}")
        return True
    except Exception as e:
        print(f"❌ Error backing up configuration: {e}")
        logger.error(f"Error backing up configuration: {e}")
        return False

def restore_config():
    """Restore system configuration from backup."""
    # Check for backups in the new organized structure
    main_backup_dir = "backups"
    backup_locations = {}
    
    # First check the main backup directory if it exists
    if os.path.exists(main_backup_dir) and os.path.isdir(main_backup_dir):
        # Look for backup folders in the main backup directory
        main_backups = [d for d in os.listdir(main_backup_dir) 
                      if d.startswith('amivault_config_backup_') 
                      and os.path.isdir(os.path.join(main_backup_dir, d))]
        
        # Add these to our backup locations with their full path
        for backup in main_backups:
            backup_locations[backup] = os.path.join(main_backup_dir, backup)
    
    # For backward compatibility, also check the root directory
    root_backups = [d for d in os.listdir('.') 
                   if d.startswith('amivault_config_backup_') 
                   and os.path.isdir(d)]
    
    # Add these to our backup locations with their full path
    for backup in root_backups:
        # Only add if not already in the list (prioritize the organized backups)
        if backup not in backup_locations:
            backup_locations[backup] = backup
    
    if not backup_locations:
        print(f"❌ No backup directories found")
        return False
    
    # Get the backup names and sort by timestamp (newest first)
    backup_dirs = list(backup_locations.keys())
    backup_dirs.sort(reverse=True)
    
    print("📂 Available backups:")
    for i, backup_dir in enumerate(backup_dirs):
        # Handle both old and new format backup directory names
        timestamp = backup_dir.replace('amivault_config_backup_', '')
        try:
            # Try parsing the new format (YYYY-MM-DD_HH-MM-SS-AM/PM)
            if '-' in timestamp:
                date_part, time_part = timestamp.split('_', 1)
                formatted_time = f"{date_part} {time_part.replace('-', ':')}"
            # Fall back to old format (YYYYMMDD_HHMMSS)
            else:
                formatted_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            # If parsing fails, just show the raw directory name
            formatted_time = timestamp
        
        print(f"  {i+1}. {backup_dir} (Created: {formatted_time})")
    
    choice = input("\nSelect backup to restore (number) or 'q' to quit: ").strip()
    if choice.lower() == 'q':
        return False
    
    try:
        backup_index = int(choice) - 1
        if backup_index < 0 or backup_index >= len(backup_dirs):
            print("❌ Invalid selection")
            return False
        
        selected_backup_name = backup_dirs[backup_index]
        selected_backup_path = backup_locations[selected_backup_name]
        print(f"\n⚠️  WARNING: Restoring from {selected_backup_name} will overwrite current configuration!")
        confirm = input("Are you sure you want to proceed? (y/N): ").lower().strip()
        
        if confirm not in ['y', 'yes']:
            print("❌ Restoration cancelled")
            return False
        
        # Final confirmation
        final_confirm = input("Type 'RESTORE' to confirm: ").strip()
        if final_confirm != 'RESTORE':
            print("❌ Restoration cancelled")
            return False
        
        print(f"\n🔄 Restoring configuration from {selected_backup_name}...")
        
        # Restore database if exists in backup
        db_backup_path = os.path.join(selected_backup_path, "database.sqlite")
        if os.path.exists(db_backup_path):
            with app.app_context():
                db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
                if db_uri.startswith("sqlite"):
                    db_path = db_uri.replace("sqlite:///", "")
                    # Create backup of current database
                    if os.path.exists(db_path):
                        shutil.copy2(db_path, f"{db_path}.bak")
                        print(f"  ✅ Current database backed up to {db_path}.bak")
                    # Restore database
                    shutil.copy2(db_backup_path, db_path)
                    print(f"  ✅ Database restored")
                else:
                    print(f"  ⚠️  Cannot automatically restore non-SQLite database")
        
        # Restore .env file if exists in backup
        env_backup_path = os.path.join(selected_backup_path, ".env")
        if os.path.exists(env_backup_path):
            if os.path.exists(".env"):
                shutil.copy2(".env", ".env.bak")
                print(f"  ✅ Current .env backed up to .env.bak")
            shutil.copy2(env_backup_path, ".env")
            print(f"  ✅ Environment variables restored")
        
        # Restore users if users.json exists in backup
        users_backup_path = os.path.join(selected_backup_path, "users.json")
        if os.path.exists(users_backup_path):
            try:
                with open(users_backup_path, 'r') as f:
                    user_data = json.load(f)
                
                with app.app_context():
                    # Only restore users if database is SQLite (for consistency)
                    db_uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
                    if db_uri.startswith("sqlite"):
                        # Check if we need to restore users manually
                        # This is needed if the database wasn't restored or if we want to ensure users are properly restored
                        restore_users = True
                        
                        if restore_users:
                            print(f"  🔄 Restoring {len(user_data)} users from backup...")
                            
                            # Track success/failure counts
                            success_count = 0
                            failure_count = 0
                            
                            for user_info in user_data:
                                try:
                                    # Check if user already exists
                                    username = user_info.get('username')
                                    existing_user = User.query.filter_by(username=username).first()
                                    
                                    if existing_user:
                                        # Update existing user
                                        existing_user.email = user_info.get('email')
                                        existing_user.is_active = user_info.get('is_active', True)
                                        
                                        # Restore password hash if available
                                        if 'password_hash' in user_info:
                                            existing_user.password_hash = user_info['password_hash']
                                        
                                        # Restore 2FA settings if available
                                        if 'two_factor_enabled' in user_info:
                                            existing_user.two_factor_enabled = user_info['two_factor_enabled']
                                        if 'two_factor_secret' in user_info:
                                            existing_user.two_factor_secret = user_info['two_factor_secret']
                                        
                                        # Parse dates if available
                                        if user_info.get('created_at'):
                                            try:
                                                existing_user.created_at = datetime.fromisoformat(user_info['created_at'])
                                            except ValueError:
                                                pass  # Skip if date format is invalid
                                        
                                        if user_info.get('last_login'):
                                            try:
                                                existing_user.last_login = datetime.fromisoformat(user_info['last_login'])
                                            except ValueError:
                                                pass  # Skip if date format is invalid
                                        
                                        db.session.commit()
                                        success_count += 1
                                    else:
                                        # Create new user
                                        new_user = User(
                                            username=username,
                                            email=user_info.get('email'),
                                            is_active=user_info.get('is_active', True)
                                        )
                                        
                                        # Set password hash directly if available
                                        if 'password_hash' in user_info:
                                            new_user.password_hash = user_info['password_hash']
                                        else:
                                            # Set a temporary password if no hash available
                                            new_user.set_password('TemporaryPassword123!')
                                        
                                        # Set 2FA settings if available
                                        if 'two_factor_enabled' in user_info:
                                            new_user.two_factor_enabled = user_info['two_factor_enabled']
                                        if 'two_factor_secret' in user_info:
                                            new_user.two_factor_secret = user_info['two_factor_secret']
                                        
                                        # Parse dates if available
                                        if user_info.get('created_at'):
                                            try:
                                                new_user.created_at = datetime.fromisoformat(user_info['created_at'])
                                            except ValueError:
                                                pass  # Skip if date format is invalid
                                        
                                        if user_info.get('last_login'):
                                            try:
                                                new_user.last_login = datetime.fromisoformat(user_info['last_login'])
                                            except ValueError:
                                                pass  # Skip if date format is invalid
                                        
                                        db.session.add(new_user)
                                        db.session.commit()
                                        success_count += 1
                                        
                                except Exception as user_error:
                                    logger.error(f"Error restoring user {user_info.get('username')}: {user_error}")
                                    failure_count += 1
                            
                            print(f"  ✅ Users restored: {success_count} successful, {failure_count} failed")
                    else:
                        print(f"  ⚠️  Cannot automatically restore users for non-SQLite database")
            except Exception as e:
                print(f"  ❌ Error restoring users: {e}")
                logger.error(f"Error restoring users: {e}")
        
        print(f"\n✅ Configuration restored successfully")
        print(f"⚠️  You may need to restart the application for changes to take effect")
        return True
    except Exception as e:
        print(f"❌ Error restoring configuration: {e}")
        logger.error(f"Error restoring configuration: {e}")
        return False

def show_version():
    """Display version information."""
    version = "1.0.0"
    build_date = "2023-11-01"
    print(f"\nAMIVault v{version} (Build: {build_date})")
    print("Professional AWS AMI Backup Management Solution")
    print("Copyright © 2023 Secsys. All rights reserved.")
    print("\nSystem Information:")
    system_info = get_system_info()
    print(f"  • Python: {system_info['python_version']}")
    print(f"  • OS: {system_info['os']} {system_info['os_version']}")
    print(f"  • Architecture: {system_info['cpu_architecture']}")
    return True

def show_help():
    """Display help information."""
    display_logo()
    print("\nAMIVault Administration Helper Tool")
    print("\nAvailable Commands:")
    print("  python helper.py                      - Interactive mode with menu")
    print("  python helper.py --help               - Display this help message")
    print("  python helper.py --list               - List all users in the system")
    print("  python helper.py --recreate-db        - Recreate the database (warning: deletes all data)")
    print("  python helper.py --check-system       - Check system health and configuration")
    print("  python helper.py --backup-config      - Backup system configuration")
    print("  python helper.py --restore-config     - Restore system configuration")
    print("  python helper.py --version            - Display version information")
    print("  python helper.py username password email - Create/update a user non-interactively")
    print("\nFor more information, visit: https://github.com/s3csys/amivault")
    return True

def main():
    """Main function with interactive menu."""
    display_logo()
    print("\n🔧 AMIVault Administration Tool")
    print("=" * 40)
    
    while True:
        print("\nOptions:")
        print("1. Create new admin user")
        print("2. Create custom user")
        print("3. List all users")
        print("4. Delete user")
        print("5. Recreate database (⚠️  DANGER ZONE)")
        print("6. Check system health")
        print("7. Backup configuration")
        print("8. Restore configuration")
        print("9. Show version information")
        print("0. Exit")
        
        choice = input("\nSelect option (0-9): ").strip()
        
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
            # Explicitly ask for username to ensure it's not defaulting to 'admin'
            custom_username = input("Enter username for the custom user: ").strip()
            if not custom_username:
                print("❌ Username cannot be empty")
                continue
                
            user = create_admin_user(username=custom_username, interactive=True)
            if user:
                print("\n✅ Custom user created successfully!")
                print("⚠️  SECURITY REMINDER:")
                print("- Make sure to use a strong, unique password")
                print("- Consider enabling two-factor authentication if available")
                print("- Regularly update your password")
        
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
            # Check system health
            check_system()
        
        elif choice == '7':
            # Backup configuration
            backup_config()
        
        elif choice == '8':
            # Restore configuration
            restore_config()
        
        elif choice == '9':
            # Show version information
            show_version()
        
        elif choice == '0':
            print("👋 Thank you for using AMIVault Administration Tool!")
            break
        
        else:
            print("❌ Invalid option. Please try again.")

if __name__ == "__main__":
    # Note: We've already suppressed logs during the import of app.py above
    # Now we want to show the normal output of the helper script
    
    # Check if running with command line arguments
    if len(sys.argv) == 4:
        # Usage: python helper.py username password email
        username, password, email = sys.argv[1], sys.argv[2], sys.argv[3]
        print(f"Creating user from command line arguments...")
        create_admin_user(username, password, email, interactive=False)
    elif len(sys.argv) == 2:
        arg = sys.argv[1].lower()
        if arg == '--list':
            # Usage: python helper.py --list
            display_logo()
            list_users()
        elif arg == '--recreate-db':
            # Usage: python helper.py --recreate-db
            display_logo()
            recreate_database(interactive=True)
        elif arg == '--check-system':
            # Usage: python helper.py --check-system
            display_logo()
            check_system()
        elif arg == '--backup-config':
            # Usage: python helper.py --backup-config
            display_logo()
            backup_config()
        elif arg == '--restore-config':
            # Usage: python helper.py --restore-config
            display_logo()
            restore_config()
        elif arg == '--version':
            # Usage: python helper.py --version
            display_logo()
            show_version()
        elif arg == '--help':
            # Usage: python helper.py --help
            show_help()
        else:
            print("❌ Unknown argument.")
            show_help()
    else:
        # Interactive mode
        main()