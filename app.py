# import pyotp, qrcode, io, base64, boto3, pytz, os, csv, secrets, logging, json
# from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
# from dotenv import load_dotenv
# from models import db, User, Instance, BackupSettings, Backup, AWSCredential
# from datetime import datetime, timezone, timedelta, UTC
# from flask_apscheduler import APScheduler
# from io import StringIO
# from botocore.exceptions import ClientError, NoCredentialsError


# from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, make_response
# from flask_sqlalchemy import SQLAlchemy
# from werkzeug.security import generate_password_hash, check_password_hash
# from datetime import datetime, timezone, timedelta, UTC
# from flask_apscheduler import APScheduler
# from io import StringIO
# from dotenv import load_dotenv

# Remove this line
# from flask_sqlalchemy import SQLAlchemy

# Keep or add these imports
import pyotp, qrcode, io, base64, boto3, pytz, os, csv, secrets, logging, json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta, UTC
from flask_apscheduler import APScheduler
from io import StringIO
from botocore.exceptions import ClientError, NoCredentialsError
from models import db, User, Instance, BackupSettings, Backup, AWSCredential

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Basic configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production'),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///amivault.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_recycle': 300,
    },
    SCHEDULER_API_ENABLED=True,
    SCHEDULER_TIMEZONE='UTC',
    DEBUG=os.environ.get('FLASK_DEBUG', '0') == '1'
)

# Initialize extensions
db.init_app(app)
scheduler = APScheduler()
scheduler.init_app(app)

def parse_cron_expression(cron_str):
    """Parse a cron expression into kwargs for APScheduler"""
    if not cron_str or not isinstance(cron_str, str):
        raise ValueError("Invalid cron expression")

    # Handle interval format
    if cron_str.startswith('@'):
        try:
            hours = int(cron_str[1:])
            return {'trigger': 'interval', 'hours': hours}
        except ValueError:
            raise ValueError(f"Invalid interval value: {cron_str}")

    # Parse standard cron expression
    try:
        minute, hour, day, month, day_of_week = cron_str.split()
        return {
            'minute': minute,
            'hour': hour,
            'day': day,
            'month': month,
            'day_of_week': day_of_week
        }
    except ValueError:
        raise ValueError(f"Invalid cron expression format: {cron_str}")

def schedule_instance_backup(instance):
    """Schedule backup for a single instance using either Python scheduler or EventBridge"""
    try:
        # Remove any existing schedules for this instance
        job_id = f"backup_{instance.instance_id}"
        if scheduler.get_job(job_id):
            scheduler.remove_job(job_id)

        # Schedule the backup based on scheduler_type
        if instance.scheduler_type == 'python':
            # Schedule with Flask-APScheduler
            if instance.backup_frequency.startswith('@'):
                # Handle interval-based schedules
                interval = instance.backup_frequency[1:]
                scheduler.add_job(
                    id=job_id,
                    func=backup_instance,
                    args=[instance.instance_id],
                    trigger='interval',
                    hours=int(interval),
                    replace_existing=True
                )
            else:
                # Handle cron-based schedules
                cron_kwargs = parse_cron_expression(instance.backup_frequency)
                scheduler.add_job(
                    id=job_id,
                    func=backup_instance,
                    args=[instance.instance_id],
                    trigger='cron',
                    replace_existing=True,
                    **cron_kwargs
                )
            logger.info(f"Scheduled Python backup job for instance {instance.instance_id}")

    except Exception as e:
        logger.error(f"Failed to schedule backup for instance {instance.instance_id}: {e}")
        raise

def schedule_all_instance_backups():
    """Schedule backups for all active instances"""
    try:
        # Clear existing jobs first
        scheduler.remove_all_jobs()
        
        # Get active instances
        instances = Instance.query.filter_by(is_active=True).all()
        for instance in instances:
            try:
                schedule_instance_backup(instance)
                logger.info(f"Initialized backup schedule for instance {instance.instance_id}")
            except Exception as e:
                logger.error(f"Failed to initialize backup schedule for instance {instance.instance_id}: {e}")
        logger.info(f"Initialized backup schedules for {len(instances)} instances")
    except Exception as e:
        logger.error(f"Error scheduling instance backups: {e}")

# Initialize database and scheduler after app starts
with app.app_context():
    try:
        # Create database tables
        db.create_all()
        logger.info("✅ Database tables created successfully")
        
        # Initialize scheduler
        if not scheduler.running:
            scheduler.start()
            logger.info("✅ Scheduler started successfully")
            
            # Schedule backups for active instances
            schedule_all_instance_backups()
            
    except Exception as e:
        logger.error(f"Error during initialization: {e}")

# App configuration
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production'),
    SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///amivault.db'),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={
        'pool_pre_ping': True,
        'pool_recycle': 300,
    },
    SCHEDULER_API_ENABLED=True,
    SCHEDULER_TIMEZONE='UTC',
    DEBUG=os.environ.get('FLASK_DEBUG', '0') == '1'
)

# Initialize extensions
#  db = SQLAlchemy(app)
# scheduler = APScheduler()
# scheduler.init_app(app)

# # Models with extend_existing=True to avoid table redefinition errors
# class AWSCredential(db.Model):
#     __tablename__ = 'aws_credentials'
#     __table_args__ = {'extend_existing': True}
    
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), unique=True, nullable=False)
#     access_key = db.Column(db.String(100), nullable=False)
#     secret_key = db.Column(db.String(100), nullable=False)
#     region = db.Column(db.String(20), nullable=False)
#     created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
#     updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    
#     def __repr__(self):
#         return f'<AWSCredential {self.name}'
    
#     def validate_credentials(self):
#         """Validate AWS credentials by making a test API call"""
#         try:
#             # Create a boto3 session with the provided credentials
#             boto3_session = boto3.Session(
#                 aws_access_key_id=self.access_key,
#                 aws_secret_access_key=self.secret_key,
#                 region_name=self.region
#             )
            
#             # Create EC2 client
#             ec2 = boto3_session.client('ec2')
            
#             # Make a simple API call to test credentials
#             ec2.describe_regions()
            
#             return True, "Credentials validated successfully"
            
#         except Exception as e:
#             return False, str(e)

# class Instance(db.Model):
#     __tablename__ = 'instances'
#     __table_args__ = {'extend_existing': True}

#     id = db.Column(db.Integer, primary_key=True)
#     instance_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
#     instance_name = db.Column(db.String(100), nullable=False)
#     access_key = db.Column(db.String(100), nullable=False)
#     secret_key = db.Column(db.String(100), nullable=False)
#     region = db.Column(db.String(20), nullable=False)
#     backup_frequency = db.Column(db.String(64), nullable=False, default="0 2 * * *")  # Daily at 2 AM
#     retention_days = db.Column(db.Integer, nullable=False, default=7)
#     created_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False)
#     updated_at = db.Column(db.DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
#     is_active = db.Column(db.Boolean, default=True, nullable=False)
#     scheduler_type = db.Column(db.String(20), nullable=False, default='python', server_default='python')  # 'python' or 'eventbridge'

#     backups = db.relationship('Backup', backref='instance_ref', lazy=True, cascade='all, delete-orphan')

#     def __repr__(self):
#         return f'<Instance {self.instance_id}: {self.instance_name}>'
        
#     def validate_aws_credentials(self):
#         """Validate AWS credentials by making a test API call"""
#         try:
#             # Create a boto3 session with the provided credentials
#             boto3_session = boto3.Session(
#                 aws_access_key_id=self.access_key,
#                 aws_secret_access_key=self.secret_key,
#                 region_name=self.region
#             )
            
#             # Create EC2 client
#             ec2 = boto3_session.client('ec2')
            
#             # Check if instance exists and get its details
#             response = ec2.describe_instances(InstanceIds=[self.instance_id])
            
#             if 'Reservations' in response and response['Reservations']:
#                 instances = response['Reservations'][0]['Instances']
#                 if instances:
#                     instance_state = instances[0].get('State', {}).get('Name', 'unknown')
#                     return True, f"Instance found in {self.region}, state: {instance_state}"
            
#             return False, "Instance not found"
            
#         except Exception as e:
#             return False, str(e)


# class BackupSettings(db.Model):
#     __tablename__ = 'backup_settings'
#     __table_args__ = {'extend_existing': True}

#     id = db.Column(db.Integer, primary_key=True)
#     retention_days = db.Column(db.Integer, default=7, nullable=False)
#     backup_frequency = db.Column(db.String(64), default="0 2 * * *", nullable=False)  # Daily at 2 AM
#     instance_id = db.Column(db.String(64), nullable=False, default="global-config")
#     instance_name = db.Column(db.String(128), default="Global Settings")
#     created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
#     updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

#     def __repr__(self):
#         return f'<BackupSettings retention={self.retention_days}d frequency={self.backup_frequency}>'


# class Backup(db.Model):
#     __tablename__ = 'backups'
#     __table_args__ = {'extend_existing': True}

#     id = db.Column(db.Integer, primary_key=True)
#     instance_id = db.Column(db.String(64), db.ForeignKey('instances.instance_id'), nullable=False, index=True)
#     instance_name = db.Column(db.String(128), nullable=False)
#     ami_id = db.Column(db.String(64), nullable=True, index=True)
#     ami_name = db.Column(db.String(128), nullable=True)
#     timestamp = db.Column(db.DateTime, default=lambda: datetime.now(UTC), nullable=False, index=True)
#     status = db.Column(db.String(32), default='Pending', nullable=False, index=True)  # 'Pending', 'Success', 'Failed'
#     region = db.Column(db.String(32), nullable=False)
#     retention_days = db.Column(db.Integer, default=7, nullable=False)

#     def __repr__(self):
#         return f'<Backup {self.ami_id} for {self.instance_id} - {self.status}>'

# class User(db.Model):
#     __tablename__ = 'users'
#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String(80), unique=True, nullable=False)
#     email = db.Column(db.String(120), unique=True, nullable=False)
#     password_hash = db.Column(db.String(128), nullable=False)
#     created_at = db.Column(db.DateTime, default=datetime.utcnow)
#     is_active = db.Column(db.Boolean, default=True)
#     last_login = db.Column(db.DateTime, nullable=True)
#     two_factor_enabled = db.Column(db.Boolean, default=False)
#     two_factor_secret = db.Column(db.String(32), nullable=True)

#     def set_password(self, password):
#         self.password_hash = generate_password_hash(password)
#     def check_password(self, password):
#         return check_password_hash(self.password_hash, password)
#     def update_last_login(self):
#         self.last_login = datetime.now(UTC)
#         db.session.commit()


# # Initialize database and scheduler
# with app.app_context():
#     try:
#         db.create_all()
#         logger.info("✅ Database tables created successfully")

#         if not scheduler.running:
#             scheduler.start()
#             logger.info("✅ Scheduler started successfully")

#             # Schedule backups for active instances
#             instances = Instance.query.filter_by(is_active=True).all()
#             for instance in instances:
#                 try:
#                     schedule_instance_backup(instance)
#                     logger.info(f"Initialized backup schedule for instance {instance.instance_id}")
#                 except Exception as e:
#                     logger.error(f"Failed to initialize backup schedule for instance {instance.instance_id}: {e}")
#             logger.info(f"Initialized backup schedules for {len(instances)} instances")
#     except Exception as e:
#         logger.error(f"Error during initialization: {e}")

############################################################ Scheduler Functions ############################################################

def create_backup(instance_id):
    """Create backup for an instance (called by scheduler)"""
    with app.app_context():
        try:
            # Get instance and global settings
            inst = Instance.query.filter_by(instance_id=instance_id, is_active=True).first()
            if not inst:
                logger.error(f"Instance {instance_id} not found or inactive")
                return

            global_config = BackupSettings.query.first()
            if not global_config:
                logger.error("Global backup settings not found")
                return

            # Get effective retention days
            retention_days = get_effective_setting(
                inst.retention_days,
                global_config.retention_days
            )

            # Create AMI backup
            ec2_client = boto3.client(
                'ec2',
                region_name=inst.region,
                aws_access_key_id=inst.access_key,
                aws_secret_access_key=inst.secret_key
            )

            # Generate AMI name with timestamp
            timestamp_str = datetime.now(pytz.UTC).strftime("%Y%m%d_%H%M%S")
            ami_name = f"{inst.instance_name}_{timestamp_str}_backup"

            # Create backup record
            backup = Backup(
                instance_id=instance_id,
                instance_name=inst.instance_name,
                ami_name=ami_name,
                timestamp=datetime.now(UTC),
                status='Pending',
                region=inst.region,
                retention_days=retention_days,
                backup_type='scheduled'
            )
            db.session.add(backup)
            db.session.commit()

            try:
                # Create AMI
                response = ec2_client.create_image(
                    InstanceId=instance_id,
                    Name=ami_name,
                    Description=f"Scheduled backup created at {timestamp_str}",
                    NoReboot=True
                )

                ami_id = response['ImageId']
                backup.ami_id = ami_id
                backup.status = 'Success'
                db.session.commit()

                logger.info(f"Successfully created backup AMI {ami_id} for instance {instance_id}")

            except Exception as e:
                backup.status = 'Failed'
                backup.error_message = str(e)
                db.session.commit()
                logger.error(f"Failed to create backup for instance {instance_id}: {e}")
                raise

        except Exception as e:
            logger.error(f"Error in create_backup for instance {instance_id}: {e}")
            raise

def schedule_instance_backup(instance):
    """Schedule backup job for an instance using specified scheduler type"""
    try:
        job_id = f'backup-{instance.instance_id}'
        
        # Remove existing schedules first
        try:
            # Remove APScheduler job
            scheduler.remove_job(job_id)
        except Exception:
            pass
            
        try:
            # Remove EventBridge rule
            eventbridge_client = boto3.client(
                'events',
                region_name=instance.region,
                aws_access_key_id=instance.access_key,
                aws_secret_access_key=instance.secret_key
            )
            eventbridge_client.delete_rule(Name=job_id, Force=True)
        except Exception:
            pass
        
        # Create schedule based on type
        if instance.scheduler_type == 'eventbridge':
            # Create EventBridge schedule
            if instance.backup_frequency.isdigit():
                # Convert minutes to rate expression
                minutes = int(instance.backup_frequency)
                schedule_expression = f"rate({minutes} minutes)"
            else:
                # Convert cron expression to AWS cron
                cron_parts = instance.backup_frequency.strip().split()
                if len(cron_parts) != 5:
                    raise ValueError(f"Invalid cron expression: {instance.backup_frequency}")
                schedule_expression = f"cron({cron_parts[0]} {cron_parts[1]} {cron_parts[2]} {cron_parts[3]} {cron_parts[4]} ? *)"
            
            # Create EventBridge rule
            response = eventbridge_client.put_rule(
                Name=job_id,
                ScheduleExpression=schedule_expression,
                State='ENABLED',
                Description=f"Backup schedule for {instance.instance_name} ({instance.instance_id})"
            )
            
            # Create target for the rule
            target_input = {
                'instance_id': instance.instance_id,
                'instance_name': instance.instance_name,
                'region': instance.region
            }
            
            eventbridge_client.put_targets(
                Rule=job_id,
                Targets=[
                    {
                        'Id': f"{job_id}-target",
                        'Arn': response['RuleArn'],
                        'Input': json.dumps(target_input)
                    }
                ]
            )
            
            logger.info(f"Scheduled EventBridge backup job for instance {instance.instance_id} with {schedule_expression}")
            
        else:  # Python scheduler
            # Schedule with APScheduler
            if instance.backup_frequency.isdigit():
                scheduler.add_job(
                    func=create_backup,
                    trigger='interval',
                    minutes=int(instance.backup_frequency),
                    id=job_id,
                    name=f'Backup {instance.instance_name}',
                    args=[instance.instance_id],
                    replace_existing=True
                )
            else:
                scheduler.add_job(
                    func=create_backup,
                    trigger='cron',
                    id=job_id,
                    name=f'Backup {instance.instance_name}',
                    args=[instance.instance_id],
                    replace_existing=True,
                    **parse_cron_expression(instance.backup_frequency)
                )
            
            logger.info(f"Scheduled Python backup job for instance {instance.instance_id} with frequency {instance.backup_frequency}")
        
        return True
        
    except Exception as e:
        logger.error(f"Error scheduling backup for instance {instance.instance_id}: {e}")
        raise

def parse_cron_expression(cron_str):
    """Parse cron expression into kwargs for APScheduler"""
    parts = cron_str.strip().split()
    if len(parts) != 5:
        raise ValueError("Invalid cron expression")
    
    return {
        'minute': parts[0],
        'hour': parts[1],
        'day': parts[2],
        'month': parts[3],
        'day_of_week': parts[4]
    }

def reschedule_instance_backup(instance):
    """Reschedule backup job for an instance"""
    return schedule_instance_backup(instance)

def remove_instance_backup_schedule(instance_id):
    """Remove backup schedule for an instance"""
    try:
        job_id = f'backup-{instance_id}'
        scheduler.remove_job(job_id)
        logger.info(f"Removed backup schedule for instance {instance_id}")
        return True
    except Exception as e:
        logger.error(f"Error removing backup schedule for instance {instance_id}: {e}")
        raise

############################################################ Helper Functions ############################################################

def get_effective_setting(instance_value, global_value):
    """Get effective setting value, preferring instance-specific over global"""
    return instance_value if instance_value not in [None, '', 0] else global_value


def validate_cron_expression(cron_str):
    """Validate cron expression format"""
    if not cron_str or not isinstance(cron_str, str):
        return False
    
    parts = cron_str.strip().split()
    return len(parts) == 5


def validate_backup_frequency(frequency):
    """Validate backup frequency (either integer minutes or cron expression)"""
    if not frequency:
        return False, "Frequency cannot be empty"
    
    frequency = str(frequency).strip()
    
    # Try parsing as integer (minutes)
    try:
        minutes = int(frequency)
        if minutes < 1:
            return False, "Frequency must be at least 1 minute"
        if minutes > 10080:  # 1 week in minutes
            return False, "Frequency cannot exceed 1 week"
        return True, f"Every {minutes} minutes"
    except ValueError:
        pass
    
    # Try parsing as cron expression
    if validate_cron_expression(frequency):
        return True, f"Cron: {frequency}"
    
    return False, "Invalid frequency format. Use minutes (e.g., 60) or cron (e.g., '0 2 * * *')"


def create_default_admin():
    """Create default admin user if none exists"""
    try:
        if not User.query.filter_by(username='admin').first():
            default_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'admin123')
            default_admin = User(
                username='admin', 
                email=os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
            )
            default_admin.set_password(default_password)
            db.session.add(default_admin)
            db.session.commit()
            logger.info(f"✅ Default admin user created: admin / {default_password}")
            return True
    except Exception as e:
        logger.error(f"Error creating default admin user: {e}")
        return False


def create_default_backup_settings():
    """Create default backup settings if none exist"""
    try:
        if not BackupSettings.query.first():
            config = BackupSettings(
                instance_id="global-config",
                instance_name="Global Settings",
                retention_days=7,
                backup_frequency="0 2 * * *"  # Daily at 2 AM
            )
            db.session.add(config)
            db.session.commit()
            logger.info("✅ Default backup settings created")
            return True
    except Exception as e:
        logger.error(f"Error creating default backup settings: {e}")
        return False


def init_database():
    """Initialize database with default data"""
    try:
        db.create_all()
        logger.info("✅ Database tables created/verified")
        
        create_default_admin()
        create_default_backup_settings()
        
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False


############################################################ Routes ############################################################

############################################################ Routes ############################################################

@app.route('/')
def dashboard():
    """Main dashboard showing backup overview and recent activity"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user or not user.is_active:
        session.clear()
        flash("Account is inactive", "warning")
        return redirect(url_for('login'))
    
    # Get dashboard statistics
    total_instances = Instance.query.filter_by(is_active=True).count()
    recent_backups = Backup.query.order_by(Backup.created_at.desc()).limit(10).all()
    # recent_backups = Backup.query.order_by(Backup.timestamp.desc()).limit(10).all()
    failed_backups = Backup.query.filter_by(status='Failed').count()
    successful_backups = Backup.query.filter_by(status='Success').count()
    
    # Get backup settings
    backup_settings = BackupSettings.query.first()
    
    stats = {
        'total_instances': total_instances,
        'successful_backups': successful_backups,
        'failed_backups': failed_backups,
        'recent_backups': recent_backups
    }
    
    return render_template('dashboard.html', 
                         user=user, 
                         stats=stats,
                         backup_settings=backup_settings)


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User authentication with optional 2FA"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            error_msg = "Username and password are required"
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error_msg})
            flash(error_msg, "danger")
            return render_template('login.html')
        
        user = User.query.filter_by(username=username, is_active=True).first()
        
        if user and user.check_password(password):
            # Update last login timestamp
            user.update_last_login()
            
            # Check if 2FA is enabled
            if user.two_factor_enabled and user.two_factor_secret:
                session['pending_2fa_user'] = user.username
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'require_2fa': True})
                return render_template('login.html', require_2fa=True, username=username)
            
            # Direct login without 2FA
            session['username'] = user.username
            session['login_time'] = datetime.now(UTC).isoformat()
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
            return redirect(url_for('dashboard'))
        else:
            error_msg = "Invalid username or password"
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error_msg})
            flash(error_msg, "danger")
    
    return render_template('login.html')


@app.route('/login_2fa', methods=['POST'])
def login_2fa():
    """Handle 2FA verification"""
    pending_user = session.get('pending_2fa_user')
    if not pending_user:
        return jsonify({'success': False, 'error': 'No 2FA session found. Please login again.'})
    
    user = User.query.filter_by(username=pending_user, is_active=True).first()
    if not user or not user.two_factor_enabled or not user.two_factor_secret:
        session.pop('pending_2fa_user', None)
        return jsonify({'success': False, 'error': '2FA not properly configured for this user.'})
    
    code = request.form.get('code', '').strip()
    if not code:
        return jsonify({'success': False, 'error': '2FA code is required.'})
    
    totp = pyotp.TOTP(user.two_factor_secret)
    if totp.verify(code, valid_window=1):  # Allow 30-second window
        session.pop('pending_2fa_user', None)
        session['username'] = user.username
        session['login_time'] = datetime.now(UTC).isoformat()
        user.update_last_login()
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    else:
        return jsonify({'success': False, 'error': 'Invalid 2FA code. Please try again.'})


@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    """Setup two-factor authentication for user"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))

    # Generate or retrieve existing secret
    if not user.two_factor_secret:
        secret = pyotp.random_base32()
        user.two_factor_secret = secret
        db.session.commit()
    else:
        secret = user.two_factor_secret

    # Create TOTP URI for QR code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name="AWS Backup Manager"
    )

    # Generate QR code as base64
    try:
        img = qrcode.make(totp_uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    except Exception as e:
        logger.error(f"Error generating QR code: {e}")
        flash("Error generating QR code", "danger")
        return redirect(url_for('user_settings'))

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not code:
            flash("Please enter the verification code", "warning")
            return render_template('setup_2fa.html', qr_b64=qr_b64, secret=secret)
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            user.two_factor_enabled = True
            db.session.commit()
            flash("Two-factor authentication enabled successfully!", "success")
            return redirect(url_for('user_settings'))
        else:
            flash("Invalid verification code. Please try again.", "danger")

    return render_template('setup_2fa.html', qr_b64=qr_b64, secret=secret)


@app.route('/disable-2fa', methods=['POST'])
def disable_2fa():
    """Disable two-factor authentication"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})
    
    password = request.form.get('password', '')
    if not user.check_password(password):
        return jsonify({'success': False, 'error': 'Invalid password'})
    
    user.two_factor_enabled = False
    user.two_factor_secret = None
    db.session.commit()
    
    return jsonify({'success': True, 'message': '2FA disabled successfully'})




@app.route('/instances')
def instances():
    """List all registered EC2 instances"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    instances = Instance.query.filter_by(is_active=True).order_by(Instance.created_at.desc()).all()
    return render_template('instances.html', instances=instances)


@app.route('/backups')
def backups():
    """List all backup records with filtering options"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get filter parameters
    status_filter = request.args.get('status')
    instance_filter = request.args.get('instance')
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Build query
    query = Backup.query
    
    if status_filter:
        query = query.filter(Backup.status == status_filter)
    
    if instance_filter:
        query = query.filter(Backup.instance_id == instance_filter)
    
    # Paginate results
    backups = query.order_by(Backup.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get instances for filter dropdown
    instances = Instance.query.filter_by(is_active=True).all()
    
    return render_template('backups.html', 
                         backups=backups, 
                         instances=instances,
                         current_status=status_filter,
                         current_instance=instance_filter)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Global backup settings configuration"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    backup_settings = BackupSettings.query.first()
    if not backup_settings:
        backup_settings = BackupSettings()
        db.session.add(backup_settings)
        db.session.commit()
    
    if request.method == 'POST':
        try:
            retention_days = int(request.form.get('retention_days', 7))
            backup_frequency = request.form.get('backup_frequency', '0 2 * * *').strip()
            email_notifications = 'email_notifications' in request.form
            notification_email = request.form.get('notification_email', '').strip()
            max_concurrent_backups = int(request.form.get('max_concurrent_backups', 5))
            backup_timeout_minutes = int(request.form.get('backup_timeout_minutes', 60))
            
            # Validate inputs
            if retention_days < 1 or retention_days > 365:
                flash("Retention days must be between 1 and 365", "danger")
                return render_template('settings.html', settings=backup_settings)
            
            is_valid, msg = validate_backup_frequency(backup_frequency)
            if not is_valid:
                flash(f"Invalid backup frequency: {msg}", "danger")
                return render_template('settings.html', settings=backup_settings)
            
            # Update settings
            backup_settings.retention_days = retention_days
            backup_settings.backup_frequency = backup_frequency
            backup_settings.email_notifications = email_notifications
            backup_settings.notification_email = notification_email if email_notifications else None
            backup_settings.max_concurrent_backups = max_concurrent_backups
            backup_settings.backup_timeout_minutes = backup_timeout_minutes
            backup_settings.updated_at = datetime.now(UTC)
            
            db.session.commit()
            flash("Settings updated successfully", "success")
            
        except ValueError as e:
            flash("Invalid input values", "danger")
        except Exception as e:
            logger.error(f"Error updating settings: {e}")
            flash("Error updating settings", "danger")
    
    return render_template('settings.html', settings=backup_settings)


@app.route('/logout')
def logout():
    """User logout and session cleanup"""
    username = session.get('username')
    
    if username:
        flash("You have been logged out successfully", "info")
        logger.info(f"User {username} logged out")
    
    session.clear()
    return redirect(url_for('login'))

############################################################ User Management ############################################################

@app.route('/user-settings', methods=['GET', 'POST'])
def user_settings():
    """User account settings and profile management"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    # Get all users for admin view (only if current user is admin)
    users = None
    if user.username == 'admin':
        users = User.query.all()
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            email = request.form.get('email', '').strip()
            if email and email != user.email:
                user.email = email
                db.session.commit()
                flash("Profile updated successfully", "success")
        
        elif action == 'change_password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            
            if not user.check_password(current_password):
                flash("Current password is incorrect", "danger")
            elif new_password != confirm_password:
                flash("New passwords do not match", "danger")
            elif len(new_password) < 6:
                flash("New password must be at least 6 characters", "danger")
            else:
                user.set_password(new_password)
                db.session.commit()
                flash("Password changed successfully", "success")
        
        return redirect(url_for('user_settings'))
    
    return render_template('user_settings.html', user=user, users=users, current_user=user)


@app.route('/add-user', methods=['POST'])
def add_user():
    """Add new user (admin only)"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user or current_user.username != 'admin':
        flash("Only admin can add users", "danger")
        return redirect(url_for('user_settings'))
    
    try:
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not username or not email or not password:
            flash("All fields are required", "danger")
            return redirect(url_for('user_settings'))
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f"Username '{username}' already exists", "danger")
            return redirect(url_for('user_settings'))
        
        user = User(
            username=username,
            email=email
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash(f"User '{username}' added successfully", "success")
        
    except Exception as e:
        logger.error(f"Error adding user: {e}")
        flash("Error adding user", "danger")
    
    return redirect(url_for('user_settings'))


@app.route('/delete-user', methods=['POST'])
def delete_user():
    """Delete user (admin only)"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user or current_user.username != 'admin':
        flash("Only admin can delete users", "danger")
        return redirect(url_for('user_settings'))
    
    try:
        username_to_delete = request.form.get('username', '').strip()
        
        if not username_to_delete:
            flash("Username is required", "danger")
            return redirect(url_for('user_settings'))
        
        if username_to_delete == 'admin':
            flash("Cannot delete admin user", "danger")
            return redirect(url_for('user_settings'))
        
        if username_to_delete == current_user.username:
            flash("Cannot delete your own account", "danger")
            return redirect(url_for('user_settings'))
        
        user = User.query.filter_by(username=username_to_delete).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            flash(f"User '{username_to_delete}' deleted successfully", "info")
        else:
            flash(f"User '{username_to_delete}' not found", "warning")
            
    except Exception as e:
        logger.error(f"Error deleting user: {e}")
        flash("Error deleting user", "danger")
    
    return redirect(url_for('user_settings'))


@app.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset user password (admin only)"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user or current_user.username != 'admin':
        flash("Only admin can reset passwords", "danger")
        return redirect(url_for('user_settings'))
    
    try:
        username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '')
        
        if not username or not new_password:
            flash("Username and new password are required", "danger")
            return redirect(url_for('user_settings'))
        
        if len(new_password) < 6:
            flash("Password must be at least 6 characters", "danger")
            return redirect(url_for('user_settings'))
        
        user = User.query.filter_by(username=username).first()
        if not user:
            flash(f"User '{username}' not found", "danger")
            return redirect(url_for('user_settings'))
        
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password reset successfully for user '{username}'", "success")
        
    except Exception as e:
        logger.error(f"Error resetting password: {e}")
        flash("Error resetting password", "danger")
    
    return redirect(url_for('user_settings'))


@app.route('/toggle-user-status', methods=['POST'])
def toggle_user_status():
    """Toggle user active/inactive status (admin only)"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    current_user = User.query.filter_by(username=session['username']).first()
    if not current_user or current_user.username != 'admin':
        return jsonify({'success': False, 'error': 'Only admin can toggle user status'})
    
    try:
        username = request.form.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'})
        
        if username == 'admin':
            return jsonify({'success': False, 'error': 'Cannot deactivate admin user'})
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'})
        
        user.is_active = not user.is_active
        db.session.commit()
        
        status = "activated" if user.is_active else "deactivated"
        return jsonify({
            'success': True, 
            'message': f"User '{username}' {status} successfully",
            'is_active': user.is_active
        })
        
    except Exception as e:
        logger.error(f"Error toggling user status: {e}")
        return jsonify({'success': False, 'error': 'Error updating user status'})


@app.route('/reinit-db', methods=['POST'])
def reinit_db():
    """Reinitialize database (admin only)"""
    # Ensure user is logged in
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': "You must be logged in."}), 403

    # Only allow admin to perform this action
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.username != 'admin':
        return jsonify({'status': 'error', 'message': "Only admin can reinitialize the database."}), 403

    try:
        # Get password from request or generate a secure one
        data = request.get_json() if request.is_json else {}
        password = data.get('password') or request.form.get('password')
        
        if not password:
            password = secrets.token_urlsafe(16)

        username = "admin"
        email = "admin@example.com"

        # Drop all tables and recreate them
        db.drop_all()
        db.create_all()

        # Create default admin user
        admin_user = User(username=username, email=email)
        admin_user.set_password(password)
        db.session.add(admin_user)
        
        # Create default backup settings
        backup_settings = BackupSettings(
            instance_id="global-config",
            instance_name="Global Settings",
            retention_days=7,
            backup_frequency="0 2 * * *"
        )
        db.session.add(backup_settings)
        
        db.session.commit()

        logger.info("Database reinitialized successfully")
        
        return jsonify({
            'status': 'success',
            'username': username,
            'password': password,
            'email': email,
            'message': "Database reinitialized successfully. Default admin user recreated."
        })
        
    except Exception as e:
        logger.error(f"Error reinitializing database: {e}")
        return jsonify({
            'status': 'error',
            'message': f"Error reinitializing database: {str(e)}"
        }), 500

############################################################ AWS Credentials ############################################################

# @app.route('/aws-credentials', methods=['GET'])
# def aws_credentials():
#     """Display and manage AWS credentials"""
#     if 'username' not in session:
#         return redirect(url_for('login'))
    
#     credentials = AWSCredential.query.all()
#     return render_template('aws_credentials.html', credentials=credentials)

@app.route('/aws-credentials')
def aws_credentials():
    """Redirect to AWS instances page"""
    return redirect(url_for('aws_instances'))

# @app.route('/add-aws-credential', methods=['POST'])
# def add_aws_credential():
#     """Add a new AWS credential set"""
#     if 'username' not in session:
#         return redirect(url_for('login'))
    
#     try:
#         name = request.form.get('name', '').strip()
#         access_key = request.form.get('access_key', '').strip()
#         secret_key = request.form.get('secret_key', '').strip()
#         region = request.form.get('region', '').strip()
#         custom_region = request.form.get('custom_region', '').strip()
        
#         if region == 'custom':
#             region = custom_region
        
#         if not all([name, access_key, secret_key, region]):
#             flash("All fields are required", "danger")
#             return redirect(url_for('aws_credentials'))
        
#         # Check if name already exists
#         existing = AWSCredential.query.filter_by(name=name).first()
#         if existing:
#             flash(f"Credential name '{name}' already exists", "danger")
#             return redirect(url_for('aws_credentials'))
        
#         # Create and validate new credential
#         credential = AWSCredential(
#             name=name,
#             access_key=access_key,
#             secret_key=secret_key,
#             region=region
#         )
        
#         is_valid, msg = credential.validate_credentials()
#         if not is_valid:
#             flash(f"Invalid AWS credentials: {msg}", "danger")
#             return redirect(url_for('aws_credentials'))
        
#         db.session.add(credential)
#         db.session.commit()
#         flash(f"AWS credentials '{name}' added successfully", "success")
        
#     except Exception as e:
#         logger.error(f"Error adding AWS credential: {e}")
#         flash("An error occurred while adding the AWS credential", "danger")
    
#     return redirect(url_for('aws_credentials'))

@app.route('/add-aws-credential', methods=['POST'])
def add_aws_credential():
    """Add a new AWS credential set"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        name = request.form.get('name', '').strip()
        access_key = request.form.get('access_key', '').strip()
        secret_key = request.form.get('secret_key', '').strip()
        region = request.form.get('region', '').strip()
        custom_region = request.form.get('custom_region', '').strip()
        
        if region == 'custom':
            region = custom_region
        
        if not all([name, access_key, secret_key, region]):
            flash("All fields are required", "danger")
            return redirect(url_for('aws_instances'))
        
        # Check if name already exists
        existing = AWSCredential.query.filter_by(name=name).first()
        if existing:
            flash(f"Credential name '{name}' already exists", "danger")
            return redirect(url_for('aws_instances'))
        
        # Get current user
        current_user = User.query.filter_by(username=session['username']).first()
        
        # Create and validate new credential
        credential = AWSCredential(
            name=name,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            user_id=current_user.id if current_user else None
        )
        
        is_valid, msg = credential.validate_credentials()
        if not is_valid:
            flash(f"Invalid AWS credentials: {msg}", "danger")
            return redirect(url_for('aws_instances'))
        
        db.session.add(credential)
        db.session.commit()
        flash(f"AWS credentials '{name}' added successfully", "success")
        
    except Exception as e:
        logger.error(f"Error adding AWS credential: {e}")
        flash("An error occurred while adding the AWS credential", "danger")
    
    return redirect(url_for('aws_instances'))

#@app.route('/delete-aws-credential/<int:credential_id>', methods=['POST'])
#def delete_aws_credential(credential_id):
#    """Delete an AWS credential set"""
#    if 'username' not in session:
#        return redirect(url_for('login'))
#    
#    try:
#        credential = AWSCredential.query.get(credential_id)
#        if not credential:
#            flash("AWS credential not found", "danger")
#            return redirect(url_for('aws_credentials'))
#        
#        # Check if credential is in use
#        instances = Instance.query.filter_by(access_key=credential.access_key, secret_key=credential.secret_key).all()
#        if instances:
#            flash("Cannot delete credential that is in use by instances", "danger")
#            return redirect(url_for('aws_credentials'))
#        
#        db.session.delete(credential)
#        db.session.commit()
#        flash(f"AWS credential '{credential.name}' deleted successfully", "success")
#        
#    except Exception as e:
#        logger.error(f"Error deleting AWS credential: {e}")
#        flash("An error occurred while deleting the AWS credential", "danger")
#    
#    return redirect(url_for('aws_credentials'))

@app.route('/delete-aws-credential/<int:credential_id>', methods=['POST'])
def delete_aws_credential(credential_id):
    """Delete an AWS credential set"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        credential = AWSCredential.query.get(credential_id)
        if not credential:
            flash("AWS credential not found", "danger")
            return redirect(url_for('aws_instances'))
        
        # Check if credential is in use
        instances = Instance.query.filter_by(access_key=credential.access_key, secret_key=credential.secret_key).all()
        if instances:
            flash("Cannot delete credential that is in use by instances", "danger")
            return redirect(url_for('aws_instances'))
        
        db.session.delete(credential)
        db.session.commit()
        flash(f"AWS credential '{credential.name}' deleted successfully", "success")
        
    except Exception as e:
        logger.error(f"Error deleting AWS credential: {e}")
        flash("An error occurred while deleting the AWS credential", "danger")
    
    return redirect(url_for('aws_instances'))

@app.route('/delete-aws-credential/<int:credential_id>', methods=['POST'])
def delete_aws_credential_ajax(credential_id):
    """Delete an AWS credential set via AJAX"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    try:
        credential = AWSCredential.query.get(credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'AWS credential not found'})
        
        # Check if credential is in use
        instances = Instance.query.filter_by(access_key=credential.access_key, secret_key=credential.secret_key).all()
        if instances:
            return jsonify({'success': False, 'error': 'Cannot delete credential that is in use by instances'})
        
        db.session.delete(credential)
        db.session.commit()
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Error deleting AWS credential: {e}")
        return jsonify({'success': False, 'error': str(e)})

############################################################ AWS Instances ############################################################

@app.route('/aws-instances', methods=['GET'])
def aws_instances():
    """Display and manage AWS EC2 instances with enhanced features"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Get filter parameters
    status_filter = request.args.get('status', 'all')
    region_filter = request.args.get('region', 'all')
    search_query = request.args.get('search', '').strip()
    
    # Build query with filters
    query = Instance.query
    
    if status_filter == 'active':
        query = query.filter_by(is_active=True)
    elif status_filter == 'inactive':
        query = query.filter_by(is_active=False)
    
    if region_filter != 'all':
        query = query.filter_by(region=region_filter)
    
    if search_query:
        query = query.filter(
            db.or_(
                Instance.instance_name.ilike(f'%{search_query}%'),
                Instance.instance_id.ilike(f'%{search_query}%')
            )
        )
    
    instances = query.order_by(Instance.created_at.desc()).all()
    
    # Get unique regions for filter dropdown
    regions = db.session.query(Instance.region).distinct().all()
    regions = [r[0] for r in regions if r[0]]
    
    # Get backup statistics for each instance
    instance_stats = {}
    for instance in instances:
        stats = {
            'total_backups': Backup.query.filter_by(instance_id=instance.instance_id).count(),
            'successful_backups': Backup.query.filter_by(instance_id=instance.instance_id, status='Success').count(),
            'failed_backups': Backup.query.filter_by(instance_id=instance.instance_id, status='Failed').count(),
            'last_backup': Backup.query.filter_by(instance_id=instance.instance_id).order_by(Backup.timestamp.desc()).first()
        }
        instance_stats[instance.instance_id] = stats
    
    # Fetch AWS credentials for the dropdown
    aws_credentials = AWSCredential.query.all()
    
    return render_template('aws_instances.html', 
                         instances=instances, 
                         instance_stats=instance_stats,
                         regions=regions,
                         current_status=status_filter,
                         current_region=region_filter,
                         search_query=search_query,
                         aws_credentials=aws_credentials)


@app.route('/add-instance', methods=['GET', 'POST'])
def add_instance():
    """Add new AWS EC2 instance with comprehensive validation"""
    from flask import session
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            # Get form data
            instance_id = request.form.get('instance_id', '').strip()
            instance_name = request.form.get('instance_name', '').strip()
            access_key = request.form.get('access_key', '').strip()
            secret_key = request.form.get('secret_key', '').strip()
            region = request.form.get('region', '').strip()
            custom_region = request.form.get('custom_region', '').strip()
            backup_frequency = request.form.get('backup_frequency', '').strip()
            custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
            retention_days = request.form.get('retention_days', 7, type=int)
            
            # Validation
            if not all([instance_id, instance_name, access_key, secret_key]):
                flash("All required fields must be filled", "danger")
                return render_template('aws_instances.html')
            
            # Handle custom region
            if region == 'custom':
                region = custom_region
            if not region:
                flash("Region is required", "danger")
                return render_template('aws_instances.html')
            
            # Handle custom backup frequency
            if backup_frequency == 'custom':
                backup_frequency = custom_backup_frequency
            if not backup_frequency:
                flash("Backup frequency is required", "danger")
                return render_template('aws_instances.html')
            
            # Validate backup frequency
            is_valid, msg = validate_backup_frequency(backup_frequency)
            if not is_valid:
                flash(f"Invalid backup frequency: {msg}", "danger")
                return render_template('aws_instances.html')
            
            # Validate retention days
            if retention_days < 1 or retention_days > 365:
                flash("Retention days must be between 1 and 365", "danger")
                return render_template('aws_instances.html')
            
            # Check if instance already exists
            existing_instance = Instance.query.filter_by(instance_id=instance_id).first()
            if existing_instance:
                flash(f"Instance '{instance_id}' already exists in the system", "danger")
                return render_template('aws_instances.html')
            
            # Validate AWS credentials and instance existence
            try:
                # Create a boto3 session with the provided credentials
                boto3_session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    region_name=region
                )
                
                # Create EC2 client
                ec2 = boto3_session.client('ec2')
                
                # Check if instance exists and get its details
                response = ec2.describe_instances(InstanceIds=[instance_id])
                
                # If we get here, instance exists. Now check its name
                if 'Reservations' in response and response['Reservations']:
                    instances = response['Reservations'][0]['Instances']
                    if instances:
                        # Find the Name tag
                        actual_name = None
                        for tag in instances[0].get('Tags', []):
                            if tag['Key'] == 'Name':
                                actual_name = tag['Value']
                                break
                        
                        # If instance has a name tag and it doesn't match user input
                        if actual_name and actual_name != instance_name:
                            flash(f"Warning: AWS instance name is '{actual_name}', but you entered '{instance_name}'. The name has been updated.", "warning")
                            instance_name = actual_name
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'InvalidInstanceID.NotFound':
                    flash(f"Instance ID '{instance_id}' not found in AWS. Please check the ID and try again.", "error")
                elif error_code == 'AuthFailure' or error_code == 'UnauthorizedOperation':
                    flash("AWS authentication failed. Please check your access key and secret key.", "error")
                else:
                    flash(f"AWS error: {str(e)}", "error")
                return render_template('aws_instances.html')
            except NoCredentialsError:
                flash("Invalid AWS credentials. Please check your access key and secret key.", "error")
                return render_template('aws_instances.html')
            except Exception as e:
                flash(f"Error validating AWS details: {str(e)}", "error")
                return render_template('aws_instances.html')

            # Check if we need to save the credentials
            save_credentials = request.form.get('save_credentials') == 'on'
            if save_credentials:
                credential_name = request.form.get('credential_name', '').strip()
                if not credential_name:
                    flash("Credential name is required when saving credentials", "danger")
                    return render_template('aws_instances.html')
                
                # Check if credential name already exists
                existing_credential = AWSCredential.query.filter_by(name=credential_name).first()
                if existing_credential:
                    flash(f"Credential name '{credential_name}' already exists", "danger")
                    return render_template('aws_instances.html')
                
                # Get current user
                current_username = session.get('username')
                current_user = User.query.filter_by(username=current_username).first()
                
                # Save the credentials with user_id
                new_credential = AWSCredential(
                    name=credential_name,
                    access_key=access_key,
                    secret_key=secret_key,
                    region=region
                )
                
                # Only set user_id if we have a valid user
                if current_user:
                    new_credential.user_id = current_user.id
                    
                db.session.add(new_credential)
                db.session.commit()
                flash(f"Credentials '{credential_name}' saved successfully", "success")

            # If validation passes, add the instance to the database
            inst = Instance(
                instance_id=instance_id,
                instance_name=instance_name,
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                backup_frequency=backup_frequency,
                retention_days=retention_days
            )
            db.session.add(inst)
            db.session.commit()
            
            username = session['username'] if 'username' in session else 'unknown'
            logger.info(f"Instance {instance_id} added successfully by {username}")
            flash(f"Instance '{instance_name}' added successfully!", "success")
            
            # Schedule backup for this instance if scheduler is available
            try:
                schedule_instance_backup(inst)
                flash("Backup schedule created", "info")
            except Exception as e:
                logger.warning(f"Could not schedule backup for {instance_id}: {e}")
            
            return redirect(url_for('aws_instances'))
            
        except ValueError as e:
            flash("Invalid input values provided", "danger")
        except Exception as e:
            logger.error(f"Error adding instance: {e}")
            flash("An error occurred while adding the instance", "danger")
    
    return render_template('aws_instances.html')


@app.route('/update-instance/<instance_id>', methods=['POST'])
def update_instance(instance_id):
    """Update existing AWS EC2 instance configuration"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            flash(f"Instance '{instance_id}' not found", "danger")
            return redirect(url_for('aws_instances'))
        
        # Get form data
        instance_name = request.form.get('instance_name', '').strip()
        access_key = request.form.get('access_key', '').strip()
        secret_key = request.form.get('secret_key', '').strip()
        region = request.form.get('region', '').strip()
        backup_frequency = request.form.get('backup_frequency', '').strip()
        custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
        retention_days = request.form.get('retention_days', 7, type=int)
        
        # Handle custom backup frequency
        if backup_frequency == 'custom':
            backup_frequency = custom_backup_frequency
        
        # Validation
        if not all([instance_name, backup_frequency]):
            flash("Instance name and backup frequency are required", "danger")
            return redirect(url_for('aws_instances'))
        
        # Validate backup frequency
        is_valid, msg = validate_backup_frequency(backup_frequency)
        if not is_valid:
            flash(f"Invalid backup frequency: {msg}", "danger")
            return redirect(url_for('aws_instances'))
        
        # Validate retention days
        if retention_days < 1 or retention_days > 365:
            flash("Retention days must be between 1 and 365", "danger")
            return redirect(url_for('aws_instances'))
        
        # Update instance
        old_frequency = instance.backup_frequency
        instance.instance_name = instance_name
        instance.backup_frequency = backup_frequency
        instance.retention_days = retention_days
        instance.updated_at = datetime.now(UTC)
        
        # Update AWS credentials if provided
        if access_key and secret_key:
            instance.access_key = access_key
            instance.secret_key = secret_key
            
            # Validate new credentials
            is_valid, validation_msg = instance.validate_aws_credentials()
            if not is_valid:
                flash(f"AWS Validation Error: {validation_msg}", "danger")
                return redirect(url_for('aws_instances'))
        
        if region:
            instance.region = region
        
        db.session.commit()
        
        # Reschedule backup if frequency changed
        if old_frequency != backup_frequency:
            try:
                reschedule_instance_backup(instance)
                flash("Backup schedule updated", "info")
            except Exception as e:
                logger.warning(f"Could not reschedule backup for {instance_id}: {e}")
        
        logger.info(f"Instance {instance_id} updated by {session['username']}")
        flash(f"Instance '{instance_name}' updated successfully!", "success")
        
    except ValueError as e:
        flash("Invalid input values provided", "danger")
    except Exception as e:
        logger.error(f"Error updating instance {instance_id}: {e}")
        flash("An error occurred while updating the instance", "danger")
    
    return redirect(url_for('aws_instances'))


@app.route('/delete-instance/<instance_id>', methods=['POST'])
def delete_instance(instance_id):
    """Delete AWS EC2 instance and all associated data"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            flash(f"Instance '{instance_id}' not found", "danger")
            return redirect(url_for('aws_instances'))
        
        instance_name = instance.instance_name
        
        # Get backup count for confirmation
        backup_count = Backup.query.filter_by(instance_id=instance_id).count()
        
        # Delete associated backups first (cascade should handle this, but being explicit)
        Backup.query.filter_by(instance_id=instance_id).delete()
        
        # Remove scheduled backup job
        try:
            remove_instance_backup_schedule(instance_id)
        except Exception as e:
            logger.warning(f"Could not remove backup schedule for {instance_id}: {e}")
        
        # Delete instance
        db.session.delete(instance)
        db.session.commit()
        
        logger.info(f"Instance {instance_id} deleted by {session['username']} (had {backup_count} backups)")
        flash(f"Instance '{instance_name}' and {backup_count} associated backup records deleted successfully!", "success")
        
    except Exception as e:
        logger.error(f"Error deleting instance {instance_id}: {e}")
        flash("An error occurred while deleting the instance", "danger")
    
    return redirect(url_for('aws_instances'))


@app.route('/toggle-instance/<instance_id>', methods=['POST'])
def toggle_instance(instance_id):
    """Toggle instance active/inactive status"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            return jsonify({'success': False, 'error': 'Instance not found'})
        
        instance.is_active = not instance.is_active
        instance.updated_at = datetime.now(UTC)
        db.session.commit()
        
        # Handle backup scheduling
        if instance.is_active:
            try:
                schedule_instance_backup(instance)
                msg = f"Instance '{instance.instance_name}' activated and backup scheduled"
            except Exception as e:
                logger.warning(f"Could not schedule backup for {instance_id}: {e}")
                msg = f"Instance '{instance.instance_name}' activated (backup scheduling failed)"
        else:
            try:
                remove_instance_backup_schedule(instance_id)
                msg = f"Instance '{instance.instance_name}' deactivated and backup unscheduled"
            except Exception as e:
                logger.warning(f"Could not remove backup schedule for {instance_id}: {e}")
                msg = f"Instance '{instance.instance_name}' deactivated"
        
        logger.info(f"Instance {instance_id} toggled by {session['username']}")
        
        return jsonify({
            'success': True,
            'message': msg,
            'is_active': instance.is_active
        })
        
    except Exception as e:
        logger.error(f"Error toggling instance {instance_id}: {e}")
        return jsonify({'success': False, 'error': 'Error updating instance status'})


@app.route('/test-instance/<instance_id>', methods=['POST'])
def test_instance(instance_id):
    """Test AWS credentials and instance connectivity"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            return jsonify({'success': False, 'error': 'Instance not found'})
        
        is_valid, message = instance.validate_aws_credentials()
        
        if is_valid:
            # Update last validation time
            instance.updated_at = datetime.now(UTC)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': f"✅ Connection successful: {message}"
            })
        else:
            return jsonify({
                'success': False,
                'message': f"❌ Connection failed: {message}"
            })
            
    except Exception as e:
        logger.error(f"Error testing instance {instance_id}: {e}")
        return jsonify({
            'success': False,
            'error': f"Test failed: {str(e)}"
        })


@app.route('/instance-details/<instance_id>')
def instance_details(instance_id):
    """Get detailed information about an instance"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            flash(f"Instance '{instance_id}' not found", "danger")
            return redirect(url_for('aws_instances'))
        
        # Get backup history
        backups = Backup.query.filter_by(instance_id=instance_id).order_by(Backup.timestamp.desc()).limit(20).all()
        
        # Get backup statistics
        total_backups = Backup.query.filter_by(instance_id=instance_id).count()
        successful_backups = Backup.query.filter_by(instance_id=instance_id, status='Success').count()
        failed_backups = Backup.query.filter_by(instance_id=instance_id, status='Failed').count()
        
        # Calculate success rate
        success_rate = (successful_backups / total_backups * 100) if total_backups > 0 else 0
        
        # Get latest backup status
        latest_backup = Backup.query.filter_by(instance_id=instance_id).order_by(Backup.timestamp.desc()).first()
        
        stats = {
            'total_backups': total_backups,
            'successful_backups': successful_backups,
            'failed_backups': failed_backups,
            'success_rate': round(success_rate, 1),
            'latest_backup': latest_backup
        }
        
        return render_template('instance_details.html', 
                             instance=instance, 
                             backups=backups, 
                             stats=stats)
        
    except Exception as e:
        logger.error(f"Error loading instance details for {instance_id}: {e}")
        flash("Error loading instance details", "danger")
        return redirect(url_for('aws_instances'))


@app.route('/bulk-action', methods=['POST'])
def bulk_action():
    """Perform bulk actions on multiple instances"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    try:
        action = request.form.get('action')
        instance_ids = request.form.getlist('instance_ids')
        
        if not action or not instance_ids:
            return jsonify({'success': False, 'error': 'Action and instance selection required'})
        
        processed = 0
        errors = []
        
        for instance_id in instance_ids:
            try:
                instance = Instance.query.filter_by(instance_id=instance_id).first()
                if not instance:
                    errors.append(f"Instance {instance_id} not found")
                    continue
                
                if action == 'activate':
                    instance.is_active = True
                    schedule_instance_backup(instance)
                elif action == 'deactivate':
                    instance.is_active = False
                    remove_instance_backup_schedule(instance_id)
                elif action == 'delete':
                    # Delete backups first
                    Backup.query.filter_by(instance_id=instance_id).delete()
                    remove_instance_backup_schedule(instance_id)
                    db.session.delete(instance)
                else:
                    errors.append(f"Unknown action: {action}")
                    continue
                
                processed += 1
                
            except Exception as e:
                errors.append(f"Error processing {instance_id}: {str(e)}")
        
        db.session.commit()
        
        result = {
            'success': True,
            'processed': processed,
            'message': f"Successfully processed {processed} instances"
        }
        
        if errors:
            result['errors'] = errors
            result['message'] += f" with {len(errors)} errors"
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in bulk action: {e}")
        return jsonify({'success': False, 'error': f"Bulk action failed: {str(e)}"})


@app.route('/export-instances')
def export_instances():
    """Export instances configuration to CSV"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        instances = Instance.query.all()
        
        # Create CSV data
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Instance ID', 'Instance Name', 'Region', 'Backup Frequency',
            'Retention Days', 'Status', 'Created At', 'Last Updated'
        ])
        
        # Data rows
        for instance in instances:
            writer.writerow([
                instance.instance_id,
                instance.instance_name,
                instance.region,
                instance.backup_frequency,
                instance.retention_days,
                'Active' if instance.is_active else 'Inactive',
                instance.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                instance.updated_at.strftime('%Y-%m-%d %H:%M:%S') if instance.updated_at else ''
            ])
        
        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=instances_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        logger.info(f"Instances exported by {session['username']}")
        return response
        
    except Exception as e:
        logger.error(f"Error exporting instances: {e}")
        flash("Error exporting instances", "danger")
        return redirect(url_for('aws_instances'))


############################################################ Backup Scheduling Helper Functions ############################################################

def schedule_instance_backup(instance):
    """Schedule backup job for a specific instance"""
    try:
        # This would integrate with your scheduler (APScheduler, Celery, etc.)
        # Implementation depends on your scheduling mechanism
        logger.info(f"Scheduling backup for instance {instance.instance_id} with frequency {instance.backup_frequency}")
        # Add actual scheduling logic here
        pass
    except Exception as e:
        logger.error(f"Error scheduling backup for {instance.instance_id}: {e}")
        raise


def remove_instance_backup_schedule(instance_id):
    """Remove scheduled backup job for an instance"""
    try:
        # Remove from scheduler
        logger.info(f"Removing backup schedule for instance {instance_id}")
        # Add actual schedule removal logic here
        pass
    except Exception as e:
        logger.error(f"Error removing backup schedule for {instance_id}: {e}")
        raise


def reschedule_instance_backup(instance):
    """Reschedule backup job for an instance"""
    try:
        remove_instance_backup_schedule(instance.instance_id)
        schedule_instance_backup(instance)
    except Exception as e:
        logger.error(f"Error rescheduling backup for {instance.instance_id}: {e}")
        raise

# Add these routes to your existing Flask application

############################################################ Bulk Actions ############################################################

@app.route('/bulk-export-amis', methods=['POST'])
def bulk_export_amis():
    """Export AMIs for selected instances to CSV"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
        
        # Get backups for selected instances
        backups = Backup.query.filter(Backup.instance_id.in_(instance_ids)).order_by(Backup.timestamp.desc()).all()
        
        if not backups:
            return jsonify({'success': False, 'error': 'No backups found for selected instances'}), 404
        
        # Generate CSV
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(['AMI ID', 'Instance Name', 'Instance ID', 'Region', 'Timestamp', 'Status', 'Backup Type', 'Retention Days'])
        
        for backup in backups:
            writer.writerow([
                backup.ami_id or 'N/A',
                backup.instance_name,
                backup.instance_id,
                backup.region,
                backup.formatted_timestamp,
                backup.status,
                backup.backup_type,
                backup.retention_days
            ])
        
        output = si.getvalue()
        timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        filename = f"amis_export_{timestamp}.csv"
        
        response = make_response(output)
        response.headers["Content-Disposition"] = f"attachment; filename={filename}"
        response.headers["Content-Type"] = "text/csv"
        
        logger.info(f"User {session['username']} exported {len(backups)} AMI records")
        return response
        
    except Exception as e:
        logger.error(f"Error in bulk export AMIs: {e}")
        return jsonify({'success': False, 'error': 'Export failed'}), 500


@app.route('/bulk-tag-amis', methods=['POST'])
def bulk_tag_amis():
    """Add tags to AMIs for selected instances"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        tag_key = data.get('tag_key', '').strip()
        tag_value = data.get('tag_value', '').strip()
        
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
            
        if not tag_key or not tag_value:
            return jsonify({'success': False, 'error': 'Tag key and value are required'}), 400
        
        tagged_amis = []
        errors = []
        
        for inst_id in instance_ids:
            inst = Instance.query.filter_by(instance_id=inst_id, is_active=True).first()
            if not inst:
                errors.append(f"Instance {inst_id} not found or inactive")
                continue
            
            # Get successful backups for this instance
            backups = Backup.query.filter_by(instance_id=inst_id, status='Success').all()
            if not backups:
                errors.append(f"No successful backups found for instance {inst_id}")
                continue
            
            try:
                # Create EC2 client
                ec2_client = boto3.client(
                    'ec2',
                    region_name=inst.region,
                    aws_access_key_id=inst.access_key,
                    aws_secret_access_key=inst.secret_key
                )
                
                for backup in backups:
                    if backup.ami_id:
                        try:
                            ec2_client.create_tags(
                                Resources=[backup.ami_id],
                                Tags=[{'Key': tag_key, 'Value': tag_value}]
                            )
                            tagged_amis.append(backup.ami_id)
                        except ClientError as e:
                            error_code = e.response.get('Error', {}).get('Code', '')
                            if error_code == 'InvalidAMIID.NotFound':
                                errors.append(f"AMI {backup.ami_id} not found")
                            else:
                                errors.append(f"Failed to tag {backup.ami_id}: {str(e)}")
                        except Exception as e:
                            errors.append(f"Failed to tag {backup.ami_id}: {str(e)}")
                            
            except Exception as e:
                errors.append(f"Failed to connect to AWS for instance {inst_id}: {str(e)}")
        
        # Prepare response
        result = {
            'success': True,
            'tagged_count': len(tagged_amis),
            'tagged_amis': tagged_amis,
            'errors': errors
        }
        
        if tagged_amis:
            message = f"Successfully tagged {len(tagged_amis)} AMIs"
            if errors:
                message += f" with {len(errors)} errors"
            result['message'] = message
        else:
            result['success'] = False
            result['message'] = "No AMIs were tagged"
        
        logger.info(f"User {session['username']} tagged {len(tagged_amis)} AMIs with {tag_key}={tag_value}")
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in bulk tag AMIs: {e}")
        return jsonify({'success': False, 'error': 'Tagging operation failed'}), 500


@app.route('/bulk-delete-backups', methods=['POST'])
def bulk_delete_backups():
    """Delete backup records for selected instances (database only)"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
        
        # Get backups to delete
        backups_to_delete = Backup.query.filter(Backup.instance_id.in_(instance_ids)).all()
        
        if not backups_to_delete:
            return jsonify({'success': False, 'error': 'No backup records found for selected instances'}), 404
        
        deleted_count = len(backups_to_delete)
        
        # Delete backup records from database
        for backup in backups_to_delete:
            db.session.delete(backup)
        
        db.session.commit()
        
        logger.info(f"User {session['username']} deleted {deleted_count} backup records")
        
        return jsonify({
            'success': True,
            'message': f'Successfully deleted {deleted_count} backup records',
            'deleted_count': deleted_count
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in bulk delete backups: {e}")
        return jsonify({'success': False, 'error': 'Delete operation failed'}), 500


@app.route('/bulk-validate-instances', methods=['POST'])
def bulk_validate_instances():
    """Validate AWS credentials and connectivity for selected instances"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
        
        validation_results = []
        
        for inst_id in instance_ids:
            inst = Instance.query.filter_by(instance_id=inst_id, is_active=True).first()
            if not inst:
                validation_results.append({
                    'instance_id': inst_id,
                    'instance_name': 'Unknown',
                    'valid': False,
                    'message': 'Instance not found or inactive'
                })
                continue
            
            # Validate AWS credentials
            is_valid, message = inst.validate_aws_credentials()
            
            validation_results.append({
                'instance_id': inst.instance_id,
                'instance_name': inst.instance_name,
                'valid': is_valid,
                'message': message
            })
            
            if is_valid:
                # Update the instance in database if validation succeeded
                inst.updated_at = datetime.now(UTC)
                db.session.commit()
        
        valid_count = sum(1 for result in validation_results if result['valid'])
        invalid_count = len(validation_results) - valid_count
        
        logger.info(f"User {session['username']} validated {len(validation_results)} instances")
        
        return jsonify({
            'success': True,
            'results': validation_results,
            'valid_count': valid_count,
            'invalid_count': invalid_count,
            'message': f'Validated {len(validation_results)} instances: {valid_count} valid, {invalid_count} invalid'
        })
        
    except Exception as e:
        logger.error(f"Error in bulk validate instances: {e}")
        return jsonify({'success': False, 'error': 'Validation operation failed'}), 500

############################################################ AWS AMI Creators ############################################################

@app.route('/start-backup/<instance_id>', methods=['POST'])
def start_backup(instance_id):
    """Manually start backup for a specific instance"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        inst = Instance.query.filter_by(instance_id=instance_id, is_active=True).first()
        if not inst:
            flash(f"Instance {instance_id} not found or inactive", "danger")
            return redirect(url_for('instances'))
        
        # Get effective retention days
        global_config = BackupSettings.query.first()
        retention_days = get_effective_setting(
            getattr(inst, 'retention_days', None), 
            global_config.retention_days if global_config else 7
        )
        
        # Validate AWS credentials first
        is_valid, validation_msg = inst.validate_aws_credentials()
        if not is_valid:
            flash(f"AWS validation failed: {validation_msg}", "danger")
            return redirect(url_for('instances'))
        
        # Create EC2 client
        ec2_client = boto3.client(
            'ec2',
            region_name=inst.region,
            aws_access_key_id=inst.access_key,
            aws_secret_access_key=inst.secret_key
        )
        
        # Get instance details and name
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        if not response.get('Reservations'):
            flash(f"Instance {instance_id} not found in AWS", "danger")
            return redirect(url_for('instances'))
        
        instance_info = response['Reservations'][0]['Instances'][0]
        instance_name = inst.instance_name  # Use stored name as fallback
        
        # Try to get name from AWS tags
        for tag in instance_info.get('Tags', []):
            if tag['Key'] == 'Name' and tag.get('Value'):
                instance_name = tag['Value']
                break
        
        if not instance_name:
            instance_name = f"Instance-{instance_id}"
        
        # Create AMI with timestamp
        ist_zone = pytz.timezone('Asia/Kolkata')
        timestamp_str = datetime.now(ist_zone).strftime("%Y_%m_%d_%I_%M_%p")
        ami_name = f"{instance_name}_{timestamp_str}_manual"
        
        # Create pending backup record first
        backup = Backup(
            instance_id=instance_id,
            instance_name=instance_name,
            ami_name=ami_name,
            timestamp=datetime.now(UTC),
            status='Pending',
            region=inst.region,
            retention_days=retention_days,
            backup_type='manual'
        )
        db.session.add(backup)
        db.session.commit()
        
        logger.info(f"Starting manual backup for instance {instance_id} by user {session['username']}")
        
        # Create AMI
        ami_response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description=f"Manual backup of {instance_name} created at {timestamp_str}",
            NoReboot=True
        )
        ami_id = ami_response['ImageId']
        
        # Tag the AMI
        ec2_client.create_tags(
            Resources=[ami_id],
            Tags=[
                {'Key': 'CreatedBy', 'Value': 'ManualBackup'},
                {'Key': 'InstanceName', 'Value': instance_name},
                {'Key': 'BackupType', 'Value': 'manual'},
                {'Key': 'Creator', 'Value': session['username']},
                {'Key': 'RetentionDays', 'Value': str(retention_days)}
            ]
        )
        
        # Update backup record to Success
        backup.status = 'Success'
        backup.ami_id = ami_id
        db.session.commit()
        
        # Trigger cleanup of old AMIs for this instance
        cleanup_old_amis(ec2_client, instance_name, retention_days, instance_id)
        
        flash(f"Manual backup created successfully for {instance_name} (AMI: {ami_id})", "success")
        logger.info(f"Manual backup completed: {ami_id} for instance {instance_id}")
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = f"AWS Error ({error_code}): {str(e)}"
        logger.error(f"Manual backup failed for {instance_id}: {error_msg}")
        
        # Update backup record to Failed if it exists
        if 'backup' in locals():
            backup.status = 'Failed'
            backup.error_message = error_msg
            db.session.commit()
        
        flash(f"Backup failed: {error_msg}", "danger")
        
    except Exception as e:
        error_msg = f"Backup failed: {str(e)}"
        logger.error(f"Manual backup failed for {instance_id}: {error_msg}")
        
        # Update backup record to Failed if it exists
        if 'backup' in locals():
            backup.status = 'Failed'
            backup.error_message = error_msg
            db.session.commit()
        
        flash(error_msg, "danger")
    
    return redirect(url_for('instances'))


def cleanup_old_amis(ec2_client, instance_name, retention_days, instance_id=None):
    """Clean up old AMIs and their associated snapshots"""
    try:
        # Get all AMIs created by our backup system for this instance
        filters = [
            {'Name': 'owner-id', 'Values': ['self']},
            {'Name': 'tag:CreatedBy', 'Values': ['AutoBackup', 'ManualBackup']},
            {'Name': 'tag:InstanceName', 'Values': [instance_name]}
        ]
        
        images_response = ec2_client.describe_images(Filters=filters)
        now = datetime.now(timezone.utc)
        cleaned_count = 0
        
        for image in images_response['Images']:
            try:
                creation_date = datetime.strptime(
                    image['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ"
                ).replace(tzinfo=timezone.utc)
                
                age_days = (now - creation_date).days
                
                if age_days > retention_days:
                    ami_id = image['ImageId']
                    
                    # Delete associated snapshots first
                    snapshot_ids = []
                    for mapping in image.get('BlockDeviceMappings', []):
                        ebs = mapping.get('Ebs')
                        if ebs and 'SnapshotId' in ebs:
                            snapshot_ids.append(ebs['SnapshotId'])
                    
                    # Deregister the AMI
                    ec2_client.deregister_image(ImageId=ami_id)
                    logger.info(f"Deregistered old AMI {ami_id} (age: {age_days} days)")
                    
                    # Delete snapshots
                    for snapshot_id in snapshot_ids:
                        try:
                            ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                            logger.info(f"Deleted snapshot {snapshot_id} for AMI {ami_id}")
                        except ClientError as snap_e:
                            if snap_e.response.get('Error', {}).get('Code') != 'InvalidSnapshot.NotFound':
                                logger.warning(f"Could not delete snapshot {snapshot_id}: {snap_e}")
                    
                    # Update database backup record
                    if instance_id:
                        backup_record = Backup.query.filter_by(
                            ami_id=ami_id, instance_id=instance_id
                        ).first()
                        if backup_record:
                            backup_record.cleanup_status = 'completed'
                            backup_record.cleanup_timestamp = datetime.now(UTC)
                    
                    cleaned_count += 1
                    
            except Exception as e:
                logger.error(f"Error cleaning up AMI {image.get('ImageId', 'unknown')}: {e}")
        
        if cleaned_count > 0:
            db.session.commit()
            logger.info(f"Cleaned up {cleaned_count} old AMIs for {instance_name}")
            
    except Exception as e:
        logger.error(f"Error in cleanup_old_amis for {instance_name}: {e}")


def backup_instance(instance_id):
    """Scheduled backup function for a specific instance"""
    with app.app_context():
        try:
            inst = Instance.query.filter_by(instance_id=instance_id, is_active=True).first()
            if not inst:
                logger.warning(f"Instance {instance_id} not found or inactive for scheduled backup")
                return
            
            global_config = BackupSettings.query.first()
            if not global_config:
                logger.error("No global backup configuration found")
                return
            
            retention_days = get_effective_setting(
                getattr(inst, 'retention_days', None), 
                global_config.retention_days
            )
            
            # Validate instance credentials
            is_valid, validation_msg = inst.validate_aws_credentials()
            if not is_valid:
                logger.error(f"AWS validation failed for {instance_id}: {validation_msg}")
                return
            
            ec2_client = boto3.client(
                'ec2',
                region_name=inst.region,
                aws_access_key_id=inst.access_key,
                aws_secret_access_key=inst.secret_key
            )
            
            # Get instance name from AWS or use stored name
            instance_name = inst.instance_name
            try:
                response = ec2_client.describe_instances(InstanceIds=[instance_id])
                if response.get('Reservations'):
                    instance_info = response['Reservations'][0]['Instances'][0]
                    for tag in instance_info.get('Tags', []):
                        if tag['Key'] == 'Name' and tag.get('Value'):
                            instance_name = tag['Value']
                            if instance_name != inst.instance_name:
                                inst.instance_name = instance_name
                                db.session.commit()
                            break
            except ClientError:
                pass  # Use stored name if AWS call fails
            
            if not instance_name:
                instance_name = f"Instance-{instance_id}"
            
            # Create AMI with timestamp
            ist_zone = pytz.timezone('Asia/Kolkata')
            timestamp_str = datetime.now(ist_zone).strftime("%Y_%m_%d_%I_%M_%p")
            ami_name = f"{instance_name}_{timestamp_str}_scheduled"
            
            start_time = datetime.now(UTC)
            
            # Create backup record
            backup = Backup(
                instance_id=instance_id,
                instance_name=instance_name,
                ami_name=ami_name,
                timestamp=start_time,
                status='Pending',
                region=inst.region,
                retention_days=retention_days,
                backup_type='scheduled'
            )
            db.session.add(backup)
            db.session.commit()
            
            # Create AMI
            ami_response = ec2_client.create_image(
                InstanceId=instance_id,
                Name=ami_name,
                Description=f"Scheduled backup of {instance_name} created at {timestamp_str}",
                NoReboot=True
            )
            ami_id = ami_response['ImageId']
            
            # Tag the AMI
            ec2_client.create_tags(
                Resources=[ami_id],
                Tags=[
                    {'Key': 'CreatedBy', 'Value': 'AutoBackup'},
                    {'Key': 'InstanceName', 'Value': instance_name},
                    {'Key': 'BackupType', 'Value': 'scheduled'},
                    {'Key': 'RetentionDays', 'Value': str(retention_days)}
                ]
            )
            
            # Update backup record
            end_time = datetime.now(UTC)
            backup.status = 'Success'
            backup.ami_id = ami_id
            backup.duration_seconds = int((end_time - start_time).total_seconds())
            db.session.commit()
            
            logger.info(f"Scheduled backup completed: {ami_id} for instance {instance_id}")
            
            # Cleanup old AMIs
            cleanup_old_amis(ec2_client, instance_name, retention_days, instance_id)
            
        except ClientError as e:
            error_msg = f"AWS Error: {str(e)}"
            logger.error(f"Scheduled backup failed for {instance_id}: {error_msg}")
            
            if 'backup' in locals():
                backup.status = 'Failed'
                backup.error_message = error_msg
                db.session.commit()
                
        except Exception as e:
            error_msg = f"Backup error: {str(e)}"
            logger.error(f"Scheduled backup failed for {instance_id}: {error_msg}")
            
            if 'backup' in locals():
                backup.status = 'Failed'
                backup.error_message = error_msg
                db.session.commit()


def schedule_all_instance_backups():
    """Schedule backup jobs for all active instances"""
    with app.app_context():
        try:
            global_config = BackupSettings.query.first()
            instances = Instance.query.filter_by(is_active=True).all()
            scheduled_ids = set()
            
            logger.info(f"Scheduling backups for {len(instances)} instances")
            
            for inst in instances:
                job_id = f"backup_{inst.instance_id}"
                scheduled_ids.add(job_id)
                
                # Remove existing job
                try:
                    scheduler.remove_job(job_id)
                    logger.debug(f"Removed existing job: {job_id}")
                except Exception:
                    pass  # Job didn't exist
                
                # Get effective backup frequency
                freq = get_effective_setting(
                    getattr(inst, 'backup_frequency', None),
                    global_config.backup_frequency if global_config else "0 2 * * *"
                )
                
                logger.debug(f"Scheduling {inst.instance_id} with frequency: {freq}")
                
                # Try to parse as minutes first, then as cron
                try:
                    freq_int = int(freq)
                    if freq_int > 0:
                        scheduler.add_job(
                            id=job_id,
                            func=backup_instance,
                            args=[inst.instance_id],
                            trigger='interval',
                            minutes=freq_int,
                            replace_existing=True
                        )
                        logger.info(f"Scheduled backup for {inst.instance_id} every {freq_int} minutes")
                except ValueError:
                    # Parse as cron expression
                    cron_parts = str(freq).strip().split()
                    if len(cron_parts) == 5:
                        scheduler.add_job(
                            id=job_id,
                            func=backup_instance,
                            args=[inst.instance_id],
                            trigger='cron',
                            minute=cron_parts[0],
                            hour=cron_parts[1],
                            day=cron_parts[2],
                            month=cron_parts[3],
                            day_of_week=cron_parts[4],
                            replace_existing=True
                        )
                        logger.info(f"Scheduled backup for {inst.instance_id} with cron: {freq}")
                    else:
                        logger.error(f"Invalid backup frequency for {inst.instance_id}: {freq}")
            
            # Clean up orphaned jobs
            current_jobs = {job.id for job in scheduler.get_jobs()}
            for job_id in current_jobs:
                if job_id.startswith("backup_") and job_id not in scheduled_ids:
                    try:
                        scheduler.remove_job(job_id)
                        logger.info(f"Removed orphaned job: {job_id}")
                    except Exception as e:
                        logger.warning(f"Could not remove orphaned job {job_id}: {e}")
            
            active_jobs = len([job for job in scheduler.get_jobs() if job.id.startswith("backup_")])
            logger.info(f"Backup scheduling completed. Active backup jobs: {active_jobs}")
            
        except Exception as e:
            logger.error(f"Error in schedule_all_instance_backups: {e}")


@app.route('/reschedule-backups', methods=['POST'])
def reschedule_backups():
    """Manually trigger rescheduling of all backup jobs"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        schedule_all_instance_backups()
        active_jobs = len([job for job in scheduler.get_jobs() if job.id.startswith("backup_")])
        
        logger.info(f"Manual backup rescheduling triggered by user {session['username']}")
        
        return jsonify({
            'success': True,
            'message': f'Successfully rescheduled backups for all instances. Active jobs: {active_jobs}',
            'active_jobs': active_jobs
        })
        
    except Exception as e:
        logger.error(f"Error rescheduling backups: {e}")
        return jsonify({'success': False, 'error': 'Failed to reschedule backups'}), 500


@app.route('/search-suggestions')
def search_suggestions():
    """Provide search suggestions for autocomplete"""
    if 'username' not in session:
        return jsonify([])
    
    try:
        # Get unique values for search suggestions
        instance_names = db.session.query(Instance.instance_name).filter(
            Instance.instance_name.isnot(None),
            Instance.is_active == True
        ).distinct().all()
        
        instance_ids = db.session.query(Instance.instance_id).filter(
            Instance.is_active == True
        ).distinct().all()
        
        ami_ids = db.session.query(Backup.ami_id).filter(
            Backup.ami_id.isnot(None)
        ).distinct().all()
        
        # Flatten and combine suggestions
        suggestions = []
        suggestions.extend([name[0] for name in instance_names if name[0]])
        suggestions.extend([id[0] for id in instance_ids if id[0]])
        suggestions.extend([ami[0] for ami in ami_ids if ami[0]])
        
        # Remove duplicates and sort
        suggestions = sorted(list(set(suggestions)))
        
        return jsonify(suggestions)
        
    except Exception as e:
        logger.error(f"Error getting search suggestions: {e}")
        return jsonify([])


@app.route('/api/instances')
def api_instances():
    """API endpoint to get instance list"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        instances = Instance.query.filter_by(is_active=True).all()
        return jsonify([{
            'instance_id': inst.instance_id,
            'instance_name': inst.instance_name,
            'region': inst.region,
            'created_at': inst.created_at.isoformat() if inst.created_at else None
        } for inst in instances])
        
    except Exception as e:
        logger.error(f"Error in api_instances: {e}")
        return jsonify({'error': 'Failed to fetch instances'}), 500


@app.route('/api/amis')
def api_amis():
    """API endpoint to get AMI list for selected instances"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        instance_ids = request.args.get('instances', '').split(',')
        instance_ids = [id.strip() for id in instance_ids if id.strip()]
        
        if not instance_ids:
            return jsonify([])
        
        backups = Backup.query.filter(
            Backup.instance_id.in_(instance_ids),
            Backup.ami_id.isnot(None)
        ).order_by(Backup.timestamp.desc()).all()
        
        return jsonify([{
            'ami_id': backup.ami_id,
            'instance_name': backup.instance_name,
            'instance_id': backup.instance_id,
            'status': backup.status,
            'timestamp': backup.formatted_timestamp,
            'backup_type': backup.backup_type
        } for backup in backups])
        
    except Exception as e:
        logger.error(f"Error in api_amis: {e}")
        return jsonify({'error': 'Failed to fetch AMIs'}), 500


@app.route('/get-credential-details/<int:credential_id>', methods=['GET'])
def get_credential_details(credential_id):
    """Get AWS credential details for auto-filling the form"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        credential = AWSCredential.query.get(credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'Credential not found'}), 404
        
        return jsonify({
            'success': True,
            'credential': {
                'id': credential.id,
                'name': credential.name,
                'region': credential.region,
                # We don't send the actual keys for security reasons
                'has_access_key': bool(credential.access_key),
                'has_secret_key': bool(credential.secret_key)
            }
        })
        
    except Exception as e:
        logger.error(f"Error retrieving credential details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get-full-credential-details/<int:credential_id>', methods=['GET'])
def get_full_credential_details(credential_id):
    """Get full AWS credential details including keys (with security checks)"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        # Get the current user
        current_username = session.get('username')
        user = User.query.filter_by(username=current_username).first()
        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get the credential - using Session.get() instead of Query.get()
        credential = db.session.get(AWSCredential, credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'Credential not found'}), 404
        
        # Security check: Only allow access to the user who created the credential or admin users
        is_admin = user.username.lower() == 'admin'  # Adjust this based on your admin detection logic
        
        # Check if user is owner (if user_id is set) or admin
        is_owner = credential.user_id is not None and credential.user_id == user.id
        
        if not (is_owner or is_admin):
            # Log the unauthorized access attempt
            logger.warning(f"User {current_username} attempted to access credential {credential_id} without permission")
            return jsonify({'success': False, 'error': 'You do not have permission to view these credentials'}), 403
        
        # Return the full credential details including keys
        return jsonify({
            'success': True,
            'credential': {
                'id': credential.id,
                'name': credential.name,
                'region': credential.region,
                'access_key': credential.access_key,
                'secret_key': credential.secret_key
            }
        })
        
    except Exception as e:
        logger.error(f"Error retrieving full credential details: {e}")
        return jsonify({'success': False, 'error': 'An error occurred'}), 500

@app.route('/bulk-delete-amis', methods=['POST'])
def bulk_delete_amis():
    """Delete AMIs and associated snapshots for selected instances"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
        
        deleted_amis = []
        errors = []
        
        for inst_id in instance_ids:
            inst = Instance.query.filter_by(instance_id=inst_id, is_active=True).first()
            if not inst:
                errors.append(f"Instance {inst_id} not found or inactive")
                continue
            
            # Get backups with AMI IDs
            backups = Backup.query.filter_by(instance_id=inst_id).filter(
                Backup.ami_id.isnot(None)
            ).all()
            
            if not backups:
                errors.append(f"No AMIs found for instance {inst_id}")
                continue
            
            try:
                ec2_client = boto3.client(
                    'ec2',
                    region_name=inst.region,
                    aws_access_key_id=inst.access_key,
                    aws_secret_access_key=inst.secret_key
                )
                
                for backup in backups:
                    try:
                        # Get AMI details before deletion
                        ami_response = ec2_client.describe_images(ImageIds=[backup.ami_id])
                        if ami_response['Images']:
                            image = ami_response['Images'][0]
                            
                            # Delete associated snapshots
                            for mapping in image.get('BlockDeviceMappings', []):
                                ebs = mapping.get('Ebs')
                                if ebs and 'SnapshotId' in ebs:
                                    try:
                                        ec2_client.delete_snapshot(SnapshotId=ebs['SnapshotId'])
                                        logger.info(f"Deleted snapshot {ebs['SnapshotId']} for AMI {backup.ami_id}")
                                    except ClientError as snap_e:
                                        if snap_e.response.get('Error', {}).get('Code') != 'InvalidSnapshot.NotFound':
                                            logger.warning(f"Could not delete snapshot {ebs['SnapshotId']}: {snap_e}")
                            
                            # Deregister AMI
                            ec2_client.deregister_image(ImageId=backup.ami_id)
                            deleted_amis.append(backup.ami_id)
                            logger.info(f"Deleted AMI {backup.ami_id} for instance {inst_id}")
                            
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'InvalidAMIID.NotFound':
                            # AMI already deleted, just remove from database
                            deleted_amis.append(backup.ami_id)
                        else:
                            errors.append(f"Error deleting AMI {backup.ami_id}: {str(e)}")
                    except Exception as e:
                        errors.append(f"Error deleting AMI {backup.ami_id}: {str(e)}")
                
                # Delete backup records from database
                deleted_records = Backup.query.filter_by(instance_id=inst_id).delete(synchronize_session=False)
                logger.info(f"Deleted {deleted_records} backup records for instance {inst_id}")
                
            except Exception as e:
                errors.append(f"Error processing instance {inst_id}: {str(e)}")
        
        # Commit database changes
        db.session.commit()
        
        result = {
            'success': True,
            'deleted_count': len(deleted_amis),
            'deleted_amis': deleted_amis,
            'errors': errors
        }
        
        if deleted_amis:
            message = f"Successfully deleted {len(deleted_amis)} AMIs"
            if errors:
                message += f" with {len(errors)} errors"
            result['message'] = message
        else:
            result['success'] = False
            result['message'] = "No AMIs were deleted"
        
        logger.info(f"User {session['username']} deleted {len(deleted_amis)} AMIs")
        return jsonify(result)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in bulk_delete_amis: {e}")
        return jsonify({'success': False, 'error': 'Delete operation failed'}), 500


# Initialize scheduler
#scheduler = APScheduler()
#scheduler.init_app(app)
#scheduler.start()

# Schedule backups on startup
@app.before_request
def initialize_scheduler():
    if not app._got_first_request:
        """Initialize backup scheduler on first request"""
        try:
            schedule_all_instance_backups()
            logger.info("✅ Backup scheduler initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize backup scheduler: {e}")

############################################################ deleting ami ############################################################

@app.route('/delete-ami/<ami_id>', methods=['POST'])
def delete_ami(ami_id):
    """Delete AMI and associated snapshots with comprehensive error handling"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Validate AMI ID format
    if not ami_id or not ami_id.startswith('ami-'):
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': 'Invalid AMI ID format'})
        flash("Invalid AMI ID format", "danger")
        return redirect(url_for('backups'))
    
    # Find backup record
    backup = Backup.query.filter_by(ami_id=ami_id).first()
    if not backup:
        error_msg = f"AMI record '{ami_id}' not found in database"
        logger.warning(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('backups'))
    
    # Find associated instance for AWS credentials
    instance = Instance.query.filter_by(instance_id=backup.instance_id).first()
    if not instance:
        error_msg = f"Instance record '{backup.instance_id}' not found"
        logger.error(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('backups'))
    
    try:
        # Initialize EC2 client with instance credentials
        ec2_client = boto3.client(
            'ec2',
            region_name=backup.region,
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key
        )
        
        # Verify AMI exists and get details
        try:
            images_response = ec2_client.describe_images(ImageIds=[ami_id])
            if not images_response.get('Images'):
                # AMI doesn't exist in AWS, but we have a record - clean up database
                logger.warning(f"AMI {ami_id} not found in AWS, removing database record")
                db.session.delete(backup)
                db.session.commit()
                
                success_msg = f"AMI {ami_id} was already deleted from AWS. Database record cleaned up."
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': True, 'message': success_msg})
                flash(success_msg, "info")
                return redirect(url_for('backups'))
                
            image = images_response['Images'][0]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidAMIID.NotFound':
                # AMI doesn't exist, clean up database record
                logger.warning(f"AMI {ami_id} not found in AWS, removing database record")
                db.session.delete(backup)
                db.session.commit()
                
                success_msg = f"AMI {ami_id} was already deleted. Database record cleaned up."
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'success': True, 'message': success_msg})
                flash(success_msg, "info")
                return redirect(url_for('backups'))
            else:
                raise  # Re-raise other ClientErrors
        
        # Track deletion results
        deletion_results = {
            'ami_deregistered': False,
            'snapshots_deleted': [],
            'snapshots_failed': [],
            'errors': []
        }
        
        # Step 1: Deregister the AMI
        try:
            ec2_client.deregister_image(ImageId=ami_id)
            deletion_results['ami_deregistered'] = True
            logger.info(f"Successfully deregistered AMI: {ami_id}")
        except ClientError as e:
            error_msg = f"Failed to deregister AMI {ami_id}: {str(e)}"
            logger.error(error_msg)
            deletion_results['errors'].append(error_msg)
        
        # Step 2: Delete associated snapshots
        block_device_mappings = image.get('BlockDeviceMappings', [])
        if block_device_mappings:
            for mapping in block_device_mappings:
                ebs = mapping.get('Ebs', {})
                snapshot_id = ebs.get('SnapshotId')
                
                if snapshot_id:
                    try:
                        ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                        deletion_results['snapshots_deleted'].append(snapshot_id)
                        logger.info(f"Successfully deleted snapshot: {snapshot_id}")
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'InvalidSnapshot.NotFound':
                            logger.warning(f"Snapshot {snapshot_id} was already deleted")
                            deletion_results['snapshots_deleted'].append(f"{snapshot_id} (already deleted)")
                        else:
                            error_msg = f"Failed to delete snapshot {snapshot_id}: {str(e)}"
                            logger.error(error_msg)
                            deletion_results['snapshots_failed'].append(snapshot_id)
                            deletion_results['errors'].append(error_msg)
                    except Exception as e:
                        error_msg = f"Unexpected error deleting snapshot {snapshot_id}: {str(e)}"
                        logger.error(error_msg)
                        deletion_results['snapshots_failed'].append(snapshot_id)
                        deletion_results['errors'].append(error_msg)
        
        # Step 3: Update backup record status and database
        if deletion_results['ami_deregistered'] or not deletion_results['errors']:
            # Mark backup as deleted in database
            backup.status = 'Deleted'
            backup.cleanup_status = 'completed'
            backup.cleanup_timestamp = datetime.now(UTC)
            backup.error_message = None
            
            # Alternatively, remove the record completely (uncomment if preferred)
            # db.session.delete(backup)
            
            db.session.commit()
            logger.info(f"Updated backup record for AMI {ami_id}")
        
        # Prepare response messages
        success_messages = []
        warning_messages = []
        
        if deletion_results['ami_deregistered']:
            success_messages.append(f"AMI {ami_id} deregistered successfully")
        
        if deletion_results['snapshots_deleted']:
            success_messages.append(f"Deleted {len(deletion_results['snapshots_deleted'])} snapshot(s)")
        
        if deletion_results['snapshots_failed']:
            warning_messages.append(f"Failed to delete {len(deletion_results['snapshots_failed'])} snapshot(s)")
        
        # Handle response based on request type
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': '; '.join(success_messages),
                'warnings': warning_messages,
                'details': deletion_results
            })
        
        # Flash messages for web interface
        for msg in success_messages:
            flash(msg, "success")
        for msg in warning_messages:
            flash(msg, "warning")
        
        return redirect(url_for('backups'))
        
    except NoCredentialsError:
        error_msg = "AWS credentials not found or invalid"
        logger.error(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('backups'))
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = f"AWS Error ({error_code}): {str(e)}"
        logger.error(f"Delete AMI failed: {error_msg}")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('backups'))
        
    except Exception as e:
        error_msg = f"Unexpected error deleting AMI: {str(e)}"
        logger.error(f"Delete AMI failed: {error_msg}")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('backups'))


@app.route('/delete-ami-bulk', methods=['POST'])
def delete_ami_bulk():
    """Bulk delete multiple AMIs with progress tracking"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    ami_ids = request.form.getlist('ami_ids[]') or request.json.get('ami_ids', [])
    
    if not ami_ids:
        return jsonify({'success': False, 'error': 'No AMI IDs provided'})
    
    results = {
        'total': len(ami_ids),
        'successful': 0,
        'failed': 0,
        'details': []
    }
    
    for ami_id in ami_ids:
        try:
            # Find backup record
            backup = Backup.query.filter_by(ami_id=ami_id).first()
            if not backup:
                results['failed'] += 1
                results['details'].append({
                    'ami_id': ami_id,
                    'status': 'failed',
                    'error': 'AMI record not found in database'
                })
                continue
            
            # Find instance for credentials
            instance = Instance.query.filter_by(instance_id=backup.instance_id).first()
            if not instance:
                results['failed'] += 1
                results['details'].append({
                    'ami_id': ami_id,
                    'status': 'failed',
                    'error': 'Instance record not found'
                })
                continue
            
            # Delete AMI using similar logic as single delete
            ec2_client = boto3.client(
                'ec2',
                region_name=backup.region,
                aws_access_key_id=instance.access_key,
                aws_secret_access_key=instance.secret_key
            )
            
            # Get AMI details and delete
            try:
                images_response = ec2_client.describe_images(ImageIds=[ami_id])
                if images_response.get('Images'):
                    image = images_response['Images'][0]
                    
                    # Deregister AMI
                    ec2_client.deregister_image(ImageId=ami_id)
                    
                    # Delete snapshots
                    snapshots_deleted = 0
                    for mapping in image.get('BlockDeviceMappings', []):
                        ebs = mapping.get('Ebs', {})
                        if ebs.get('SnapshotId'):
                            try:
                                ec2_client.delete_snapshot(SnapshotId=ebs['SnapshotId'])
                                snapshots_deleted += 1
                            except:
                                pass  # Continue with other snapshots
                    
                    # Update database
                    backup.status = 'Deleted'
                    backup.cleanup_status = 'completed'
                    backup.cleanup_timestamp = datetime.now(UTC)
                    
                    results['successful'] += 1
                    results['details'].append({
                        'ami_id': ami_id,
                        'status': 'success',
                        'snapshots_deleted': snapshots_deleted
                    })
                else:
                    # AMI doesn't exist, clean up database
                    db.session.delete(backup)
                    results['successful'] += 1
                    results['details'].append({
                        'ami_id': ami_id,
                        'status': 'success',
                        'message': 'AMI already deleted, cleaned up database record'
                    })
                    
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'InvalidAMIID.NotFound':
                    # AMI doesn't exist, clean up database
                    db.session.delete(backup)
                    results['successful'] += 1
                    results['details'].append({
                        'ami_id': ami_id,
                        'status': 'success',
                        'message': 'AMI already deleted, cleaned up database record'
                    })
                else:
                    raise
                    
        except Exception as e:
            results['failed'] += 1
            results['details'].append({
                'ami_id': ami_id,
                'status': 'failed',
                'error': str(e)
            })
    
    # Commit all database changes
    try:
        db.session.commit()
    except Exception as e:
        logger.error(f"Database commit failed during bulk delete: {e}")
        return jsonify({'success': False, 'error': 'Database error during bulk operation'})
    
    return jsonify({
        'success': True,
        'results': results,
        'message': f"Processed {results['total']} AMIs: {results['successful']} successful, {results['failed']} failed"
    })

############################################################ AWS Checker ############################################################

@app.route('/check-instance', methods=['POST'])
def check_instance():
    """Validate AWS EC2 instance credentials and retrieve instance details"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()
    
    # Extract and validate required parameters
    instance_id = data.get('instance_id', '').strip()
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    region = data.get('region', '').strip()
    
    # Check if using saved credentials
    credential_id = data.get('credential_id')
    if credential_id:
        # Look up the saved credential
        credential = AWSCredential.query.get(credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'Saved credential not found'}), 404
        
        # Use the saved credential details
        access_key = credential.access_key
        secret_key = credential.secret_key
        region = credential.region
    
    # Input validation
    validation_errors = []
    
    if not instance_id:
        validation_errors.append('Instance ID is required')
    elif not instance_id.startswith('i-'):
        validation_errors.append('Invalid instance ID format (should start with i-)')
    
    if not access_key:
        validation_errors.append('AWS Access Key is required')
    elif len(access_key) < 16:
        validation_errors.append('Invalid AWS Access Key format')
    
    if not secret_key:
        validation_errors.append('AWS Secret Key is required')
    elif len(secret_key) < 32:
        validation_errors.append('Invalid AWS Secret Key format')
    
    if not region:
        validation_errors.append('AWS Region is required')
    elif not region.replace('-', '').replace('_', '').isalnum():
        validation_errors.append('Invalid AWS Region format')
    
    if validation_errors:
        logger.warning(f"Instance check validation failed: {validation_errors}")
        return jsonify({
            'success': False, 
            'error': 'Validation failed',
            'details': validation_errors
        })
    
    try:
        # Create EC2 client with provided credentials
        ec2_client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=boto3.session.Config(
                retries={'max_attempts': 3, 'mode': 'standard'},
                read_timeout=30,
                connect_timeout=10
            )
        )
        
        # Test credentials by describing the specific instance
        logger.info(f"Checking instance {instance_id} in region {region}")
        
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get('Reservations', [])
        
        if not reservations or not reservations[0].get('Instances'):
            error_msg = f"Instance '{instance_id}' not found in region '{region}'"
            logger.warning(error_msg)
            return jsonify({
                'success': False, 
                'error': error_msg,
                'suggestion': 'Verify the instance ID and region are correct'
            })
        
        # Extract instance details
        instance = reservations[0]['Instances'][0]
        instance_state = instance.get('State', {}).get('Name', 'unknown')
        instance_type = instance.get('InstanceType', 'unknown')
        availability_zone = instance.get('Placement', {}).get('AvailabilityZone', 'unknown')
        
        # Get instance name from tags
        instance_name = instance_id  # Default to ID
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name' and tag.get('Value'):
                instance_name = tag['Value'].strip()
                break
        
        # Additional instance information
        instance_details = {
            'instance_id': instance_id,
            'instance_name': instance_name,
            'instance_type': instance_type,
            'state': instance_state,
            'availability_zone': availability_zone,
            'region': region,
            'platform': instance.get('Platform', 'Linux/Unix'),
            'launch_time': instance.get('LaunchTime').isoformat() if instance.get('LaunchTime') else None,
            'vpc_id': instance.get('VpcId'),
            'subnet_id': instance.get('SubnetId'),
            'private_ip': instance.get('PrivateIpAddress'),
            'public_ip': instance.get('PublicIpAddress')
        }
        
        # Log successful validation
        logger.info(f"Successfully validated instance {instance_id} ({instance_name}) - State: {instance_state}")
        
        # Check if instance already exists in database
        existing_instance = Instance.query.filter_by(instance_id=instance_id).first()
        
        response_data = {
            'success': True,
            'instance_name': instance_name,
            'instance_details': instance_details,
            'already_registered': existing_instance is not None
        }
        
        if existing_instance:
            response_data['existing_instance'] = {
                'id': existing_instance.id,
                'name': existing_instance.instance_name,
                'region': existing_instance.region,
                'is_active': existing_instance.is_active,
                'created_at': existing_instance.created_at.isoformat()
            }
        
        return jsonify(response_data)
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific AWS errors with user-friendly messages
        if error_code == 'InvalidInstanceID.NotFound':
            error_msg = f"Instance '{instance_id}' not found in region '{region}'"
            suggestion = "Verify the instance ID and region are correct"
        elif error_code == 'UnauthorizedOperation':
            error_msg = "Insufficient permissions to describe EC2 instances"
            suggestion = "Ensure the AWS credentials have ec2:DescribeInstances permission"
        elif error_code == 'AuthFailure':
            error_msg = "Authentication failed - invalid AWS credentials"
            suggestion = "Verify your AWS Access Key and Secret Key are correct"
        elif error_code == 'InvalidInstanceID.Malformed':
            error_msg = f"Malformed instance ID: '{instance_id}'"
            suggestion = "Instance ID should start with 'i-' followed by alphanumeric characters"
        elif error_code == 'InvalidUserID.NotFound':
            error_msg = "AWS credentials are valid but user not found"
            suggestion = "Check if the AWS user still exists and has proper permissions"
        else:
            error_msg = f"AWS Error ({error_code}): {error_message}"
            suggestion = "Check AWS service status and your credentials"
        
        logger.error(f"AWS ClientError during instance check: {error_code} - {error_message}")
        
        return jsonify({
            'success': False,
            'error': error_msg,
            'error_code': error_code,
            'suggestion': suggestion
        })
        
    except NoCredentialsError:
        error_msg = "AWS credentials not provided or invalid format"
        logger.error("NoCredentialsError during instance check")
        return jsonify({
            'success': False,
            'error': error_msg,
            'suggestion': 'Ensure AWS Access Key and Secret Key are provided'
        })
        
    except Exception as e:
        error_msg = f"Unexpected error during instance validation: {str(e)}"
        logger.error(f"Unexpected error during instance check: {e}")
        return jsonify({
            'success': False,
            'error': error_msg,
            'suggestion': 'Please try again or contact support if the issue persists'
        })


@app.route('/check-instance-bulk', methods=['POST'])
def check_instance_bulk():
    """Validate multiple AWS EC2 instances at once"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json() or {}
    instances_data = data.get('instances', [])
    
    if not instances_data:
        return jsonify({'success': False, 'error': 'No instances provided'})
    
    results = {
        'total': len(instances_data),
        'successful': 0,
        'failed': 0,
        'details': []
    }
    
    for instance_data in instances_data:
        instance_id = instance_data.get('instance_id', '').strip()
        
        try:
            # Use the existing check_instance logic
            check_result = check_single_instance_internal(instance_data)
            
            if check_result['success']:
                results['successful'] += 1
                results['details'].append({
                    'instance_id': instance_id,
                    'status': 'success',
                    'instance_name': check_result.get('instance_name'),
                    'details': check_result.get('instance_details')
                })
            else:
                results['failed'] += 1
                results['details'].append({
                    'instance_id': instance_id,
                    'status': 'failed',
                    'error': check_result.get('error')
                })
                
        except Exception as e:
            results['failed'] += 1
            results['details'].append({
                'instance_id': instance_id,
                'status': 'failed',
                'error': str(e)
            })
    
    return jsonify({
        'success': True,
        'results': results,
        'message': f"Checked {results['total']} instances: {results['successful']} successful, {results['failed']} failed"
    })


def check_single_instance_internal(data):
    """Internal function to check single instance (used by bulk checker)"""
    instance_id = data.get('instance_id', '').strip()
    access_key = data.get('access_key', '').strip()
    secret_key = data.get('secret_key', '').strip()
    region = data.get('region', '').strip()
    
    if not all([instance_id, access_key, secret_key, region]):
        return {'success': False, 'error': 'Missing required fields'}
    
    try:
        ec2_client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get('Reservations', [])
        
        if not reservations or not reservations[0].get('Instances'):
            return {'success': False, 'error': 'Instance not found'}
        
        instance = reservations[0]['Instances'][0]
        instance_name = instance_id
        
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag.get('Key') == 'Name' and tag.get('Value'):
                instance_name = tag['Value']
                break
        
        return {
            'success': True,
            'instance_name': instance_name,
            'instance_details': {
                'instance_id': instance_id,
                'instance_name': instance_name,
                'state': instance.get('State', {}).get('Name', 'unknown'),
                'instance_type': instance.get('InstanceType', 'unknown')
            }
        }
        
    except Exception as e:
        return {'success': False, 'error': str(e)}


############################################################ Notifications ############################################################

def add_notification(message, category='info', persistent=False):
    """Add notification to session with improved categorization"""
    if 'notifications' not in session:
        session['notifications'] = []
    
    # Prevent duplicate notifications
    existing_messages = [n.get('message') for n in session['notifications']]
    if message not in existing_messages:
        notification = {
            'message': message,
            'category': category,
            'timestamp': datetime.now(UTC).isoformat(),
            'persistent': persistent,
            'id': secrets.token_hex(8)  # Unique ID for each notification
        }
        session['notifications'].append(notification)
        session.modified = True
        
        # Also use Flask's flash for immediate display
        flash(message, category)
        
        # Log notification for debugging
        logger.info(f"Added notification [{category}]: {message}")


def get_notifications():
    """Retrieve all notifications from session"""
    notifications = session.get('notifications', [])
    
    # Clean up old notifications (older than 1 hour for non-persistent ones)
    current_time = datetime.now(UTC)
    filtered_notifications = []
    
    for notification in notifications:
        if notification.get('persistent', False):
            filtered_notifications.append(notification)
        else:
            try:
                notification_time = datetime.fromisoformat(notification.get('timestamp', ''))
                if (current_time - notification_time).total_seconds() < 3600:  # 1 hour
                    filtered_notifications.append(notification)
            except (ValueError, TypeError):
                # Keep notification if timestamp parsing fails
                filtered_notifications.append(notification)
    
    # Update session if notifications were cleaned up
    if len(filtered_notifications) != len(notifications):
        session['notifications'] = filtered_notifications
        session.modified = True
    
    return filtered_notifications


@app.route('/clear-notifications', methods=['POST'])
def clear_notifications():
    """Clear all or specific notifications"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    notification_id = request.form.get('notification_id') or request.json.get('notification_id')
    
    if notification_id:
        # Clear specific notification
        notifications = session.get('notifications', [])
        session['notifications'] = [n for n in notifications if n.get('id') != notification_id]
        session.modified = True
        logger.info(f"Cleared specific notification: {notification_id}")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'Notification cleared'})
    else:
        # Clear all notifications
        session['notifications'] = []
        session.modified = True
        logger.info("Cleared all notifications")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': True, 'message': 'All notifications cleared'})
    
    return redirect(request.referrer or url_for('dashboard'))


@app.route('/notifications/api', methods=['GET'])
def notifications_api():
    """API endpoint to get current notifications"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    notifications = get_notifications()
    
    return jsonify({
        'success': True,
        'notifications': notifications,
        'count': len(notifications)
    })


@app.route('/mark-notification-read', methods=['POST'])
def mark_notification_read():
    """Mark notification as read"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    notification_id = request.form.get('notification_id') or request.json.get('notification_id')
    
    if not notification_id:
        return jsonify({'success': False, 'error': 'Notification ID required'})
    
    notifications = session.get('notifications', [])
    for notification in notifications:
        if notification.get('id') == notification_id:
            notification['read'] = True
            notification['read_at'] = datetime.now(UTC).isoformat()
            break
    
    session['notifications'] = notifications
    session.modified = True
    
    return jsonify({'success': True, 'message': 'Notification marked as read'})


# Context processor to make notifications available in all templates
@app.context_processor
def inject_notifications():
    """Inject notifications into all templates"""
    return {
        'notifications': get_notifications(),
        'notification_count': len(get_notifications())
    }


# Enhanced notification functions for specific use cases
def notify_backup_success(instance_name, ami_id):
    """Notify successful backup creation"""
    message = f"Backup created successfully for {instance_name} (AMI: {ami_id})"
    add_notification(message, 'success')


def notify_backup_failure(instance_name, error_msg):
    """Notify backup failure"""
    message = f"Backup failed for {instance_name}: {error_msg}"
    add_notification(message, 'danger', persistent=True)


def notify_instance_added(instance_name):
    """Notify new instance registration"""
    message = f"Instance '{instance_name}' added successfully"
    add_notification(message, 'success')


def notify_cleanup_completed(count):
    """Notify cleanup operation completion"""
    message = f"Cleanup completed: {count} expired backups removed"
    add_notification(message, 'info')

############################################################ Backup Settings ############################################################

@app.route('/backup-settings', methods=['GET'])
def backup_settings():
    """Display backup settings configuration page"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    config = BackupSettings.query.first()
    if not config:
        # Create default backup settings with global config ID
        config = BackupSettings(
            instance_id="global-config",
            instance_name="Global Settings",
            retention_days=7,
            backup_frequency="0 2 * * *"  # Daily at 2 AM
        )
        db.session.add(config)
        db.session.commit()
        logger.info("Created default backup settings")
    
    return render_template('backup_settings.html', config=config)


@app.route('/update-backup-settings', methods=['POST'])
def update_backup_settings():
    """Update global backup settings and reschedule jobs"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    config = BackupSettings.query.first()
    if not config:
        flash("Backup settings not found", "danger")
        return redirect(url_for('backup_settings'))
    
    try:
        # Get form data
        retention_days = int(request.form.get('retention_days', 7))
        backup_frequency = request.form.get('backup_frequency', '0 2 * * *').strip()
        email_notifications = 'email_notifications' in request.form
        notification_email = request.form.get('notification_email', '').strip()
        max_concurrent_backups = int(request.form.get('max_concurrent_backups', 5))
        backup_timeout_minutes = int(request.form.get('backup_timeout_minutes', 60))
        
        # Validate inputs
        if retention_days < 1 or retention_days > 365:
            flash("Retention days must be between 1 and 365", "danger")
            return redirect(url_for('backup_settings'))
        
        is_valid, msg = validate_backup_frequency(backup_frequency)
        if not is_valid:
            flash(f"Invalid backup frequency: {msg}", "danger")
            return redirect(url_for('backup_settings'))
        
        if max_concurrent_backups < 1 or max_concurrent_backups > 20:
            flash("Max concurrent backups must be between 1 and 20", "danger")
            return redirect(url_for('backup_settings'))
        
        if backup_timeout_minutes < 5 or backup_timeout_minutes > 1440:  # 1 day max
            flash("Backup timeout must be between 5 and 1440 minutes", "danger")
            return redirect(url_for('backup_settings'))
        
        # Update configuration
        config.retention_days = retention_days
        config.backup_frequency = backup_frequency
        config.email_notifications = email_notifications
        config.notification_email = notification_email if email_notifications else None
        config.max_concurrent_backups = max_concurrent_backups
        config.backup_timeout_minutes = backup_timeout_minutes
        config.updated_at = datetime.now(UTC)
        
        db.session.commit()
        
        # Reschedule all backup jobs with new settings
        if 'scheduler' in globals() and scheduler.running:
            schedule_all_instance_backups()
            logger.info("Rescheduled all backup jobs after settings update")
        
        flash("Backup settings updated successfully", "success")
        
    except ValueError as e:
        flash("Invalid input values provided", "danger")
        logger.error(f"ValueError updating backup settings: {e}")
    except Exception as e:
        flash("Error updating backup settings", "danger")
        logger.error(f"Error updating backup settings: {e}")
    
    return redirect(url_for('backup_settings'))


############################################################ Scheduler Functions ############################################################

def schedule_all_instance_backups():
    """Schedule backup jobs for all active instances using both APScheduler and EventBridge"""
    try:
        # Clear existing APScheduler jobs
        scheduler.remove_all_jobs()
        logger.info("Cleared all existing APScheduler jobs")
        
        # Get global backup settings
        global_settings = BackupSettings.query.first()
        if not global_settings:
            logger.warning("No global backup settings found")
            return
        
        # Schedule jobs for each active instance
        active_instances = Instance.query.filter_by(is_active=True).all()
        success_count = 0
        
        for instance in active_instances:
            try:
                # Use instance-specific frequency or fall back to global
                frequency = get_effective_setting(
                    instance.backup_frequency, 
                    global_settings.backup_frequency
                )
                
                if not frequency:
                    logger.warning(f"No backup frequency configured for instance {instance.instance_id}")
                    continue
                
                # Schedule using both APScheduler and EventBridge
                schedule_instance_backup(instance)
                success_count += 1
                logger.info(f"Scheduled backup for instance {instance.instance_id} with frequency {frequency}")
                
            except Exception as e:
                logger.error(f"Error scheduling backup for {instance.instance_id}: {e}")
                continue
        
        logger.info(f"Successfully scheduled backup jobs for {success_count} out of {len(active_instances)} instances")
        
    except Exception as e:
        logger.error(f"Error in schedule_all_instance_backups: {e}")


def perform_backup(instance_id):
    """Perform backup for a specific instance"""
    try:
        instance = Instance.query.filter_by(instance_id=instance_id, is_active=True).first()
        if not instance:
            logger.warning(f"Instance {instance_id} not found or inactive")
            return
        
        # Create backup record
        backup = Backup(
            instance_id=instance.instance_id,
            instance_name=instance.instance_name,
            region=instance.region,
            status='Pending',
            backup_type='scheduled',
            retention_days=get_effective_setting(
                instance.retention_days,
                BackupSettings.query.first().retention_days if BackupSettings.query.first() else 7
            )
        )
        db.session.add(backup)
        db.session.commit()
        
        start_time = datetime.now(UTC)
        logger.info(f"Starting backup for instance {instance_id}")
        
        # Create EC2 client
        ec2_client = boto3.client(
            'ec2',
            region_name=instance.region,
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key
        )
        
        # Create AMI
        ami_name = f"{instance.instance_name}-backup-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
        
        response = ec2_client.create_image(
            InstanceId=instance.instance_id,
            Name=ami_name,
            Description=f"Automated backup of {instance.instance_name}",
            NoReboot=True
        )
        
        ami_id = response['ImageId']
        backup.ami_id = ami_id
        backup.ami_name = ami_name
        backup.status = 'Success'
        backup.duration_seconds = int((datetime.now(UTC) - start_time).total_seconds())
        
        db.session.commit()
        
        logger.info(f"Backup completed for {instance_id}: AMI {ami_id}")
        
        # Schedule cleanup of old backups
        cleanup_old_backups(instance_id)
        
    except Exception as e:
        logger.error(f"Backup failed for {instance_id}: {e}")
        
        # Update backup record with error
        if 'backup' in locals():
            backup.status = 'Failed'
            backup.error_message = str(e)
            backup.duration_seconds = int((datetime.now(UTC) - start_time).total_seconds()) if 'start_time' in locals() else 0
            db.session.commit()


def cleanup_old_backups(instance_id):
    """Clean up expired backups for an instance"""
    try:
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            return
        
        # Get expired backups
        expired_backups = Backup.query.filter(
            Backup.instance_id == instance_id,
            Backup.status == 'Success',
            Backup.cleanup_status != 'completed'
        ).all()
        
        ec2_client = boto3.client(
            'ec2',
            region_name=instance.region,
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key
        )
        
        for backup in expired_backups:
            if backup.is_expired and backup.ami_id:
                try:
                    # Delete AMI and associated snapshots
                    ec2_client.deregister_image(ImageId=backup.ami_id)
                    
                    # Get and delete associated snapshots
                    images = ec2_client.describe_images(ImageIds=[backup.ami_id])
                    if images['Images']:
                        for block_device in images['Images'][0].get('BlockDeviceMappings', []):
                            if 'Ebs' in block_device and 'SnapshotId' in block_device['Ebs']:
                                snapshot_id = block_device['Ebs']['SnapshotId']
                                ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                    
                    backup.cleanup_status = 'completed'
                    backup.cleanup_timestamp = datetime.now(UTC)
                    
                    logger.info(f"Cleaned up expired backup {backup.ami_id} for {instance_id}")
                    
                except ClientError as e:
                    if e.response['Error']['Code'] != 'InvalidAMIID.NotFound':
                        logger.error(f"Error cleaning up backup {backup.ami_id}: {e}")
                        backup.cleanup_status = 'failed'
                    else:
                        # AMI already deleted, mark as completed
                        backup.cleanup_status = 'completed'
                        backup.cleanup_timestamp = datetime.now(UTC)
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error in cleanup_old_backups for {instance_id}: {e}")

############################################################ scheduling ############################################################

@app.route('/schedules', methods=['GET', 'POST'])
def schedules():
    """Display and manage backup schedules for all instances"""
    if 'username' not in session:
        return redirect(url_for('login'))
    
    try:
        if request.method == 'POST':
            instance_id = request.form.get('instance_id')
            scheduler_type = request.form.get('scheduler_type')
            
            if instance_id and scheduler_type in ['python', 'eventbridge']:
                instance = Instance.query.filter_by(instance_id=instance_id).first()
                if instance:
                    # Update scheduler type
                    instance.scheduler_type = scheduler_type
                    db.session.commit()
                    
                    # Reschedule the backup
                    schedule_instance_backup(instance)
                    
                    flash(f'Updated scheduler type to {scheduler_type} for instance {instance.instance_name}', 'success')
                else:
                    flash('Instance not found', 'error')
            else:
                flash('Invalid scheduler type', 'error')
        
        scheduled_instances = []
        eventbridge_rules = []
        current_time = datetime.now(UTC)
        
        # Get all active instances
        instances = Instance.query.filter_by(is_active=True).all()
        
        for instance in instances:
            try:
                # Create AWS clients
                ec2_client = boto3.client(
                    'ec2',
                    region_name=instance.region,
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key
                )
                
                eventbridge_client = boto3.client(
                    'events',
                    region_name=instance.region,
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key
                )
                
                # Get instance details from AWS
                try:
                    ec2_response = ec2_client.describe_instances(InstanceIds=[instance.instance_id])
                    if ec2_response.get('Reservations'):
                        aws_instance = ec2_response['Reservations'][0]['Instances'][0]
                        instance_state = aws_instance.get('State', {}).get('Name', 'unknown')
                        instance_type = aws_instance.get('InstanceType', 'unknown')
                    else:
                        instance_state = 'not-found'
                        instance_type = 'unknown'
                except Exception as e:
                    logger.warning(f"Could not get instance details for {instance.instance_id}: {e}")
                    instance_state = 'unknown'
                    instance_type = 'unknown'
                
                # Check for EventBridge rule for this instance
                rule_name = f"backup-{instance.instance_id}"
                rule_status = None
                schedule = None
                next_run = None
                timezone_info = 'UTC'
                
                try:
                    # Try to get the backup rule
                    rule_response = eventbridge_client.describe_rule(Name=rule_name)
                    rule_status = {
                        'exists': True,
                        'state': rule_response.get('State', 'UNKNOWN'),
                        'schedule': rule_response.get('ScheduleExpression', ''),
                        'description': rule_response.get('Description', '')
                    }
                    schedule = rule_response.get('ScheduleExpression', instance.backup_frequency)
                    
                    # Calculate next run time
                    next_run = calculate_next_run(schedule, current_time)
                    
                except eventbridge_client.exceptions.ResourceNotFoundException:
                    rule_status = {
                        'exists': False,
                        'state': 'NOT_CONFIGURED'
                    }
                    schedule = instance.backup_frequency
                    next_run = calculate_next_run(schedule, current_time)
                except Exception as e:
                    logger.warning(f"Error checking EventBridge rule for {instance.instance_id}: {e}")
                    rule_status = {
                        'exists': False,
                        'state': 'ERROR'
                    }
                    schedule = instance.backup_frequency
                
                scheduled_instances.append({
                    'instance_id': instance.instance_id,
                    'instance_name': instance.instance_name,
                    'instance_type': instance_type,
                    'state': instance_state,
                    'schedule': schedule,
                    'timezone': timezone_info,
                    'next_run': next_run,
                    'rule_status': rule_status,
                    'region': instance.region
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance.instance_id}: {e}")
                # Still add the instance with basic info
                scheduled_instances.append({
                    'instance_id': instance.instance_id,
                    'instance_name': instance.instance_name,
                    'instance_type': 'unknown',
                    'state': 'error',
                    'schedule': instance.backup_frequency,
                    'timezone': 'UTC',
                    'next_run': None,
                    'rule_status': {'exists': False, 'state': 'ERROR'},
                    'region': instance.region
                })
        
        # Get all backup-related EventBridge rules across all instances
        try:
            # Group instances by region to minimize API calls
            regions = {}
            for instance in instances:
                if instance.region not in regions:
                    regions[instance.region] = []
                regions[instance.region].append(instance)
            
            for region, region_instances in regions.items():
                if not region_instances:
                    continue
                
                # Use first instance's credentials for the region
                instance = region_instances[0]
                try:
                    eventbridge_client = boto3.client(
                        'events',
                        region_name=region,
                        aws_access_key_id=instance.access_key,
                        aws_secret_access_key=instance.secret_key
                    )
                    
                    # List all rules with backup prefix
                    rules_response = eventbridge_client.list_rules(NamePrefix='backup-')
                    
                    for rule in rules_response.get('Rules', []):
                        rule_detail = {
                            'name': rule.get('Name', ''),
                            'state': rule.get('State', 'UNKNOWN'),
                            'schedule': rule.get('ScheduleExpression', ''),
                            'description': rule.get('Description', ''),
                            'region': region
                        }
                        
                        # Get targets count
                        try:
                            targets_response = eventbridge_client.list_targets_by_rule(Rule=rule['Name'])
                            rule_detail['targets'] = len(targets_response.get('Targets', []))
                        except Exception:
                            rule_detail['targets'] = 0
                        
                        # Calculate next run
                        if rule_detail['schedule']:
                            rule_detail['next_run'] = calculate_next_run(rule_detail['schedule'], current_time)
                        else:
                            rule_detail['next_run'] = None
                        
                        eventbridge_rules.append(rule_detail)
                        
                except Exception as e:
                    logger.error(f"Error listing EventBridge rules for region {region}: {e}")
        
        except Exception as e:
            logger.error(f"Error processing EventBridge rules: {e}")
        
        return render_template('schedules.html',
                             scheduled_instances=scheduled_instances,
                             eventbridge_rules=eventbridge_rules,
                             current_time=current_time)
    
    except Exception as e:
        logger.error(f"Error in schedules route: {e}")
        flash("Error loading schedules", "danger")
        return render_template('schedules.html',
                             scheduled_instances=[],
                             eventbridge_rules=[],
                             current_time=current_time)


def calculate_next_run(schedule_expression, current_time):
    """Calculate next run time for a schedule expression"""
    try:
        if not schedule_expression:
            return None
        
        # Handle cron expressions (rate expressions not fully supported here)
        if schedule_expression.startswith('cron('):
            # Extract cron expression
            cron_expr = schedule_expression[5:-1]  # Remove 'cron(' and ')'
            parts = cron_expr.split()
            
            if len(parts) == 6:  # AWS cron format: minute hour day month day-of-week year
                # Convert to standard cron format (remove year)
                cron_parts = parts[:5]
                
                # Simple next run calculation for common patterns
                minute, hour, day, month, dow = cron_parts
                
                next_run = current_time.replace(second=0, microsecond=0)
                
                # Handle daily backups (common case)
                if minute.isdigit() and hour.isdigit() and day == '*' and month == '*' and dow == '*':
                    target_hour = int(hour)
                    target_minute = int(minute)
                    
                    next_run = next_run.replace(hour=target_hour, minute=target_minute)
                    
                    # If time has passed today, schedule for tomorrow
                    if next_run <= current_time:
                        next_run += timedelta(days=1)
                    
                    return next_run
                    
                # Handle weekly backups
                elif minute.isdigit() and hour.isdigit() and day == '*' and month == '*' and dow.isdigit():
                    target_hour = int(hour)
                    target_minute = int(minute)
                    target_dow = int(dow)  # 0 = Sunday, 1 = Monday, etc.
                    
                    # Calculate days until target day of week
                    current_dow = current_time.weekday() + 1  # Convert Monday=0 to Sunday=1 format
                    if current_dow == 7:
                        current_dow = 0  # Sunday = 0
                    
                    days_ahead = target_dow - current_dow
                    if days_ahead <= 0:  # Target day already happened this week
                        days_ahead += 7
                    
                    next_run = next_run.replace(hour=target_hour, minute=target_minute)
                    next_run += timedelta(days=days_ahead)
                    
                    return next_run
        
        elif schedule_expression.startswith('rate('):
            # Handle rate expressions like rate(1 day), rate(2 hours)
            rate_expr = schedule_expression[5:-1]  # Remove 'rate(' and ')'
            parts = rate_expr.split()
            
            if len(parts) >= 2:
                value = int(parts[0])
                unit = parts[1].lower().rstrip('s')  # Remove plural 's'
                
                if unit in ['minute', 'minutes']:
                    return current_time + timedelta(minutes=value)
                elif unit in ['hour', 'hours']:
                    return current_time + timedelta(hours=value)
                elif unit in ['day', 'days']:
                    return current_time + timedelta(days=value)
        
        # If we can't parse the expression, return None
        return None
        
    except Exception as e:
        logger.warning(f"Error calculating next run for schedule '{schedule_expression}': {e}")
        return None


@app.template_filter('time_until')
def time_until_filter(target_time):
    """Template filter to show human-readable time until target"""
    if not target_time:
        return None
    
    try:
        now = datetime.now(UTC)
        if target_time <= now:
            return "Overdue"
        
        delta = target_time - now
        
        if delta.days > 0:
            if delta.days == 1:
                return f"{delta.days} day"
            else:
                return f"{delta.days} days"
        
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        
        if hours > 0:
            if hours == 1:
                return f"{hours} hour"
            else:
                return f"{hours} hours"
        
        if minutes > 0:
            if minutes == 1:
                return f"{minutes} minute"
            else:
                return f"{minutes} minutes"
        
        return "Less than a minute"
        
    except Exception as e:
        logger.warning(f"Error calculating time until: {e}")
        return "Unknown"


@app.route('/api/schedules/refresh')
def api_refresh_schedules():
    """API endpoint to refresh schedule data (for AJAX calls)"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get fresh schedule data
        scheduled_instances = []
        current_time = datetime.now(UTC)
        
        instances = Instance.query.filter_by(is_active=True).all()
        
        for instance in instances:
            try:
                # Get basic instance info and next run time
                schedule = instance.backup_frequency
                next_run = calculate_next_run(schedule, current_time)
                
                scheduled_instances.append({
                    'instance_id': instance.instance_id,
                    'instance_name': instance.instance_name,
                    'schedule': schedule,
                    'next_run': next_run.isoformat() if next_run else None,
                    'next_run_human': time_until_filter(next_run) if next_run else None
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance.instance_id}: {e}")
        
        return jsonify({
            'scheduled_instances': scheduled_instances,
            'current_time': current_time.isoformat(),
            'refresh_time': current_time.strftime('%Y-%m-%d %H:%M:%S UTC')
        })
    
    except Exception as e:
        logger.error(f"Error refreshing schedules: {e}")
        return jsonify({'error': 'Failed to refresh schedules'}), 500

############################################################ Application Startup ############################################################

def init_app():
    """Initialize the application"""
    with app.app_context():
        try:
            # Create database tables
            db.create_all()
            
            # Initialize database with default data
            if not init_database():
                logger.error("Failed to initialize database")
                return False
            
            # Start scheduler if not running
            if not scheduler.running:
                scheduler.start()
                schedule_all_instance_backups()
                logger.info("✅ Backup scheduler started successfully")
            
            return True
        except Exception as e:
            logger.error(f"Error initializing application: {e}")
            return False

if __name__ == '__main__':
    try:
        if init_app():
            logger.info("🚀 Starting AWS Backup Manager")
            app.run(host="0.0.0.0", port=5000)
    except Exception as e:
        logger.error(f"Error starting application: {e}")
    finally:
        # Cleanup scheduler on exit
        if scheduler.running:
            scheduler.shutdown()
            logger.info("Scheduler shutdown complete")