# Keep or add these imports
import pyotp, qrcode, io, base64, boto3, pytz, os, csv, secrets, logging, json, time
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, make_response
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta, UTC
from flask_apscheduler import APScheduler
from io import StringIO
from botocore.exceptions import ClientError, NoCredentialsError
from models import db, User, Instance, BackupSettings, Backup, AWSCredential
from lambda_callback import lambda_callback

# Monkeypatch dateutil and pytz to fix deprecation warnings
import dateutil.tz.tz
import pytz.tzinfo

# Fix dateutil.tz.tz.EPOCH
original_epoch = dateutil.tz.tz.EPOCH
dateutil.tz.tz.EPOCH = datetime.fromtimestamp(0, UTC)

# Fix pytz.tzinfo._epoch
original_pytz_epoch = pytz.tzinfo._epoch
pytz.tzinfo._epoch = datetime.fromtimestamp(0, UTC)

# Load environment variables from .env file
load_dotenv()

# Configure logging
import os
import logging
import sys
import io
from logging.handlers import RotatingFileHandler

# Get logging configuration from environment variables
log_level = os.environ.get('LOG_LEVEL', 'INFO')
log_dir = os.environ.get('LOG_DIR', 'logs')
access_log = os.environ.get('ACCESS_LOG', 'access.log')
error_log = os.environ.get('ERROR_LOG', 'error.log')
app_log = os.environ.get('APP_LOG', 'app.log')
log_format = os.environ.get('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_date_format = os.environ.get('LOG_DATE_FORMAT', '%Y-%m-%d %H:%M:%S')
log_max_bytes = int(os.environ.get('LOG_MAX_BYTES', 10485760))  # 10MB default
log_backup_count = int(os.environ.get('LOG_BACKUP_COUNT', 5))  # 5 backups default

# Create logs directory if it doesn't exist
try:
    log_dir_abs = os.path.abspath(log_dir)
    if not os.path.exists(log_dir_abs):
        os.makedirs(log_dir_abs)
    print(f"Created logs directory at {log_dir_abs}")
except Exception as e:
    print(f"Error creating logs directory: {e}")
    # Fall back to current directory
    log_dir = '.'
    log_dir_abs = os.path.abspath(log_dir)

# Configure formatter
formatter = logging.Formatter(log_format, log_date_format)

# Configure root logger
root_logger = logging.getLogger()
root_logger.setLevel(getattr(logging, log_level))

# Clear existing handlers to avoid duplicates
for handler in root_logger.handlers[:]:  # Use a copy of the list
    root_logger.removeHandler(handler)

# Add console handler - use sys.stdout to avoid encoding issues
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
root_logger.addHandler(console_handler)

# Function to safely create a file handler
def create_file_handler(log_path, level, max_bytes, backup_count):
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        # Create an empty file if it doesn't exist
        if not os.path.exists(log_path):
            with open(log_path, 'w', encoding='utf-8') as f:
                pass
        
        # Create the handler with UTF-8 encoding
        handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        handler.setFormatter(formatter)
        handler.setLevel(level)
        return handler
    except Exception as e:
        print(f"Error creating log file {log_path}: {e}")
        return None

try:
    # Configure app logger for general application logs
    app_log_path = os.path.join(log_dir_abs, app_log)
    app_handler = create_file_handler(
        app_log_path,
        getattr(logging, log_level),
        log_max_bytes,
        log_backup_count
    )
    if app_handler:
        root_logger.addHandler(app_handler)
        print(f"App log file created at {app_log_path}")

    # Configure error logger for error-level logs
    error_log_path = os.path.join(log_dir_abs, error_log)
    error_handler = create_file_handler(
        error_log_path,
        logging.ERROR,
        log_max_bytes,
        log_backup_count
    )
    if error_handler:
        root_logger.addHandler(error_handler)
        print(f"Error log file created at {error_log_path}")

    # Configure access logger for Flask requests
    access_log_path = os.path.join(log_dir_abs, access_log)
    access_logger = logging.getLogger('werkzeug')
    
    # Remove existing handlers from werkzeug logger to avoid duplicates
    for handler in access_logger.handlers[:]:
        access_logger.removeHandler(handler)
    
    # Set propagate to False to prevent werkzeug logs from being sent to the root logger
    access_logger.propagate = False
    
    access_handler = create_file_handler(
        access_log_path,
        logging.INFO,
        log_max_bytes,
        log_backup_count
    )
    if access_handler:
        access_logger.addHandler(access_handler)
        print(f"Access log file created at {access_log_path}")
    
    # Add a console handler for werkzeug logs
    werkzeug_console = logging.StreamHandler(sys.stdout)
    werkzeug_console.setFormatter(formatter)
    access_logger.addHandler(werkzeug_console)

except Exception as e:
    print(f"Error setting up log files: {e}")
    # Continue with console logging only

# Create logger for this module
logger = logging.getLogger(__name__)
logger.info("Logging initialized at level {} with logs in {}".format(log_level, log_dir))

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
    # SCHEDULER_TIMEZONE=os.environ.get('SCHEDULER_TIMEZONE', 'UTC'),
    DEBUG=os.environ.get('FLASK_DEBUG', '0') == '1'
)

# Initialize extensions
db.init_app(app)
scheduler = APScheduler()
scheduler.init_app(app)

# Register blueprints
app.register_blueprint(lambda_callback)

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

def calculate_next_backup_time(backup_frequency):
    """Calculate the next backup time based on backup frequency
    
    Args:
        backup_frequency (str): Backup frequency in cron format or @interval format
        
    Returns:
        datetime: The next backup time
    """
    from croniter import croniter
    from datetime import datetime, timedelta
    import pytz
    
    now = datetime.now(pytz.UTC)
    
    # Handle interval-based schedules (@12 for every 12 hours)
    if backup_frequency.startswith('@'):
        try:
            interval_hours = int(backup_frequency[1:])
            return now + timedelta(hours=interval_hours)
        except ValueError:
            logger.error(f"Invalid interval format: {backup_frequency}")
            # Default to 24 hours if invalid
            return now + timedelta(hours=24)
    
    # Handle cron-based schedules
    try:
        # Create a croniter instance
        cron = croniter(backup_frequency, now)
        # Get the next occurrence
        next_time = cron.get_next(datetime)
        return next_time
    except Exception as e:
        logger.error(f"Error calculating next backup time from cron expression '{backup_frequency}': {e}")
        # Default to 24 hours if invalid
        return now + timedelta(hours=24)

def poll_ami_status(instance_id=None, return_details=False):
    """Poll AWS for AMI status updates for instances marked for polling
    
    This function is designed to be scheduled to run periodically to check for AMI status
    updates for instances that are using EventBridge but don't have an API Gateway endpoint
    configured for callbacks.
    
    Args:
        instance_id (str, optional): If provided, only poll for this specific instance
        return_details (bool, optional): If True, return detailed information about the polling process
    
    Returns:
        dict: If return_details is True, returns a dictionary with polling details
    """
    # Initialize result dictionary if we need to return details
    result = {
        'instances_polled': 0,
        'total_amis_found': 0,
        'new_records_created': 0,
        'records_updated': 0,
        'errors': [],
        'instance_details': {}
    } if return_details else None
    
    try:
        # Get instances that need status polling
        query = Instance.query.filter_by(is_active=True, needs_status_polling=True, scheduler_type='eventbridge')
        
        # If instance_id is provided, only poll for that specific instance
        if instance_id:
            query = query.filter_by(instance_id=instance_id)
            
        instances = query.all()
        
        if not instances:
            logger.debug("No instances require AMI status polling")
            if return_details:
                return result
            return
            
        logger.info(f"Polling AMI status for {len(instances)} instances")
        
        if return_details:
            result['instances_polled'] = len(instances)
        
        for instance in instances:
            try:
                # Create boto3 session with instance credentials
                boto3_session = boto3.Session(
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key,
                    region_name=instance.region
                )
                
                # Create EC2 client
                ec2_client = boto3_session.client('ec2')
                
                # Get the most recent backup record for this instance
                latest_backup = Backup.query.filter_by(instance_id=instance.instance_id).order_by(Backup.created_at.desc()).first()
                
                # Calculate when the next backup should have occurred
                if latest_backup:
                    # If we have a previous backup, calculate when the next one should occur
                    last_backup_time = latest_backup.timestamp
                    # Add a buffer time (10 minutes) to account for scheduling delays
                    buffer_time = timedelta(minutes=10)
                    
                    # Calculate the next expected backup time based on the frequency
                    from_time = last_backup_time - buffer_time
                else:
                    # If no previous backup, use a reasonable time window (24 hours)
                    from_time = datetime.now(UTC) - timedelta(hours=24)
                
                # Get all AMIs created after the from_time
                try:
                    # Filter AMIs by state only, we'll filter by date manually
                    response = ec2_client.describe_images(
                        Owners=['self'],
                        Filters=[
                            {
                                'Name': 'state',
                                'Values': ['available', 'pending']
                            }
                            # Removed date filter - we'll filter by exact timestamp below
                        ]
                    )
                    
                    # Log the number of AMIs found before filtering
                    logger.debug(f"Found {len(response.get('Images', []))} AMIs before timestamp filtering")
                    
                    # Filter images that match our instance ID pattern and were created after from_time
                    instance_amis = []
                    for image in response.get('Images', []):
                        # Check creation date against our from_time
                        creation_date_str = image.get('CreationDate')
                        try:
                            # AWS returns ISO format timestamps
                            creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                            
                            # Skip images created before our from_time
                            if creation_date < from_time:
                                logger.debug(f"Skipping AMI {image.get('ImageId')} created at {creation_date} (before {from_time})")
                                continue
                        except (ValueError, AttributeError) as e:
                            logger.warning(f"Could not parse creation date '{creation_date_str}': {e}")
                            # If we can't parse the date, include it to be safe
                        
                        # Check if this AMI was created for this instance
                        # Look for instance ID in name, description, or tags
                        name = image.get('Name', '')
                        description = image.get('Description', '')
                        tags = image.get('Tags', [])
                        
                        # Check if instance ID is in name or description
                        if instance.instance_id in name or instance.instance_id in description:
                            logger.debug(f"Found AMI {image.get('ImageId')} matching instance ID in name/description")
                            instance_amis.append(image)
                            continue
                            
                        # Check if instance ID is in tags
                        for tag in tags:
                            if tag.get('Key') == 'InstanceId' and tag.get('Value') == instance.instance_id:
                                logger.debug(f"Found AMI {image.get('ImageId')} matching instance ID in tags")
                                instance_amis.append(image)
                                break
                    
                    # Process any AMIs found
                    logger.info(f"Found {len(instance_amis)} AMIs matching instance {instance.instance_id} after filtering")
                    for ami in instance_amis:
                        ami_id = ami.get('ImageId')
                        ami_name = ami.get('Name')
                        ami_state = ami.get('State')
                        creation_date_str = ami.get('CreationDate')
                        
                        logger.debug(f"Processing AMI {ami_id} (name: {ami_name}, state: {ami_state})")
                        
                        # Parse the creation date
                        try:
                            # AWS returns ISO format timestamps
                            creation_date = datetime.fromisoformat(creation_date_str.replace('Z', '+00:00'))
                            logger.debug(f"AMI {ami_id} creation date: {creation_date}")
                        except (ValueError, AttributeError) as e:
                            # If we can't parse the date, use current time
                            creation_date = datetime.now(UTC)
                            logger.warning(f"Could not parse creation date for AMI {ami_id}: {e}, using current time")
                        
                        # Check if we already have a record for this AMI
                        existing_backup = Backup.query.filter_by(instance_id=instance.instance_id, ami_id=ami_id).first()
                        
                        if existing_backup:
                            logger.debug(f"Found existing backup record for AMI {ami_id}")
                            # Update the status if needed
                            if existing_backup.status != 'Success' and ami_state == 'available':
                                existing_backup.status = 'Success'
                                existing_backup.completed_at = datetime.now(UTC)
                                try:
                                    db.session.commit()
                                    logger.info(f"Updated status to Success for AMI {ami_id} (instance {instance.instance_id})")
                                except Exception as e:
                                    db.session.rollback()
                                    logger.error(f"Error updating backup record for AMI {ami_id}: {e}")
                        else:
                            logger.debug(f"No existing backup record found for AMI {ami_id}, creating new record")
                            # Create a new backup record
                            try:
                                new_backup = Backup(
                                    instance_id=instance.instance_id,
                                    ami_id=ami_id,
                                    ami_name=ami_name,
                                    status='Success' if ami_state == 'available' else 'Pending',
                                    timestamp=creation_date,
                                    created_at=datetime.now(UTC),
                                    completed_at=datetime.now(UTC) if ami_state == 'available' else None,
                                    retention_days=instance.retention_days,
                                    region=instance.region,
                                    instance_name=instance.instance_name
                                )
                                db.session.add(new_backup)
                                db.session.commit()
                                logger.info(f"Created new backup record for AMI {ami_id} (instance {instance.instance_id})")
                            except Exception as e:
                                db.session.rollback()
                                logger.error(f"Error creating backup record for AMI {ami_id}: {e}")
                    
                    if not instance_amis:
                        logger.debug(f"No new AMIs found for instance {instance.instance_id}")
                        
                except Exception as e:
                    logger.error(f"Error querying AMIs for instance {instance.instance_id}: {e}")
            
            except Exception as e:
                logger.error(f"Error polling AMI status for instance {instance.instance_id}: {e}")
                continue
    
    except Exception as e:
        logger.error(f"Error in poll_ami_status: {e}")

# Schedule the AMI status polling job based on instance backup frequency, falling back to global polling setting
def schedule_ami_status_polling(run_immediate=False, instance_id=None):
    """Schedule the AMI status polling job based on instance backup frequency
    
    Args:
        run_immediate (bool): If True, schedule a one-time job to run after a short delay
                             to check newly created AMIs
        instance_id (str): Optional instance ID to schedule polling specifically for this instance
    """
    job_id = "ami_status_polling"
    if scheduler.get_job(job_id):
        scheduler.remove_job(job_id)
    
    # Create a wrapper function that ensures app context is available
    def poll_ami_status_with_context(specific_instance_id=None):
        with app.app_context():
            poll_ami_status(instance_id=specific_instance_id or instance_id)
    
    # Get instances that need polling (only EventBridge instances)
    query = Instance.query.filter_by(
        is_active=True, 
        needs_status_polling=True, 
        scheduler_type='eventbridge'
    )
    
    # If instance_id is provided, only schedule for that specific instance
    if instance_id:
        query = query.filter_by(instance_id=instance_id)
    
    instances_needing_polling = query.all()
    
    if not instances_needing_polling:
        logger.info("No EventBridge instances require AMI status polling, skipping scheduler setup")
        return
    
    # Try to use the backup_frequency from the first instance
    try:
        # Use the first instance's backup_frequency as the polling schedule
        instance_frequency = instances_needing_polling[0].backup_frequency
        logger.info(f"Using instance backup frequency for polling: {instance_frequency}")
        
        # Schedule the regular polling job using the instance's backup frequency
        scheduler.add_job(
            id=job_id,
            func=poll_ami_status_with_context,
            trigger='cron',
            replace_existing=True,
            **parse_cron_expression(instance_frequency)
        )
        logger.info(f"Scheduled AMI status polling job with instance frequency: {instance_frequency}")
    except Exception as e:
        # If there's any issue with using instance frequency, fall back to global polling
        logger.warning(f"Error using instance backup frequency for polling: {e}. Falling back to global polling.")
        
        # Get global backup settings for polling frequency as fallback
        global_settings = BackupSettings.query.first()
        
        if not global_settings or not global_settings.global_polling:
            logger.warning("No global polling setting found, using default hourly cron schedule")
            global_polling = "0 * * * *"  # Default to hourly if not set
        else:
            global_polling = global_settings.global_polling
            logger.info(f"Using global polling schedule as fallback: {global_polling}")
        
        # Schedule the regular polling job using the global polling cron schedule
        scheduler.add_job(
            id=job_id,
            func=poll_ami_status_with_context,
            trigger='cron',
            replace_existing=True,
            **parse_cron_expression(global_polling)
        )
        logger.info(f"Scheduled AMI status polling job with fallback cron schedule: {global_polling}")
    
    # If run_immediate is requested for a specific instance, schedule a one-time job
    if run_immediate and instance_id:
        immediate_job_id = f"immediate_ami_status_polling_{instance_id}"
        if not scheduler.get_job(immediate_job_id):
            # Schedule immediate polling with a 10-second delay
            def poll_specific_instance():
                # Add a 10-second sleep before polling to ensure AWS has time to process
                time.sleep(60)
                poll_ami_status_with_context(specific_instance_id=instance_id)
            
            scheduler.add_job(
                id=immediate_job_id,
                func=poll_specific_instance,
                trigger='date',
                run_date=datetime.now(),  # Run immediately, sleep is inside the function
                replace_existing=True
            )
            logger.info(f"Scheduled one-time AMI status polling job for instance {instance_id} with 60-second sleep")
    
    # If run_immediate is requested but no specific instance_id was provided,
    # schedule a general immediate polling job
    elif run_immediate and not instance_id:
        immediate_job_id = "immediate_ami_status_polling"
        if not scheduler.get_job(immediate_job_id):
            # Create a function for general polling (no specific instance)
            def poll_all_instances():
                # Add a 10-second sleep before polling to ensure AWS has time to process
                time.sleep(60)
                poll_ami_status_with_context()
                
            scheduler.add_job(
                id=immediate_job_id,
                func=poll_all_instances,
                trigger='date',
                run_date=datetime.now(),  # Run immediately, sleep is inside the function
                replace_existing=True
            )
            logger.info("Scheduled one-time AMI status polling job with 60-second sleep")
    
    # This appears to be a duplicate of the above condition, but keeping for safety
    # with the updated sleep implementation
    if run_immediate and not instance_id and not scheduler.get_job("immediate_ami_status_polling"):
        # Create a function for general polling (no specific instance)
        def poll_all_instances():
            # Add a 10-second sleep before polling to ensure AWS has time to process
            time.sleep(60)
            poll_ami_status_with_context()
            
        scheduler.add_job(
            id="immediate_ami_status_polling",
            func=poll_all_instances,
            trigger='date',
            run_date=datetime.now(),  # Run immediately, sleep is inside the function
            replace_existing=True
        )
        logger.info("Scheduled one-time AMI status polling job with 10-second sleep")

# # Initialize database and scheduler after app starts
# with app.app_context():
#     try:
#         # Create database tables
#         db.create_all()
#         logger.info("✅ Database tables created successfully")
        
#         # Initialize scheduler
#         if not scheduler.running:
#             scheduler.start()
#             logger.info("✅ Scheduler started successfully")
            
#             # Schedule backups for active instances
#             schedule_all_instance_backups()
            
#     except Exception as e:
#         logger.error(f"Error during initialization: {e}")


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

# def create_backup(instance_id):
#     """Create backup for an instance (called by scheduler)"""
#     with app.app_context():
#         try:
#             # Get instance and global settings
#             inst = Instance.query.filter_by(instance_id=instance_id, is_active=True).first()
#             if not inst:
#                 logger.error(f"Instance {instance_id} not found or inactive")
#                 return

#             global_config = BackupSettings.query.first()
#             if not global_config:
#                 logger.error("Global backup settings not found")
#                 return

#             # Get effective retention days
#             retention_days = get_effective_setting(
#                 inst.retention_days,
#                 global_config.retention_days
#             )

#             # Create AMI backup
#             ec2_client = boto3.client(
#                 'ec2',
#                 region_name=inst.region,
#                 aws_access_key_id=inst.access_key,
#                 aws_secret_access_key=inst.secret_key
#             )

#             # Generate AMI name with timestamp
#             timestamp_str = datetime.now(pytz.UTC).strftime("%Y%m%d_%H%M%S")
#             ami_name = f"{inst.instance_name}_{timestamp_str}_backup"

#             # Create backup record
#             backup = Backup(
#                 instance_id=instance_id,
#                 instance_name=inst.instance_name,
#                 ami_name=ami_name,
#                 timestamp=datetime.now(UTC),
#                 status='Pending',
#                 region=inst.region,
#                 retention_days=retention_days,
#                 backup_type='scheduled'
#             )
#             db.session.add(backup)
#             db.session.commit()

#             try:
#                 # Create AMI
#                 response = ec2_client.create_image(
#                     InstanceId=instance_id,
#                     Name=ami_name,
#                     Description=f"Scheduled backup created at {timestamp_str}",
#                     NoReboot=True
#                 )

#                 ami_id = response['ImageId']
#                 Backup.snapshot_id = ami_id
#                 backup.status = 'Success'
#                 db.session.commit()

#                 logger.info(f"Successfully created backup AMI {ami_id} for instance {instance_id}")

#             except Exception as e:
#                 backup.status = 'Failed'
#                 backup.error_message = str(e)
#                 db.session.commit()
#                 logger.error(f"Failed to create backup for instance {instance_id}: {e}")
#                 raise

#         except Exception as e:
#             logger.error(f"Error in create_backup for instance {instance_id}: {e}")
#             raise
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
            logger.info(f"Removed job {job_id}")            

        # Schedule the backup based on scheduler_type
        if instance.scheduler_type == 'python':
            # Schedule with Flask-APScheduler
            if instance.backup_frequency.startswith('@'):
                # Handle interval-based schedules
                interval = instance.backup_frequency[1:]
                scheduler.add_job(
                    id=job_id,
                    func=backup_instance,  # Using your existing backup_instance function
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
                    func=backup_instance,  # Using your existing backup_instance function
                    args=[instance.instance_id],
                    trigger='cron',
                    replace_existing=True,
                    **cron_kwargs
                )
            logger.info(f"Scheduled Python backup job for instance {instance.instance_id}")
        elif instance.scheduler_type == 'eventbridge':
            # Schedule with AWS EventBridge
            try:
                # Create boto3 session with instance credentials
                boto3_session = boto3.Session(
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key,
                    region_name=instance.region
                )
                
                # Create EventBridge client
                events_client = boto3_session.client('events')
                
                # Create or update rule
                rule_name = f"AMIVault-Backup-{instance.instance_id}"
                
                # Convert cron expression to EventBridge format using utility function
                try:
                    aws_cron = convert_to_eventbridge_format(instance.backup_frequency)
                    # Log the cron expression for debugging
                    logger.info(f"EventBridge expression for {instance.instance_id}: {aws_cron}")
                except ValueError as e:
                    error_msg = f"Error converting cron expression for {instance.instance_id}: {e}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                # Create or update the rule
                try:
                    rule_response = events_client.put_rule(
                        Name=rule_name,
                        ScheduleExpression=aws_cron,
                        State='ENABLED',
                        Description=f"AMIVault backup schedule for {instance.instance_id}"
                    )
                    rule_arn = rule_response.get('RuleArn')
                    logger.info(f"Created/updated EventBridge rule: {rule_name} with ARN: {rule_arn}")
                except Exception as e:
                    error_msg = f"Failed to create EventBridge rule for {instance.instance_id}: {e}"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
                
                # Configure the target for the EventBridge rule
                # First check if we need to deploy a Lambda function
                lambda_arn = os.environ.get('BACKUP_LAMBDA_ARN', '')
                api_endpoint = os.environ.get('API_GATEWAY_ENDPOINT', '')
                
                # If no Lambda ARN is set, try to deploy one automatically
                if not lambda_arn and not api_endpoint:
                    try:
                        # Create Lambda function if it doesn't exist
                        lambda_arn = deploy_lambda_function(instance)
                        logger.info(f"Automatically deployed Lambda function with ARN: {lambda_arn}")
                    except Exception as e:
                        logger.error(f"Failed to automatically deploy Lambda function: {e}")
                        # Continue with fallback options
                
                if not lambda_arn and not api_endpoint:
                    # Create a default EC2 target that will create an AMI
                    # This is a fallback if no Lambda or API Gateway is configured
                    target_id = f"AMIVault-Target-{instance.instance_id}"
                    
                    # Create EC2 client to use for the target
                    ec2_client = boto3_session.client('ec2')
                    
                    # Create a role for EventBridge to assume (or use an existing one)
                    # This is a simplified example - in production, you would create a proper IAM role
                    # with permissions to create AMIs
                    
                    # For now, we'll use the EC2 instance itself as the target
                    try:
                        events_client.put_targets(
                            Rule=rule_name,
                            Targets=[
                                {
                                    'Id': target_id,
                                    'Arn': f"arn:aws:ec2:{instance.region}:{boto3_session.client('sts').get_caller_identity()['Account']}:instance/{instance.instance_id}",
                                    'Input': json.dumps({
                                        'instance_id': instance.instance_id,
                                        'action': 'create-image',
                                        'name': f"{instance.instance_name}_{datetime.now().strftime('%Y_%m_%d_%I_%M_%p')}_eventbridge",
                                        'description': f"Automated backup created by AMIVault"
                                    })
                                }
                            ]
                        )
                        logger.info(f"Configured EventBridge target for {instance.instance_id} using EC2 instance as target")
                    except Exception as e:
                        logger.error(f"Failed to configure EC2 target for EventBridge rule: {e}")
                        logger.warning("No API Gateway endpoint or Lambda ARN configured for EventBridge target. Please set one of these environment variables.")
                        # We'll continue without a target for now, but log a warning
                elif lambda_arn:
                    # Use Lambda function as target
                    target_id = f"AMIVault-Target-{instance.instance_id}"
                    try:
                        events_client.put_targets(
                            Rule=rule_name,
                            Targets=[
                                {
                                    'Id': target_id,
                                    'Arn': lambda_arn,
                                    'Input': json.dumps({
                                        'instance_id': instance.instance_id,
                                        'action': 'backup',
                                        'endpoint': api_endpoint if api_endpoint else None
                                    })
                                }
                            ]
                        )
                        logger.info(f"Configured EventBridge target for {instance.instance_id} using Lambda function")
                        
                        # Set needs_status_polling flag based on API endpoint availability
                        if not api_endpoint:
                            instance.needs_status_polling = True
                            db.session.commit()
                            logger.info(f"Set needs_status_polling=True for instance {instance.instance_id} due to missing API endpoint")
                            
                            # Schedule AMI status polling for this instance
                            schedule_ami_status_polling(instance_id=instance.instance_id)
                            logger.info(f"Scheduled AMI status polling for instance {instance.instance_id}")
                        else:
                            instance.needs_status_polling = False
                            db.session.commit()
                            logger.info(f"Set needs_status_polling=False for instance {instance.instance_id} as API endpoint is configured")
                    except Exception as e:
                        logger.error(f"Failed to configure Lambda target for EventBridge rule: {e}")
                        raise ValueError(f"Failed to configure Lambda target: {e}")
                elif api_endpoint:
                    # Use API Gateway as target if it's an ARN
                    if not api_endpoint.startswith('http'):
                        # It's an ARN, use it directly
                        target_id = f"AMIVault-Target-{instance.instance_id}"
                        try:
                            events_client.put_targets(
                                Rule=rule_name,
                                Targets=[
                                    {
                                        'Id': target_id,
                                        'Arn': api_endpoint,
                                        'Input': json.dumps({
                                            'instance_id': instance.instance_id,
                                            'action': 'backup'
                                        })
                                    }
                                ]
                            )
                            logger.info(f"Configured EventBridge target for {instance.instance_id} using API Gateway ARN")
                        except Exception as e:
                            logger.error(f"Failed to configure API Gateway target for EventBridge rule: {e}")
                            raise ValueError(f"Failed to configure API Gateway target: {e}")
                    else:
                        # It's a URL, we need to create an API destination
                        logger.warning(f"API Gateway endpoint is a URL, not an ARN. EventBridge requires an ARN for targets.")
                        logger.warning(f"Please set the BACKUP_LAMBDA_ARN environment variable to use a Lambda function as target.")
                        # We'll continue without a target for now, but log a warning
                
                logger.info(f"Scheduled EventBridge backup job for instance {instance.instance_id}")
            except Exception as e:
                logger.error(f"Failed to schedule EventBridge backup for {instance.instance_id}: {e}")
                raise

    except Exception as e:
        logger.error(f"Failed to schedule backup for instance {instance.instance_id}: {e}")
        raise

# def parse_cron_expression(cron_str):
#     """Parse cron expression into kwargs for APScheduler"""
#     parts = cron_str.strip().split()
#     if len(parts) != 5:
#         raise ValueError("Invalid cron expression")
    
#     return {
#         'minute': parts[0],
#         'hour': parts[1],
#         'day': parts[2],
#         'month': parts[3],
#         'day_of_week': parts[4]
#     }

def deploy_lambda_function(instance):
    """Deploy Lambda function for EventBridge target if it doesn't exist
    
    Args:
        instance: The instance object with AWS credentials
        
    Returns:
        str: ARN of the Lambda function
    """
    try:
        # Create boto3 session with instance credentials
        boto3_session = boto3.Session(
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key,
            region_name=instance.region
        )
        
        # Check if BACKUP_LAMBDA_ARN is already set
        lambda_arn = os.environ.get('BACKUP_LAMBDA_ARN', '')
        if lambda_arn:
            logger.info(f"Using existing Lambda ARN: {lambda_arn}")
            return lambda_arn
            
        # Create Lambda client
        lambda_client = boto3_session.client('lambda')
        
        # Check if the Lambda function already exists
        function_name = 'amivault-backup'
        try:
            response = lambda_client.get_function(FunctionName=function_name)
            lambda_arn = response['Configuration']['FunctionArn']
            logger.info(f"Found existing Lambda function: {lambda_arn}")
            
            # Update the .env file with the Lambda ARN
            update_env_file('BACKUP_LAMBDA_ARN', lambda_arn)
            
            return lambda_arn
        except lambda_client.exceptions.ResourceNotFoundException:
            logger.info(f"Lambda function {function_name} not found, creating it")
        
        # Create IAM role for Lambda function
        iam_client = boto3_session.client('iam')
        role_name = 'AMIVault-Lambda-Role'
        
        # Check if role exists
        try:
            role_response = iam_client.get_role(RoleName=role_name)
            role_arn = role_response['Role']['Arn']
            logger.info(f"Using existing IAM role: {role_arn}")
        except iam_client.exceptions.NoSuchEntityException:
            # Create the role
            logger.info(f"Creating IAM role: {role_name}")
            assume_role_policy = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
            
            role_response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=assume_role_policy,
                Description="Role for AMIVault Lambda function"
            )
            role_arn = role_response['Role']['Arn']
            
            # Attach policies
            policy_document = json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:DescribeInstances",
                            "ec2:CreateImage",
                            "ec2:CreateTags",
                            "ec2:DescribeImages"
                        ],
                        "Resource": "*"
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents"
                        ],
                        "Resource": "arn:aws:logs:*:*:*"
                    }
                ]
            })
            
            policy_name = "AMIVault-Lambda-Policy"
            iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName=policy_name,
                PolicyDocument=policy_document
            )
            
            # Wait for role to propagate
            import time
            time.sleep(60)
        
        # Check if lambda_function.py exists, if not create it
        lambda_code_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lambda_function.py')
        lambda_callback_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lambda_callback.py')
        
        # Create lambda_function.py if it doesn't exist
        if not os.path.exists(lambda_code_path):
            logger.info(f"Creating lambda_function.py file")
            lambda_code = '''
import json
import boto3
import os
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    AWS Lambda function to create AMI backups for EC2 instances
    
    Expected event format:
    {
        "instance_id": "i-1234567890abcdef0",
        "action": "backup",
        "endpoint": "https://your-api-endpoint/api/backup-callback" (optional)
    }
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract parameters from the event
        instance_id = event.get('instance_id')
        action = event.get('action', 'backup')
        endpoint = event.get('endpoint')
        
        if not instance_id:
            logger.error("No instance_id provided in the event")
            return {
                'statusCode': 400,
                'body': json.dumps({'error': 'No instance_id provided'})
            }
        
        # Get the instance region
        ec2_client = boto3.client('ec2')
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response.get('Reservations') or not response['Reservations'][0].get('Instances'):
            logger.error(f"Instance {instance_id} not found")
            return {
                'statusCode': 404,
                'body': json.dumps({'error': f"Instance {instance_id} not found"})
            }
        
        instance = response['Reservations'][0]['Instances'][0]
        region = instance['Placement']['AvailabilityZone'][:-1]  # Remove the AZ letter to get the region
        
        # Get instance name from tags
        instance_name = instance_id
        for tag in instance.get('Tags', []):
            if tag['Key'] == 'Name':
                instance_name = tag['Value']
                break
        
        # Create AMI
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        ami_name = f"AMIVault-{instance_name}-{timestamp}"
        
        ec2_client = boto3.client('ec2', region_name=region)
        ami_response = ec2_client.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            Description=f"Automated backup created by AMIVault Lambda function at {timestamp}",
            NoReboot=True
        )
        
        ami_id = ami_response['ImageId']
        logger.info(f"Created AMI {ami_id} for instance {instance_id}")
        
        # Tag the AMI
        ec2_client.create_tags(
            Resources=[ami_id],
            Tags=[
                {'Key': 'CreatedBy', 'Value': 'AMIVault-Lambda'},
                {'Key': 'InstanceId', 'Value': instance_id},
                {'Key': 'InstanceName', 'Value': instance_name},
                {'Key': 'BackupType', 'Value': 'eventbridge'}
            ]
        )
        
        # Call back to the API endpoint if provided
        if endpoint:
            try:
                import urllib3
                http = urllib3.PoolManager()
                
                callback_data = {
                    'instance_id': instance_id,
                    'ami_id': ami_id,
                    'ami_name': ami_name,
                    'status': 'success',
                    'timestamp': timestamp
                }
                
                response = http.request(
                    'POST',
                    endpoint,
                    body=json.dumps(callback_data).encode('utf-8'),
                    headers={'Content-Type': 'application/json'}
                )
                
                logger.info(f"Callback to {endpoint} returned status {response.status}")
            except Exception as e:
                logger.error(f"Error calling back to endpoint {endpoint}: {str(e)}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': True,
                'ami_id': ami_id,
                'ami_name': ami_name,
                'instance_id': instance_id,
                'instance_name': instance_name
            })
        }
        
    except Exception as e:
        logger.error(f"Error creating AMI backup: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
'''
            with open(lambda_code_path, 'w') as file:
                file.write(lambda_code)
            logger.info(f"Created lambda_function.py file")
        
        # Create lambda_callback.py if it doesn't exist
        if not os.path.exists(lambda_callback_path):
            logger.info(f"Creating lambda_callback.py file")
            callback_code = '''
from flask import Blueprint, request, jsonify
from models import db, Backup, Instance
from datetime import datetime, UTC
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create a Blueprint for the Lambda callback routes
lambda_callback = Blueprint('lambda_callback', __name__)

@lambda_callback.route('/api/backup-callback', methods=['POST'])
def backup_callback():
    """
    Endpoint to receive callbacks from the Lambda function after AMI creation
    
    Expected JSON payload:
    {
        "instance_id": "i-1234567890abcdef0",
        "ami_id": "ami-1234567890abcdef0",
        "ami_name": "AMIVault-instance-name-20230101-123456",
        "status": "success",
        "timestamp": "20230101-123456"
    }
    """
    try:
        # Get the JSON data from the request
        data = request.get_json()
        
        if not data:
            logger.error("No JSON data received in callback")
            return jsonify({'error': 'No data received'}), 400
        
        # Extract data from the payload
        instance_id = data.get('instance_id')
        ami_id = data.get('ami_id')
        ami_name = data.get('ami_name')
        status = data.get('status', 'unknown')
        timestamp_str = data.get('timestamp')
        
        # Validate required fields
        if not all([instance_id, ami_id, ami_name]):
            logger.error(f"Missing required fields in callback data: {data}")
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Get the instance from the database
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            logger.warning(f"Instance {instance_id} not found in database for callback")
            return jsonify({'error': 'Instance not found'}), 404
        
        # Parse timestamp or use current time
        try:
            if timestamp_str:
                timestamp = datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
            else:
                timestamp = datetime.now(UTC)
        except ValueError:
            logger.warning(f"Invalid timestamp format: {timestamp_str}, using current time")
            timestamp = datetime.now(UTC)
        
        # Create or update backup record
        existing_backup = Backup.query.filter_by(instance_id=instance_id, ami_id=ami_id).first()
        
        if existing_backup:
            # Update existing backup
            existing_backup.status = 'Success' if status == 'success' else 'Failed'
            existing_backup.ami_name = ami_name
            existing_backup.timestamp = timestamp
            db.session.commit()
            logger.info(f"Updated existing backup record for AMI {ami_id}")
        else:
            # Create new backup record
            backup = Backup(
                instance_id=instance_id,
                ami_id=ami_id,
                ami_name=ami_name,
                status='Success' if status == 'success' else 'Failed',
                timestamp=timestamp,
                retention_days=instance.retention_days
            )
            db.session.add(backup)
            db.session.commit()
            logger.info(f"Created new backup record for AMI {ami_id}")
        
        return jsonify({
            'success': True,
            'message': f"Backup record {'updated' if existing_backup else 'created'} for AMI {ami_id}"
        })
        
    except Exception as e:
        logger.error(f"Error processing Lambda callback: {str(e)}")
        return jsonify({'error': str(e)}), 500
'''
            with open(lambda_callback_path, 'w') as file:
                file.write(callback_code)
            logger.info(f"Created lambda_callback.py file")
            
            # Check if the blueprint is already registered in app.py
            # This is a simplified check, in a real implementation you might want to parse the file
            try:
                with open(__file__, 'r') as app_file:
                    app_content = app_file.read()
                    if 'from lambda_callback import lambda_callback' not in app_content:
                        logger.info("Lambda callback import not found in app.py")
                        logger.info("Add 'from lambda_callback import lambda_callback' to your imports")
                    
                    if 'app.register_blueprint(lambda_callback)' not in app_content:
                        logger.info("Lambda callback blueprint not registered in app.py")
                        logger.info("Add 'app.register_blueprint(lambda_callback)' after app initialization")
                    
                    # Both import and registration are present
                    if 'from lambda_callback import lambda_callback' in app_content and 'app.register_blueprint(lambda_callback)' in app_content:
                        logger.info("Lambda callback blueprint is already properly registered in app.py")
            except Exception as e:
                logger.error(f"Error checking app.py for blueprint registration: {e}")
        
        # Read the Lambda function code
        with open(lambda_code_path, 'r') as file:
            lambda_code = file.read()
        
        # Create a zip file in memory
        import io
        import zipfile
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('lambda_function.py', lambda_code)
        
        zip_buffer.seek(0)
        zip_bytes = zip_buffer.read()
        
        # Create the Lambda function
        response = lambda_client.create_function(
            FunctionName=function_name,
            Runtime='python3.9',
            Role=role_arn,
            Handler='lambda_function.lambda_handler',
            Code={
                'ZipFile': zip_bytes
            },
            Description='AMIVault backup function for creating EC2 AMIs',
            Timeout=300,
            MemorySize=256,
            Publish=True
        )
        
        lambda_arn = response['FunctionArn']
        logger.info(f"Created Lambda function: {lambda_arn}")
        
        # Update the .env file with the Lambda ARN
        update_env_file('BACKUP_LAMBDA_ARN', lambda_arn)
        
        # Add permission for EventBridge to invoke the Lambda function
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId='AllowEventBridgeInvoke',
            Action='lambda:InvokeFunction',
            Principal='events.amazonaws.com'
        )
        
        return lambda_arn
    except Exception as e:
        logger.error(f"Failed to deploy Lambda function: {e}")
        raise

def update_env_file(key, value):
    """Update a key-value pair in the .env file
    
    Args:
        key: The environment variable key
        value: The value to set
    """
    try:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        
        # Read the current .env file
        with open(env_path, 'r') as file:
            lines = file.readlines()
        
        # Check if the key already exists
        key_exists = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                key_exists = True
                break
        
        # If the key doesn't exist, add it
        if not key_exists:
            lines.append(f"\n{key}={value}\n")
        
        # Write the updated content back to the .env file
        with open(env_path, 'w') as file:
            file.writelines(lines)
        
        # Update the environment variable in the current process
        os.environ[key] = value
        
        logger.info(f"Updated .env file with {key}={value}")
    except Exception as e:
        logger.error(f"Failed to update .env file: {e}")

def reschedule_instance_backup(instance, old_scheduler_type=None):
    """Reschedule backup job for an instance
    
    Args:
        instance: The instance object
        old_scheduler_type: The previous scheduler type if it was changed
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # If scheduler type changed, we need to remove the old schedule first
        if old_scheduler_type and old_scheduler_type != instance.scheduler_type:
            logger.info(f"Scheduler type changed from {old_scheduler_type} to {instance.scheduler_type} for {instance.instance_id}")
            
            # If changing to EventBridge, ensure Lambda function is deployed
            if instance.scheduler_type == 'eventbridge':
                try:
                    # Check if Lambda ARN is already set
                    lambda_arn = os.environ.get('BACKUP_LAMBDA_ARN', '')
                    api_endpoint = os.environ.get('API_GATEWAY_ENDPOINT', '')
                    
                    # If no Lambda ARN or API endpoint is set, deploy Lambda function
                    if not lambda_arn and not api_endpoint:
                        logger.info(f"Deploying Lambda function for EventBridge scheduler for {instance.instance_id}")
                        try:
                            lambda_arn = deploy_lambda_function(instance)
                            logger.info(f"Successfully deployed Lambda function with ARN: {lambda_arn}")
                        except Exception as lambda_error:
                            logger.error(f"Failed to deploy Lambda function for {instance.instance_id}: {lambda_error}")
                            # Continue with scheduling, it will use fallback options
                except Exception as e:
                    logger.error(f"Error checking/deploying Lambda function for {instance.instance_id}: {e}")
            
            try:
                remove_instance_backup_schedule(instance.instance_id, old_scheduler_type)
                logger.info(f"Removed {old_scheduler_type} backup schedule for instance {instance.instance_id}")
            except Exception as e:
                # If the error is ResourceNotFoundException, we can ignore it and continue
                if 'ResourceNotFoundException' in str(e):
                    logger.warning(f"Rule not found when removing {old_scheduler_type} schedule for {instance.instance_id}. Continuing with new schedule.")
                else:
                    # For other errors, log but continue with scheduling
                    logger.error(f"Error removing {old_scheduler_type} schedule for {instance.instance_id}: {e}")
        
        # Schedule with the new scheduler type
        try:
            schedule_instance_backup(instance)
            return True
        except ValueError as e:
            # Handle specific validation errors
            logger.error(f"Validation error when scheduling backup for {instance.instance_id}: {e}")
            # If this was a scheduler type change and it failed, try to revert to the old scheduler type
            if old_scheduler_type and old_scheduler_type != instance.scheduler_type:
                logger.warning(f"Attempting to revert to previous scheduler type {old_scheduler_type} for {instance.instance_id}")
                instance.scheduler_type = old_scheduler_type
                db.session.commit()
                try:
                    schedule_instance_backup(instance)
                    logger.info(f"Successfully reverted to {old_scheduler_type} scheduler for {instance.instance_id}")
                    return False
                except Exception as revert_error:
                    logger.error(f"Failed to revert to previous scheduler type for {instance.instance_id}: {revert_error}")
            raise
    except Exception as e:
        logger.error(f"Error rescheduling backup for {instance.instance_id}: {e}")
        logger.warning(f"Could not reschedule backup for {instance.instance_id}: {e}")
        raise

def remove_lambda_function():
    """Remove Lambda function used for EventBridge targets and update .env file
    
    This function removes the Lambda function created for EventBridge targets
    and updates the .env file to remove the BACKUP_LAMBDA_ARN entry.
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Get the Lambda ARN from environment variables
        lambda_arn = os.environ.get('BACKUP_LAMBDA_ARN', '')
        if not lambda_arn:
            logger.info("No Lambda ARN found in environment variables")
            return True
        
        # Parse the Lambda ARN to get region and function name
        # Format: arn:aws:lambda:region:account-id:function:function-name
        arn_parts = lambda_arn.split(':')
        if len(arn_parts) < 7 or arn_parts[2] != 'lambda':
            logger.warning(f"Invalid Lambda ARN format: {lambda_arn}")
            return False
        
        region = arn_parts[3]
        function_name = arn_parts[6]
        
        # Create a boto3 session with default credentials
        # This assumes the application has AWS credentials configured
        boto3_session = boto3.Session(region_name=region)
        
        # Create Lambda client
        lambda_client = boto3_session.client('lambda')
        
        # Delete the Lambda function
        try:
            lambda_client.delete_function(FunctionName=function_name)
            logger.info(f"Successfully deleted Lambda function: {function_name}")
            
            # Remove the BACKUP_LAMBDA_ARN from .env file
            remove_env_variable('BACKUP_LAMBDA_ARN')
            
            return True
        except lambda_client.exceptions.ResourceNotFoundException:
            logger.warning(f"Lambda function {function_name} not found")
            # Still remove from .env file
            remove_env_variable('BACKUP_LAMBDA_ARN')
            return True
        except Exception as e:
            logger.error(f"Error deleting Lambda function {function_name}: {e}")
            return False
    except Exception as e:
        logger.error(f"Error removing Lambda function: {e}")
        return False

def remove_env_variable(key):
    """Remove a key-value pair from the .env file
    
    Args:
        key: The environment variable key to remove
    """
    try:
        env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        
        # Read the current .env file
        with open(env_path, 'r') as file:
            lines = file.readlines()
        
        # Filter out the line with the specified key
        new_lines = [line for line in lines if not line.strip().startswith(f"{key}=")]
        
        # Write the updated content back to the .env file
        with open(env_path, 'w') as file:
            file.writelines(new_lines)
        
        # Remove the environment variable from the current process
        if key in os.environ:
            del os.environ[key]
        
        logger.info(f"Removed {key} from .env file")
    except Exception as e:
        logger.error(f"Failed to remove {key} from .env file: {e}")

def remove_instance_backup_schedule(instance_id, scheduler_type='python'):
    """Remove backup schedule for an instance based on scheduler type"""
    try:
        if scheduler_type == 'python':
            # Remove from APScheduler
            job_id = f'backup_{instance_id}'  # Fixed job_id format to match schedule_instance_backup
            if scheduler.get_job(job_id):
                scheduler.remove_job(job_id)
                logger.info(f"Removed Python backup schedule for instance {instance_id}")
            return True
        elif scheduler_type == 'eventbridge':
            # Remove from EventBridge
            # First, get the instance to access its AWS credentials
            with app.app_context():
                instance = Instance.query.filter_by(instance_id=instance_id).first()
                if not instance:
                    logger.warning(f"Instance {instance_id} not found when removing EventBridge schedule")
                    return False
                
                # Create boto3 session with instance credentials
                boto3_session = boto3.Session(
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key,
                    region_name=instance.region
                )
                
                # Create EventBridge client
                events_client = boto3_session.client('events')
                
                # Remove targets first
                rule_name = f"AMIVault-Backup-{instance_id}"  # Fixed to match the rule_name in schedule_instance_backup
                target_id = f"AMIVault-Target-{instance_id}"  # Matches the target_id in schedule_instance_backup
                
                try:
                    # Try to remove targets first (required before deleting the rule)
                    try:
                        events_client.remove_targets(
                            Rule=rule_name,
                            Ids=[target_id]
                        )
                    except Exception as e:
                        # If the rule doesn't exist, we can skip removing targets
                        if 'ResourceNotFoundException' in str(e):
                            logger.warning(f"Rule {rule_name} not found when removing targets for {instance_id}")
                        else:
                            # For other errors, log and re-raise
                            logger.error(f"Error removing EventBridge targets for {instance_id}: {e}")
                            raise
                    
                    # Then try to delete the rule
                    try:
                        events_client.delete_rule(
                            Name=rule_name
                        )
                    except Exception as e:
                        # If the rule doesn't exist, that's fine
                        if 'ResourceNotFoundException' in str(e):
                            logger.warning(f"Rule {rule_name} not found when deleting for {instance_id}")
                        else:
                            # For other errors, log and re-raise
                            logger.error(f"Error deleting EventBridge rule for {instance_id}: {e}")
                            raise
                    
                    # Check if this is the last instance using EventBridge
                    # If so, remove the Lambda function and update .env file
                    with app.app_context():
                        eventbridge_instances_count = Instance.query.filter_by(scheduler_type='eventbridge').count()
                        if eventbridge_instances_count <= 1:  # This instance is being removed or changed
                            logger.info("This is the last instance using EventBridge, removing Lambda function")
                            remove_lambda_function()
                    
                    logger.info(f"Removed EventBridge backup schedule for instance {instance_id}")
                    return True
                except Exception as e:
                    logger.error(f"Error removing EventBridge schedule for {instance_id}: {e}")
                    raise
        else:
            logger.warning(f"Unknown scheduler type '{scheduler_type}' for instance {instance_id}")
            return False
    except Exception as e:
        logger.error(f"Error removing backup schedule for instance {instance_id}: {e}")
        raise

############################################################ Helper Functions ############################################################

def get_effective_setting(instance_value, global_value):
    """Get effective setting value, preferring instance-specific over global"""
    return instance_value if instance_value not in [None, '', 0] else global_value


def validate_cron_expression(cron_str, raise_exceptions=False):
    """Validate cron expression format for both standard cron and AWS EventBridge compatibility
    
    This function validates a standard 5-part cron expression and checks for AWS EventBridge
    compatibility requirements. AWS EventBridge has specific rules for cron expressions,
    particularly regarding the day-of-month and day-of-week fields.
    
    Validation rules:
    1. Must have exactly 5 parts (minutes hours day-of-month month day-of-week)
    2. Each part must be within valid ranges:
       - Minutes: 0-59
       - Hours: 0-23
       - Day-of-month: 1-31 or * or ?
       - Month: 1-12 or * or named months (JAN-DEC)
       - Day-of-week: 0-7 or * or ? or named days (SUN-SAT), where 0 and 7 both represent Sunday
    3. AWS EventBridge specific rules:
       - If both day-of-month and day-of-week are specified (not * or ?), one must be set to ?
       - Both day-of-month and day-of-week cannot be ? at the same time
    
    Examples of valid expressions:
    - "0 2 * * *" - Daily at 2 AM
    - "0 12 ? * MON-FRI" - Weekdays at noon
    - "0 0 1 * ?" - 1st day of month at midnight
    
    Examples of invalid expressions:
    - "* * * *" - Too few parts
    - "* * ? * ?" - Both day-of-month and day-of-week are ?
    - "* * 1 * 1" - Both day-of-month and day-of-week are specified without ?
    
    Args:
        cron_str: A string containing a standard 5-part cron expression
        raise_exceptions: If True, raises exceptions with detailed error messages instead of returning False
        
    Returns:
        Boolean indicating if the cron expression is valid
        
    Raises:
        ValueError: If raise_exceptions is True and validation fails, with a specific error message
    """
    if not cron_str or not isinstance(cron_str, str):
        if raise_exceptions:
            raise ValueError("Cron expression must be a non-empty string")
        return False
    
    # First check if it has 5 parts (standard cron format)
    parts = cron_str.strip().split()
    if len(parts) != 5:
        if raise_exceptions:
            raise ValueError(f"Cron expression must have exactly 5 parts, got {len(parts)}: {cron_str}")
        return False
    
    # Basic validation for cron expression format
    # Minutes: 0-59 or */n or n-m or n,m,...
    # Hours: 0-23 or */n or n-m or n,m,...
    # Day of month: 1-31 or * or ? or */n or n-m or n,m,...
    # Month: 1-12 or * or */n or n-m or n,m,...
    # Day of week: 0-7 or * or ? or */n or n-m or n,m,... (0 or 7=Sunday)
    try:
        minutes, hours, day_of_month, month, day_of_week = parts
        
        # Check minutes (0-59)
        if minutes != '*' and not all(0 <= int(m) <= 59 for m in minutes.replace('*/','').replace('-',',').split(',') if m.isdigit()):
            if raise_exceptions:
                raise ValueError(f"Invalid minutes field '{minutes}': must be between 0-59, *, or contain valid ranges/lists/steps")
            return False
            
        # Check hours (0-23)
        if hours != '*' and not all(0 <= int(h) <= 23 for h in hours.replace('*/','').replace('-',',').split(',') if h.isdigit()):
            if raise_exceptions:
                raise ValueError(f"Invalid hours field '{hours}': must be between 0-23, *, or contain valid ranges/lists/steps")
            return False
            
        # Check day of month (1-31 or ?)
        if day_of_month != '*' and day_of_month != '?' and not all(1 <= int(d) <= 31 for d in day_of_month.replace('*/','').replace('-',',').split(',') if d.isdigit()):
            if raise_exceptions:
                raise ValueError(f"Invalid day-of-month field '{day_of_month}': must be between 1-31, *, ?, or contain valid ranges/lists/steps")
            return False
            
        # Check month (1-12)
        if month != '*' and not all(1 <= int(m) <= 12 for m in month.replace('*/','').replace('-',',').split(',') if m.isdigit()):
            if raise_exceptions:
                raise ValueError(f"Invalid month field '{month}': must be between 1-12, *, or contain valid ranges/lists/steps")
            return False
            
        # Check day of week (0-7, where both 0 and 7 represent Sunday, or ?)
        if day_of_week != '*' and day_of_week != '?' and not all(0 <= int(d) <= 7 for d in day_of_week.replace('*/','').replace('-',',').split(',') if d.isdigit()):
            if raise_exceptions:
                raise ValueError(f"Invalid day-of-week field '{day_of_week}': must be between 0-7, *, ?, or contain valid ranges/lists/steps")
            return False
        
        # AWS EventBridge specific validation for day-of-month and day-of-week fields
        # Rule 1: If both fields are specified (not * or ?), one must be set to ?
        if (day_of_month != '*' and day_of_month != '?' and 
            day_of_week != '*' and day_of_week != '?'):
            if raise_exceptions:
                raise ValueError(f"AWS EventBridge requires that if both day-of-month '{day_of_month}' and day-of-week '{day_of_week}' are specified, one must be set to '?'")
            return False
            
        # Rule 2: Both fields cannot be set to ? at the same time
        if day_of_month == '?' and day_of_week == '?':
            if raise_exceptions:
                raise ValueError("AWS EventBridge does not allow both day-of-month and day-of-week to be '?' at the same time")
            return False
            
        return True
    except (ValueError, IndexError) as e:
        if raise_exceptions:
            if isinstance(e, ValueError) and str(e):
                # Re-raise the specific ValueError we created
                raise
            # Otherwise, it's an unexpected error
            raise ValueError(f"Invalid cron expression format: {cron_str}")
        return False


def convert_to_eventbridge_format(frequency):
    """Convert standard cron or interval expressions to AWS EventBridge format
    
    AWS EventBridge has specific requirements for cron expressions:
    1. Format: cron(minutes hours day-of-month month day-of-week year)
       - The year field is required (usually set to *)
    2. Day-of-week uses 1-7 (1=Monday, 7=Sunday) instead of 0-6
    3. Day-of-month and day-of-week fields have special rules:
       - If one field is specified (not * or ?), the other must be set to ?
       - Both fields cannot be ? at the same time
       - If both fields are *, one should be set to ? (we set day-of-week to ?)
    
    Examples:
        - "0 2 * * *" -> "cron(0 2 * * ? *)" (Daily at 2 AM)
        - "0 12 ? * MON-FRI" -> "cron(0 12 ? * MON-FRI *)" (Weekdays at noon)
        - "0 0 1 * ?" -> "cron(0 0 1 * ? *)" (1st day of month at midnight)
        - "@12" -> "rate(12 hours)" (Every 12 hours)
    
    Args:
        frequency: A string containing either a standard cron expression or an interval (@hours)
        
    Returns:
        A string in AWS EventBridge format (either cron() or rate())
        
    Raises:
        ValueError: If the frequency format is invalid, with a detailed error message
    """
    # Handle interval-based schedules (e.g., @12)
    if frequency.startswith('@'):
        try:
            interval_hours = int(frequency[1:])
            # Use rate expression for intervals
            return f"rate({interval_hours} hours)"
        except ValueError:
            raise ValueError(f"Invalid interval value: {frequency}. Must be a number after @.")
    else:
        # Handle cron expressions
        cron_parts = frequency.split()
        if len(cron_parts) == 5:  # Standard cron format
            # AWS EventBridge requires cron expressions in the format: cron(minutes hours day-of-month month day-of-week year)
            # The year field is required for AWS EventBridge
            minutes, hours, day_of_month, month, day_of_week = cron_parts
            
            # AWS EventBridge uses 1-7 for day-of-week (1=Monday, 7=Sunday)
            # Standard cron uses 0-6 (0=Sunday, 6=Saturday)
            # Convert if needed - handle all cases where 0 might appear
            if day_of_week.isdigit() and int(day_of_week) == 0:
                day_of_week = '7'  # Convert Sunday from 0 to 7
            elif '0' in day_of_week:
                # Handle comma-separated list that includes 0
                if ',' in day_of_week:
                    days = day_of_week.split(',')
                    days = ['7' if d == '0' else d for d in days]
                    day_of_week = ','.join(days)
                # Handle range that includes 0
                elif '-' in day_of_week:
                    if day_of_week.startswith('0-'):
                        day_of_week = '7' + day_of_week[1:]
                    elif day_of_week.endswith('-0'):
                        day_of_week = day_of_week[:-1] + '7'
                    elif '-0-' in day_of_week:
                        day_of_week = day_of_week.replace('-0-', '-7-')
            
            # In AWS EventBridge, you can't specify both day-of-month and day-of-week with specific values
            # If both are specified with values other than *, one must be set to ?
            # See: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cron-expressions.html
            
            # Handle AWS EventBridge specific requirements for day-of-month and day-of-week fields
            if day_of_month != '*' and day_of_week != '*' and day_of_week != '?' and day_of_month != '?':
                # If both are specified with non-wildcard values, set day-of-week to ?
                day_of_week = '?'
            elif day_of_week == '*' and day_of_month != '?':
                # If day-of-week is * and day-of-month is not ?, set day-of-week to ? to ensure compatibility
                # AWS requires either day-of-month or day-of-week to be '?' if the other is specified or '*'
                day_of_week = '?'
            elif day_of_month == '*' and day_of_week == '*':
                # If both are *, set day-of-week to ? as per AWS EventBridge requirements
                day_of_week = '?'
            
            # AWS EventBridge cron format is: cron(minutes hours day-of-month month day-of-week year)
            # The year field is required for AWS EventBridge
            aws_cron = f"cron({minutes} {hours} {day_of_month} {month} {day_of_week} *)"
            
            # Validate the final cron expression
            if not aws_cron.startswith("cron(") or not aws_cron.endswith(")"):
                raise ValueError(f"Invalid EventBridge cron expression format: {aws_cron}")
            
            # Additional validation for AWS EventBridge cron expressions with detailed error messages
            try:
                validate_cron_expression(f"{minutes} {hours} {day_of_month} {month} {day_of_week}", raise_exceptions=True)
            except ValueError as e:
                raise ValueError(f"Invalid AWS EventBridge cron expression: {str(e)}. Generated expression: {aws_cron}")
                
            return aws_cron
        else:
            raise ValueError(f"Invalid cron expression: {frequency}. Must have 5 parts.")



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
    try:
        # Attempt to validate the cron expression with detailed error messages
        validate_cron_expression(frequency, raise_exceptions=True)
        return True, f"Cron: {frequency}"
    except ValueError as e:
        # Return the specific error message for better user feedback
        return False, f"Invalid cron expression: {str(e)}"
    
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
    # total_instances = Instance.query.filter_by(is_active=True).count()
    # recent_backups = Backup.query.order_by(Backup.created_at.desc()).limit(10).all()
    # # recent_backups = Backup.query.order_by(Backup.timestamp.desc()).limit(10).all()
    # failed_backups = Backup.query.filter_by(status='Failed').count()
    # successful_backups = Backup.query.filter_by(status='Success').count()
    backups = Backup.query.order_by(Backup.timestamp.desc()).all()
    last_backup = backups[0] if backups else None
    regions = db.session.query(Backup.region).distinct().all()
    ami_ids = db.session.query(Backup.ami_id).distinct().all()

    # Get backup settings
    backup_settings = BackupSettings.query.first()
    
    # stats = {
    #     'total_instances': total_instances,
    #     'successful_backups': successful_backups,
    #     'failed_backups': failed_backups,
    #     'recent_backups': recent_backups
    # }
    
    # return render_template('dashboard.html', 
    #                     #  user=user, 
    #                     #  stats=stats,
    #                     user=user,
    #                     backups=backups,
    #                     last_backup=last_backup,
    #                     region=region,
    #                     ami_id=ami_id,
    #                     backup_settings=backup_settings)
    return render_template('dashboard.html', 
                       user=user,
                       backups=backups,
                       last_backup=last_backup,
                       regions=regions,
                       ami_ids=ami_ids,
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
        
        # First check if user exists without active filter
        user = User.query.filter_by(username=username).first()
        
        # Check if user exists but is inactive
        if user and not user.is_active:
            error_msg = "Your account is inactive. Please contact the administrator."
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': error_msg})
            flash(error_msg, "warning")
            return render_template('login.html')
        
        # Now check password for active user
        if user and user.is_active and user.check_password(password):
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
    
    user = User.query.filter_by(username=pending_user).first()
    
    # Check if user exists but is inactive
    if user and not user.is_active:
        session.pop('pending_2fa_user', None)
        return jsonify({'success': False, 'error': 'Your account is inactive. Please contact the administrator.'})
    
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
        issuer_name="AMIVault"
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


# @app.route('/backups')
# def backups():
#     """List all backup records with filtering options"""
#     if 'username' not in session:
#         return redirect(url_for('login'))
    
#     # Get filter parameters
#     status_filter = request.args.get('status')
#     instance_filter = request.args.get('instance')
#     page = request.args.get('page', 1, type=int)
#     per_page = 20
    
#     # Build query
#     query = Backup.query
    
#     if status_filter:
#         query = query.filter(Backup.status == status_filter)
    
#     if instance_filter:
#         query = query.filter(Backup.instance_id == instance_filter)
    
#     # Paginate results
#     backups = query.order_by(Backup.timestamp.desc()).paginate(
#         page=page, per_page=per_page, error_out=False
#     )
    
#     # Get instances for filter dropdown
#     instances = Instance.query.filter_by(is_active=True).all()
    
#     return render_template('backups.html', 
#                          backups=backups, 
#                          instances=instances,
#                          current_status=status_filter,
#                          current_instance=instance_filter)


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
        # credential = AWSCredential.query.get(credential_id)
        credential = db.session.get(AWSCredential, credential_id)
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

# @app.route('/delete-aws-credential/<int:credential_id>', methods=['POST'])
# def delete_aws_credential_ajax(credential_id):
#     """Delete an AWS credential set via AJAX"""
#     if 'username' not in session:
#         return jsonify({'success': False, 'error': 'Not authenticated'})
    
#     try:
#         # credential = AWSCredential.query.get(credential_id)
#         credential = db.session.get(AWSCredential, credential_id)
#         if not credential:
#             return jsonify({'success': False, 'error': 'AWS credential not found'})
        
#         # Check if credential is in use
#         instances = Instance.query.filter_by(access_key=credential.access_key, secret_key=credential.secret_key).all()
#         if instances:
#             return jsonify({'success': False, 'error': 'Cannot delete credential that is in use by instances'})
        
#         db.session.delete(credential)
#         db.session.commit()
#         return jsonify({'success': True})
        
#     except Exception as e:
#         logger.error(f"Error deleting AWS credential: {e}")
#         return jsonify({'success': False, 'error': str(e)})

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
            # 'last_backup': Backup.query.filter_by(instance_id=instance.instance_id).order_by(Backup.timestamp.desc()).first()
            'last_backup': Backup.query.filter_by(instance_id=instance.instance_id).order_by(Backup.created_at.desc()).first()            
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
            aws_credential_id = request.form.get('aws_credential_id', '').strip()
            
            # If using saved credentials, get them from the database
            if aws_credential_id and aws_credential_id != 'new':
                credential = db.session.get(AWSCredential, aws_credential_id)
                if not credential:
                    flash("Selected AWS credential not found", "danger")
                    return render_template('aws_instances.html')
                access_key = credential.access_key
                secret_key = credential.secret_key
                region = credential.region
            else:
                # Get credentials from form for new credentials
                access_key = request.form.get('access_key', '').strip()
                secret_key = request.form.get('secret_key', '').strip()
                region = request.form.get('region', '').strip()
                custom_region = request.form.get('custom_region', '').strip()
                
                # Handle custom region
                if region == 'custom':
                    region = custom_region
            
            backup_frequency = request.form.get('backup_frequency', '').strip()
            custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
            retention_days = request.form.get('retention_days', 7, type=int)
            
            # Validation
            if not instance_id:
                flash("Instance ID is required", "danger")
                return render_template('aws_instances.html')
            
            if not aws_credential_id or aws_credential_id == 'new':
                if not all([access_key, secret_key, region]):
                    flash("All credential fields must be filled when not using saved credentials", "danger")
                    return render_template('aws_instances.html')
            
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
                retention_days=retention_days,
                scheduler_type=request.form.get('scheduler_type', 'python')
            )
            db.session.add(inst)
            db.session.commit()
            
            username = session['username'] if 'username' in session else 'unknown'
            logger.info(f"Instance {instance_id} added successfully by {username}")
            flash(f"Instance '{instance_name}' added successfully!", "success")
            
            # Schedule backup for this instance if scheduler is available
            try:
                schedule_instance_backup(inst)
                flash("Backup schedule created", "success")
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
        scheduler_type = request.form.get('scheduler_type', 'python')
        
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
        old_scheduler_type = instance.scheduler_type
        instance.instance_name = instance_name
        instance.backup_frequency = backup_frequency
        instance.retention_days = retention_days
        instance.scheduler_type = scheduler_type
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
        
        # Reschedule backup if frequency or scheduler type changed
        if old_frequency != backup_frequency or old_scheduler_type != scheduler_type:
            try:
                reschedule_instance_backup(instance, old_scheduler_type)
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
        
        # Check if this is a confirmation after the backup warning
        confirm_delete = request.form.get('confirm_delete') == 'true'
        
        # If there are backups and this is not a confirmation, return JSON response
        if backup_count > 0 and not confirm_delete and request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'has_backups': True,
                'backup_count': backup_count,
                'instance_id': instance_id,
                'instance_name': instance_name
            })
        
        # If there are backups, use bulk_delete_amis to properly clean up AWS resources
        if backup_count > 0:
            try:
                # Call bulk_delete_amis internally to handle AWS resource deletion
                logger.info(f"Deleting AWS resources for instance {instance_id} using bulk_delete_amis")
                
                # Create EC2 client for AWS operations
                ec2_client = boto3.client(
                    'ec2',
                    region_name=instance.region,
                    aws_access_key_id=instance.access_key,
                    aws_secret_access_key=instance.secret_key
                )
                
                # Get backups with AMI IDs
                backups = Backup.query.filter_by(instance_id=instance_id).filter(
                    Backup.ami_id.isnot(None)
                ).all()
                
                deleted_amis = []
                aws_errors = []
                
                for backup in backups:
                    try:
                        # Get AMI details before deletion
                        ami_response = ec2_client.describe_images(ImageIds=[backup.ami_id])
                        if ami_response['Images']:
                            image = ami_response['Images'][0]
                            
                            # Deregister AMI
                            ec2_client.deregister_image(ImageId=backup.ami_id)
                            deleted_amis.append(backup.ami_id)
                            logger.info(f"Deleted AMI {backup.ami_id} for instance {instance_id}")
                            
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
                                            aws_errors.append(f"Error deleting snapshot {ebs['SnapshotId']}: {str(snap_e)}")

                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'InvalidAMIID.NotFound':
                            # AMI already deleted, just remove from database
                            deleted_amis.append(backup.ami_id)
                        else:
                            aws_errors.append(f"Error deleting AMI {backup.ami_id}: {str(e)}")
                    except Exception as e:
                        aws_errors.append(f"Error deleting AMI {backup.ami_id}: {str(e)}")
                
                if aws_errors:
                    logger.warning(f"Encountered {len(aws_errors)} errors while deleting AWS resources for instance {instance_id}: {aws_errors}")
            except Exception as e:
                logger.error(f"Error deleting AWS resources for instance {instance_id}: {e}")
        
        # Delete associated backups from database (cascade should handle this, but being explicit)
        Backup.query.filter_by(instance_id=instance_id).delete()
        
        # Remove scheduled backup job
        try:
            remove_instance_backup_schedule(instance_id, instance.scheduler_type)
        except Exception as e:
            logger.warning(f"Could not remove backup schedule for {instance_id}: {e}")
        
        # Delete instance
        db.session.delete(instance)
        db.session.commit()
        
        logger.info(f"Instance {instance_id} deleted by {session['username']} (had {backup_count} backups)")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'message': f"Instance '{instance_name}' and {backup_count} associated backup records deleted successfully!"
            })
        else:
            flash(f"Instance '{instance_name}' and {backup_count} associated backup records deleted successfully!", "success")
        
    except Exception as e:
        logger.error(f"Error deleting instance {instance_id}: {e}")
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': False,
                'error': "An error occurred while deleting the instance"
            }), 500
        else:
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

# def schedule_instance_backup(instance):
#     """Schedule backup job for a specific instance"""
#     try:
#         # This would integrate with your scheduler (APScheduler, Celery, etc.)
#         # Implementation depends on your scheduling mechanism
#         logger.info(f"Scheduling backup for instance {instance.instance_id} with frequency {instance.backup_frequency}")
#         # Add actual scheduling logic here
#         pass
#     except Exception as e:
#         logger.error(f"Error scheduling backup for {instance.instance_id}: {e}")
#         raise


# This function has been moved and updated with additional parameters
# See the implementation at line ~664 that includes scheduler_type parameter


# This function has been moved and updated with additional parameters
# See the implementation at line ~664 that includes old_scheduler_type parameter

# Add these routes to your existing Flask application

############################################################ Bulk Actions ############################################################

# Removed duplicate bulk_export_amis endpoint - using the implementation at line ~3088 instead


# Removed duplicate bulk_tag_amis endpoint - using the implementation at line ~3088 instead


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
            return redirect(url_for('aws_instances'))
        
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
            return redirect(url_for('aws_instances'))
        
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
            return redirect(url_for('aws_instances'))
        
        instance_info = response['Reservations'][0]['Instances'][0]
        instance_name = inst.instance_name  # Use stored name as fallback
        
        # Try to get name from AWS tags
        for tag in instance_info.get('Tags', []):
            if tag['Key'] == 'Name' and tag.get('Value'):
                instance_name = tag['Value']
                break
        
        if not instance_name:
            instance_name = f"Instance-{instance_id}"
        
        # Create AMI with timestamp - using UTC consistently
        timestamp_str = datetime.now(UTC).strftime("%Y_%m_%d_%I_%M_%p")
        ami_name = f"{instance_name}_{timestamp_str}_manual"
        
        # Create pending backup record first
        backup = Backup(
            instance_id=instance_id,
            instance_name=instance_name,
            ami_name=ami_name,
            timestamp=datetime.now(UTC),
            status='Pending',
            region=inst.region,
            retention_days=retention_days
            # Removed backup_type field as it doesn't exist in the model
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
        backup.ami_id = ami_id  # Use backup.ami_id instead of Backup.snapshot_id
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
    
    return redirect(url_for('aws_instances'))


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
            ist_zone = pytz.timezone('UTC')
            timestamp_str = datetime.now(ist_zone).strftime("%Y_%m_%d_%I_%M_%p")
            ami_name = f"{instance_name}_{timestamp_str}_scheduled"
            
            start_time = datetime.now(UTC)
            
            # Create backup record
            backup = Backup(
                # instance_id=instance_id,
                # instance_name=instance_name,
                # ami_name=ami_name,
                # timestamp=start_time,
                # status='Pending',
                region=inst.region,
                # retention_days=retention_days,
                # backup_type='scheduled'
                instance_id=instance_id,
                ami_name=ami_name,
                timestamp=start_time,
                status='Pending',
                retention_days=retention_days
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
            # db.session.refresh(backup)
            # backup.ami_id = ami_id
            # db.session.commit()
            # logger.info(f"Attempting to update AMI ID to: {ami_id}")
            db.session.refresh(backup)
            backup.ami_id = ami_id
            db.session.commit()
            # logger.info(f"Successfully updated AMI ID to: {backup.ami_id}")

            # Tag the AMI
            ec2_client.create_tags(
                Resources=[ami_id],
                Tags=[
                    {'Key': 'CreatedBy', 'Value': 'AmiVault'},
                    {'Key': 'InstanceName', 'Value': instance_name},
                    {'Key': 'BackupType', 'Value': 'python'},
                    {'Key': 'RetentionDays', 'Value': str(retention_days)}
                ]
                # db.session.refresh(backup)
                # backup.tags = tags
                # db.session.commit()
            )
            
            # Update backup record
            end_time = datetime.now(UTC)
            backup.status = 'Success'
            db.session.commit()

            # Update backup record with duration
            backup.duration_seconds = int((end_time - start_time).total_seconds())
            db.session.commit()
            
            logger.info(f"Scheduled backup completed: {ami_id} for instance {instance_id}")
            
            # Schedule immediate AMI status polling to check the status of the newly created AMI
            # Only for EventBridge instances that need polling
            if inst.needs_status_polling and inst.scheduler_type == 'eventbridge':
                schedule_ami_status_polling(run_immediate=True, instance_id=instance_id)
                logger.info(f"Scheduled one-time AMI status polling job for newly created AMI {ami_id} to run after 10 seconds")
            
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
        # Get instance IDs from query parameters
        instance_ids = request.args.get('instances', '')
        
        # Handle both comma-separated string and empty case
        if instance_ids:
            instance_ids = [id.strip() for id in instance_ids.split(',') if id.strip()]
        else:
            # If no instances specified, get all instances
            instances = Instance.query.filter_by(is_active=True).all()
            instance_ids = [inst.instance_id for inst in instances]
        
        if not instance_ids:
            return jsonify([])
        
        # Query backups with valid AMI IDs for the specified instances
        backups = Backup.query.filter(
            Backup.instance_id.in_(instance_ids),
            Backup.ami_id.isnot(None)
        ).order_by(Backup.timestamp.desc()).all()
        
        # Format the response
        result = [{
            'ami_id': backup.ami_id,
            'instance_name': backup.instance_name or (backup.instance_ref.instance_name if backup.instance_ref else 'Unknown'),
            'instance_id': backup.instance_id,
            'status': backup.status,
            'region': backup.region,
            'ami_name': backup.ami_name,
            'size_gb': backup.size_gb,
            'timestamp': backup.timestamp.isoformat() if backup.timestamp else None,
            'created_at': backup.created_at.isoformat() if backup.created_at else None,
            'completed_at': backup.completed_at.isoformat() if backup.completed_at else None
        } for backup in backups]
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_amis: {e}")
        return jsonify({'error': 'Failed to fetch AMIs', 'details': str(e)}), 500


@app.route('/get-credential-details/<int:credential_id>', methods=['GET'])
def get_credential_details(credential_id):
    """Get AWS credential details for auto-filling the form"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        # credential = AWSCredential.query.get(credential_id)
        # credential = AWSCredential.query.filter_by(id=credential_id, user_id=session['user_id']).first()
        credential = db.session.get(AWSCredential, credential_id)
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
                            
                            # Deregister AMI
                            ec2_client.deregister_image(ImageId=backup.ami_id)
                            deleted_amis.append(backup.ami_id)
                            logger.info(f"Deleted AMI {backup.ami_id} for instance {inst_id}")
                            
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


@app.route('/bulk-export-amis', methods=['POST'])
def bulk_export_amis():
    """Export AMI list for selected instances as CSV"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
            
        instance_ids = data.get('instances', [])
        if not instance_ids:
            return jsonify({'success': False, 'error': 'No instances selected'}), 400
        
        # Get all backups with AMI IDs for the selected instances
        backups = Backup.query.filter(
            Backup.instance_id.in_(instance_ids),
            Backup.ami_id.isnot(None)
        ).order_by(Backup.timestamp.desc()).all()
        
        if not backups:
            return jsonify({'success': False, 'error': 'No backups found'}), 404
        
        # Create CSV in memory
        csv_data = StringIO()
        csv_writer = csv.writer(csv_data)
        
        # Write header
        csv_writer.writerow([
            'Instance ID', 'AMI ID', 'AMI Name', 'Region', 'Timestamp', 'Retention Days', 'Status'
        ])
        
        # Write data rows
        for backup in backups:
            instance_name = backup.instance_name
            if not instance_name and backup.instance_ref:
                instance_name = backup.instance_ref.instance_name
                
            csv_writer.writerow([
                backup.instance_id,
                backup.ami_id,
                backup.ami_name or 'N/A',
                backup.region or 'Unknown',
                backup.timestamp.strftime('%Y-%m-%d %H:%M:%S') if backup.timestamp else 'N/A',
                str(backup.retention_days) if backup.retention_days else 'N/A',
                backup.status
            ])
        
        # Prepare response
        csv_output = csv_data.getvalue()
        csv_data.close()
        
        response = make_response(csv_output)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        response.headers["Content-Disposition"] = f"attachment; filename=amis_export_{timestamp}.csv"
        response.headers["Content-type"] = "text/csv"
        
        logger.info(f"User {session['username']} exported {len(backups)} AMIs as CSV")
        return response
        
    except Exception as e:
        logger.error(f"Error in bulk_export_amis: {e}")
        return jsonify({'success': False, 'error': 'Export operation failed', 'details': str(e)}), 500


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
        tag_key = data.get('tag_key')
        tag_value = data.get('tag_value')
        
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
                        # Add tag to AMI
                        ec2_client.create_tags(
                            Resources=[backup.ami_id],
                            Tags=[{'Key': tag_key, 'Value': tag_value}]
                        )
                        tagged_amis.append(backup.ami_id)
                        logger.info(f"Tagged AMI {backup.ami_id} with {tag_key}={tag_value}")
                        
                        # Update tags in database if they exist
                        if backup.tags is None:
                            backup.tags = {}
                        
                        if isinstance(backup.tags, dict):
                            backup.tags[tag_key] = tag_value
                            db.session.add(backup)
                        
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'InvalidAMIID.NotFound':
                            errors.append(f"AMI {backup.ami_id} not found in AWS")
                        else:
                            errors.append(f"Error tagging AMI {backup.ami_id}: {str(e)}")
                    except Exception as e:
                        errors.append(f"Error tagging AMI {backup.ami_id}: {str(e)}")
                
            except Exception as e:
                errors.append(f"Error processing instance {inst_id}: {str(e)}")
        
        # Commit database changes
        db.session.commit()
        
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
        db.session.rollback()
        logger.error(f"Error in bulk_tag_amis: {e}")
        return jsonify({'success': False, 'error': 'Tag operation failed', 'details': str(e)}), 500


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
            schedule_ami_status_polling()
            logger.info("✅ Backup scheduler and AMI status polling initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize backup scheduler: {e}")


# API Endpoints
@app.route('/api/backups')
def api_backups():
    """API endpoint to get all backups"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get query parameters
        instance_id = request.args.get('instance_id')
        status = request.args.get('status')
        limit = request.args.get('limit', type=int, default=100)
        offset = request.args.get('offset', type=int, default=0)
        
        # Build query
        query = Backup.query
        
        if instance_id:
            query = query.filter_by(instance_id=instance_id)
        
        if status:
            query = query.filter_by(status=status)
        
        # Get total count for pagination
        total_count = query.count()
        
        # Apply pagination
        backups = query.order_by(Backup.timestamp.desc()).offset(offset).limit(limit).all()
        
        # Format response
        result = {
            'backups': [{
                'id': backup.id,
                'instance_id': backup.instance_id,
                'instance_name': backup.instance_name or (backup.instance_ref.instance_name if backup.instance_ref else 'Unknown'),
                'ami_id': backup.ami_id,
                'ami_name': backup.ami_name,
                'status': backup.status,
                'region': backup.region,
                'size_gb': backup.size_gb,
                'timestamp': backup.timestamp.isoformat() if backup.timestamp else None,
                'created_at': backup.created_at.isoformat() if backup.created_at else None,
                'completed_at': backup.completed_at.isoformat() if backup.completed_at else None,
                'error_message': backup.error_message
            } for backup in backups],
            'pagination': {
                'total': total_count,
                'offset': offset,
                'limit': limit
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_backups: {e}")
        return jsonify({'error': 'Failed to fetch backups', 'details': str(e)}), 500


@app.route('/api/backup/<int:backup_id>')
def api_backup_detail(backup_id):
    """API endpoint to get details of a specific backup"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        backup = db.session.get(Backup, backup_id)
        
        if not backup:
            return jsonify({'error': 'Backup not found'}), 404
        
        result = {
            'id': backup.id,
            'instance_id': backup.instance_id,
            'instance_name': backup.instance_name or (backup.instance_ref.instance_name if backup.instance_ref else 'Unknown'),
            'ami_id': backup.ami_id,
            'ami_name': backup.ami_name,
            'status': backup.status,
            'region': backup.region,
            'size_gb': backup.size_gb,
            'timestamp': backup.timestamp.isoformat() if backup.timestamp else None,
            'created_at': backup.created_at.isoformat() if backup.created_at else None,
            'completed_at': backup.completed_at.isoformat() if backup.completed_at else None,
            'error_message': backup.error_message,
            'duration_seconds': backup.duration_seconds,
            'cleanup_status': backup.cleanup_status,
            'cleanup_timestamp': backup.cleanup_timestamp.isoformat() if backup.cleanup_timestamp else None,
            'retention_days': backup.retention_days
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_backup_detail: {e}")
        return jsonify({'error': 'Failed to fetch backup details', 'details': str(e)}), 500


@app.route('/api/backup-settings')
def api_backup_settings():
    """API endpoint to get global backup settings"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        settings = BackupSettings.query.first()
        
        if not settings:
            return jsonify({'error': 'Backup settings not found'}), 404
        
        result = {
            'id': settings.id,
            'retention_days': settings.retention_days,
            'backup_frequency': settings.backup_frequency,
            'email_notifications': settings.email_notifications,
            'notification_email': settings.notification_email,
            'max_concurrent_backups': settings.max_concurrent_backups,
            'backup_timeout_minutes': settings.backup_timeout_minutes,
            'created_at': settings.created_at.isoformat() if settings.created_at else None,
            'updated_at': settings.updated_at.isoformat() if settings.updated_at else None
        }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_backup_settings: {e}")
        return jsonify({'error': 'Failed to fetch backup settings', 'details': str(e)}), 500


@app.route('/api/aws-credentials')
def api_aws_credentials():
    """API endpoint to get AWS credentials"""
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        # Get the current user
        current_username = session.get('username')
        user = User.query.filter_by(username=current_username).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check if user is admin
        is_admin = user.username.lower() == 'admin'
        
        # Query credentials
        if is_admin:
            # Admin can see all credentials
            credentials = AWSCredential.query.all()
        else:
            # Regular users can only see their own credentials
            credentials = AWSCredential.query.filter_by(user_id=user.id).all()
        
        result = [{
            'id': cred.id,
            'name': cred.name,
            'region': cred.region,
            'has_access_key': bool(cred.access_key),
            'has_secret_key': bool(cred.secret_key),
            'created_at': cred.created_at.isoformat() if cred.created_at else None,
            'updated_at': cred.updated_at.isoformat() if cred.updated_at else None
        } for cred in credentials]
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in api_aws_credentials: {e}")
        return jsonify({'error': 'Failed to fetch AWS credentials', 'details': str(e)}), 500


@app.route('/api/instances/<instance_id>/poll', methods=['POST'])
def api_poll_instance(instance_id):
    """API endpoint to manually trigger AMI status polling for a specific instance"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        # Check if instance exists
        instance = Instance.query.filter_by(instance_id=instance_id).first()
        if not instance:
            return jsonify({'success': False, 'error': f'Instance {instance_id} not found'}), 404
        
        # Call the polling function directly for this instance
        logger.info(f"Manual AMI status polling triggered for instance {instance_id}")
        result = poll_specific_instance(instance_id)
        
        return jsonify({
            'success': True,
            'message': f'AMI status polling completed for instance {instance_id}',
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in manual AMI status polling for instance {instance_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/poll-all-instances', methods=['POST'])
def api_poll_all_instances():
    """API endpoint to manually trigger AMI status polling for all instances"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    try:
        # Call the polling function directly for all instances
        logger.info("Manual AMI status polling triggered for all instances")
        result = poll_all_instances()
        
        return jsonify({
            'success': True,
            'message': 'AMI status polling completed for all instances',
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in manual AMI status polling for all instances: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/docs')
def api_docs():
    """API documentation endpoint (JSON format)"""
    api_endpoints = [
        {
            'endpoint': '/api/instances',
            'method': 'GET',
            'description': 'Get list of all instances',
            'parameters': [],
            'response': 'Array of instance objects with instance_id, instance_name, region, and created_at'
        },
        {
            'endpoint': '/api/amis',
            'method': 'GET',
            'description': 'Get list of AMIs for selected instances',
            'parameters': [
                {'name': 'instances', 'type': 'string', 'description': 'Comma-separated list of instance IDs (optional)'}
            ],
            'response': 'Array of AMI objects with ami_id, instance_name, instance_id, status, region, etc.'
        },
        {
            'endpoint': '/api/backups',
            'method': 'GET',
            'description': 'Get list of all backups with pagination',
            'parameters': [
                {'name': 'instance_id', 'type': 'string', 'description': 'Filter by instance ID (optional)'},
                {'name': 'status', 'type': 'string', 'description': 'Filter by status (optional)'},
                {'name': 'limit', 'type': 'integer', 'description': 'Number of results to return (default: 100)'},
                {'name': 'offset', 'type': 'integer', 'description': 'Offset for pagination (default: 0)'}
            ],
            'response': 'Object with backups array and pagination information'
        },
        {
            'endpoint': '/api/backup/<backup_id>',
            'method': 'GET',
            'description': 'Get details of a specific backup',
            'parameters': [
                {'name': 'backup_id', 'type': 'integer', 'description': 'ID of the backup to retrieve'}
            ],
            'response': 'Detailed backup object'
        },
        {
            'endpoint': '/api/backup-settings',
            'method': 'GET',
            'description': 'Get global backup settings',
            'parameters': [],
            'response': 'Backup settings object'
        },
        {
            'endpoint': '/api/aws-credentials',
            'method': 'GET',
            'description': 'Get AWS credentials (admin sees all, users see only their own)',
            'parameters': [],
            'response': 'Array of credential objects (without actual keys)'
        },
        {
            'endpoint': '/bulk-delete-amis',
            'method': 'POST',
            'description': 'Delete AMIs and associated snapshots for selected instances',
            'parameters': [
                {'name': 'instances', 'type': 'array', 'description': 'Array of instance IDs'}
            ],
            'response': 'Object with success status, deleted count, and errors'
        }
    ]
    
    api_data = {
        'api_name': 'AMIVault API',
        'version': '1.0',
        'description': 'API for managing AWS EC2 instance backups and AMIs',
        'endpoints': api_endpoints
    }
    
    # Check if the client wants JSON or HTML
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        return jsonify(api_data)
    
    # Default to HTML documentation
    return render_template('api_docs.html', api=api_data)


@app.route('/docs')
def docs_redirect():
    """Redirect /docs to /api/docs for convenience"""
    return redirect(url_for('api_docs'))

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
        return redirect(url_for('dashboard'))
    
    # Find backup record
    backup = Backup.query.filter_by(ami_id=ami_id).first()
    if not backup:
        error_msg = f"AMI record '{ami_id}' not found in database"
        logger.warning(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('dashboard'))
    
    # Find associated instance for AWS credentials
    instance = Instance.query.filter_by(instance_id=backup.instance_id).first()
    if not instance:
        error_msg = f"Instance record '{backup.instance_id}' not found"
        logger.error(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('dashboard'))
    
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
                
                # success_msg = f"AMI {ami_id} was already deleted from AWS. Database record cleaned up."
                # if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    # return jsonify({'success': True, 'message': success_msg})
                flash("success", "success")
                return redirect(url_for('dashboard'))
                
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
                return redirect(url_for('dashboard'))
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
        
        return redirect(url_for('dashboard'))
        
    except NoCredentialsError:
        error_msg = "AWS credentials not found or invalid"
        logger.error(f"Delete AMI failed: {error_msg}")
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('dashboard'))
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_msg = f"AWS Error ({error_code}): {str(e)}"
        logger.error(f"Delete AMI failed: {error_msg}")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        error_msg = f"Unexpected error deleting AMI: {str(e)}"
        logger.error(f"Delete AMI failed: {error_msg}")
        
        if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'error': error_msg})
        flash(error_msg, "danger")
        return redirect(url_for('dashboard'))


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
    credential_id = data.get('credential_id')  # Move this line up before using credential_id
    if credential_id:
        # Look up the saved credential
        credential = db.session.get(AWSCredential, credential_id)
        if not credential:
            return jsonify({'success': False, 'error': 'Saved credential not found'}), 404
        # Look up the saved credential using session.get() (SQLAlchemy 2.0 compatible)
        # This line is removed as it's redundant with the check above
        
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

# def add_notification(message, category='info', persistent=False):
#     """Add notification to session with improved categorization"""
#     if 'notifications' not in session:
#         session['notifications'] = []
    
#     # Prevent duplicate notifications
#     existing_messages = [n.get('message') for n in session['notifications']]
#     if message not in existing_messages:
#         notification = {
#             'message': message,
#             'category': category,
#             'timestamp': datetime.now(UTC).isoformat(),
#             'persistent': persistent,
#             'id': secrets.token_hex(8)  # Unique ID for each notification
#         }
#         session['notifications'].append(notification)
#         session.modified = True
        
#         # Also use Flask's flash for immediate display
#         flash(message, category)
        
#         # Log notification for debugging
#         logger.info(f"Added notification [{category}]: {message}")


# def get_notifications():
#     """Retrieve all notifications from session"""
#     notifications = session.get('notifications', [])
    
#     # Clean up old notifications (older than 1 hour for non-persistent ones)
#     current_time = datetime.now(UTC)  # Use UTC timezone directly
#     filtered_notifications = []
    
#     for notification in notifications:
#         if notification.get('persistent', False):
#             filtered_notifications.append(notification)
#         else:
#             try:
#                 # Parse the timestamp and ensure it has timezone info
#                 notification_time = datetime.fromisoformat(notification.get('timestamp', ''))
#                 # If the timestamp doesn't have timezone info, assume it's UTC
#                 if notification_time.tzinfo is None:
#                     notification_time = notification_time.replace(tzinfo=UTC)
                    
#                 if (current_time - notification_time).total_seconds() < 3600:  # 1 hour
#                     filtered_notifications.append(notification)
#             except (ValueError, TypeError):
#                 # Keep notification if timestamp parsing fails
#                 filtered_notifications.append(notification)
    
#     # Update session if notifications were cleaned up
#     if len(filtered_notifications) != len(notifications):
#         session['notifications'] = filtered_notifications
#         session.modified = True
    
#     return filtered_notifications


# @app.route('/clear-notifications', methods=['POST'])
# def clear_notifications():
#     """Clear all or specific notifications"""
#     if 'username' not in session:
#         return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
#     notification_id = request.form.get('notification_id') or request.json.get('notification_id')
    
#     if notification_id:
#         # Clear specific notification
#         notifications = session.get('notifications', [])
#         session['notifications'] = [n for n in notifications if n.get('id') != notification_id]
#         session.modified = True
#         logger.info(f"Cleared specific notification: {notification_id}")
        
#         if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
#             return jsonify({'success': True, 'message': 'Notification cleared'})
#     else:
#         # Clear all notifications
#         session['notifications'] = []
#         session.modified = True
#         logger.info("Cleared all notifications")
        
#         if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
#             return jsonify({'success': True, 'message': 'All notifications cleared'})
    
#     return redirect(request.referrer or url_for('dashboard'))


# @app.route('/notifications/api', methods=['GET'])
# def notifications_api():
#     """API endpoint to get current notifications"""
#     if 'username' not in session:
#         return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
#     notifications = get_notifications()
    
#     return jsonify({
#         'success': True,
#         'notifications': notifications,
#         'count': len(notifications)
#     })


# @app.route('/mark-notification-read', methods=['POST'])
# def mark_notification_read():
#     """Mark notification as read"""
#     if 'username' not in session:
#         return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
#     notification_id = request.form.get('notification_id') or request.json.get('notification_id')
    
#     if not notification_id:
#         return jsonify({'success': False, 'error': 'Notification ID required'})
    
#     notifications = session.get('notifications', [])
#     for notification in notifications:
#         if notification.get('id') == notification_id:
#             notification['read'] = True
#             notification['read_at'] = datetime.now(UTC).isoformat()
#             break
    
#     session['notifications'] = notifications
#     session.modified = True
    
#     return jsonify({'success': True, 'message': 'Notification marked as read'})


# # Context processor to make notifications available in all templates
# @app.context_processor
# def inject_notifications():
#     """Inject notifications into all templates"""
#     return {
#         'notifications': get_notifications(),
#         'notification_count': len(get_notifications())
#     }


# # Enhanced notification functions for specific use cases
# def notify_backup_success(instance_name, ami_id):
#     """Notify successful backup creation"""
#     message = f"Backup created successfully for {instance_name} (AMI: {ami_id})"
#     add_notification(message, 'success')


# def notify_backup_failure(instance_name, error_msg):
#     """Notify backup failure"""
#     message = f"Backup failed for {instance_name}: {error_msg}"
#     add_notification(message, 'danger', persistent=True)


# def notify_instance_added(instance_name):
#     """Notify new instance registration"""
#     message = f"Instance '{instance_name}' added successfully"
#     add_notification(message, 'success')


# def notify_cleanup_completed(count):
#     """Notify cleanup operation completion"""
#     message = f"Cleanup completed: {count} expired backups removed"
#     add_notification(message, 'info')

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

# def schedule_all_instance_backups():
#     """Schedule backup jobs for all active instances using both APScheduler and EventBridge"""
#     try:
#         # Clear existing APScheduler jobs
#         scheduler.remove_all_jobs()
#         logger.info("Cleared all existing APScheduler jobs")
        
#         # Get global backup settings
#         global_settings = BackupSettings.query.first()
#         if not global_settings:
#             logger.warning("No global backup settings found")
#             return
        
#         # Schedule jobs for each active instance
#         active_instances = Instance.query.filter_by(is_active=True).all()
#         success_count = 0
        
#         for instance in active_instances:
#             try:
#                 # Use instance-specific frequency or fall back to global
#                 frequency = get_effective_setting(
#                     instance.backup_frequency, 
#                     global_settings.backup_frequency
#                 )
                
#                 if not frequency:
#                     logger.warning(f"No backup frequency configured for instance {instance.instance_id}")
#                     continue
                
#                 # Schedule using both APScheduler and EventBridge
#                 schedule_instance_backup(instance)
#                 success_count += 1
#                 logger.info(f"Scheduled backup for instance {instance.instance_id} with frequency {frequency}")
                
#             except Exception as e:
#                 logger.error(f"Error scheduling backup for {instance.instance_id}: {e}")
#                 continue
        
#         logger.info(f"Successfully scheduled backup jobs for {success_count} out of {len(active_instances)} instances")
        
#     except Exception as e:
#         logger.error(f"Error in schedule_all_instance_backups: {e}")

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
                
                # Create job ID
                job_id = f"backup_{instance.instance_id}"
                
                # Schedule based on frequency type
                if frequency.startswith('@'):
                    # Handle interval-based schedules
                    try:
                        hours = int(frequency[1:])
                        scheduler.add_job(
                            id=job_id,
                            func=backup_instance,
                            args=[instance.instance_id],
                            trigger='interval',
                            hours=hours,
                            replace_existing=True
                        )
                    except ValueError as e:
                        logger.error(f"Invalid interval value for instance {instance.instance_id}: {e}")
                        continue
                else:
                    # Handle cron-based schedules
                    try:
                        cron_kwargs = parse_cron_expression(frequency)
                        scheduler.add_job(
                            id=job_id,
                            func=backup_instance,
                            args=[instance.instance_id],
                            trigger='cron',
                            replace_existing=True,
                            **cron_kwargs
                        )
                    except ValueError as e:
                        logger.error(f"Invalid cron expression for instance {instance.instance_id}: {e}")
                        continue
                
                success_count += 1
                logger.info(f"Successfully scheduled backup for instance {instance.instance_id}")
                
            except Exception as e:
                logger.error(f"Failed to schedule backup for instance {instance.instance_id}: {e}")
                continue
        
        logger.info(f"Successfully scheduled backups for {success_count} out of {len(active_instances)} instances")
        
        # Schedule the AMI status polling job
        schedule_ami_status_polling()
        logger.info("Scheduled AMI status polling job")
        
    except Exception as e:
        logger.error(f"Error in schedule_all_instance_backups: {e}")
        raise


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
            #instance_name=instance.instance_name,
            #region=instance.region,
            status='Pending',
            #backup_type='scheduled',
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
        ami_name = f"{instance.instance_name}_{datetime.now(UTC).strftime('%Y_%m_%d_%I_%M_%p')}_python"
        
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
        
        # Get backups for this instance
        backups = Backup.query.filter(
            Backup.instance_id == instance_id,
            Backup.status == 'Success'
        ).all()
        
        # Get retention days from instance or global settings
        retention_days = get_effective_setting(
            instance.retention_days,
            BackupSettings.query.first().retention_days if BackupSettings.query.first() else 7
        )
        
        # Current time in UTC
        now = datetime.now(UTC)
        
        ec2_client = boto3.client(
            'ec2',
            region_name=instance.region,
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key
        )
        
        for backup in backups:
            # Check if backup is older than retention period
            if backup.timestamp and (now - backup.timestamp).days > retention_days and backup.ami_id:
                try:
                    # Delete AMI and associated snapshots
                    ec2_client.deregister_image(ImageId=backup.ami_id)
                    
                    # Get and delete associated snapshots
                    try:
                        images = ec2_client.describe_images(ImageIds=[backup.ami_id])
                        if images.get('Images'):
                            for block_device in images['Images'][0].get('BlockDeviceMappings', []):
                                if 'Ebs' in block_device and 'SnapshotId' in block_device['Ebs']:
                                    snapshot_id = block_device['Ebs']['SnapshotId']
                                    ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                    except ClientError:
                        # AMI might already be deleted
                        pass
                    
                    # Update backup record
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
            cron_schedule = request.form.get('cron_schedule')
            
            if instance_id and scheduler_type in ['python', 'eventbridge']:
                instance = Instance.query.filter_by(instance_id=instance_id).first()
                if instance:
                    # Update scheduler type
                    instance.scheduler_type = scheduler_type
                    
                    # If switching to EventBridge and a cron schedule is provided, update the backup frequency
                    if scheduler_type == 'eventbridge' and cron_schedule:
                        instance.backup_frequency = cron_schedule
                    
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
        
        # Always use UTC timezone for scheduling
        app_timezone = pytz.timezone('UTC')
        # Create a timezone-aware datetime using pytz's localize method
        current_time = app_timezone.localize(datetime.now().replace(tzinfo=None))
        
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
                timezone_info = 'UTC'  # Always use UTC for scheduling
                
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
                    is_active = instance.is_active
                
                scheduled_instances.append({
                    'instance_id': instance.instance_id,
                    'instance_name': instance.instance_name,
                    'instance_type': instance_type,
                    'state': instance_state,
                    'schedule': schedule,
                    'timezone': timezone_info,
                    'next_run': next_run,
                    'rule_status': rule_status,
                    'region': instance.region,
                    'is_active': instance.is_active
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
                    rules_response = eventbridge_client.list_rules(NamePrefix='AMIVault-Backup-')
                    
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
            
            # Handle both 5-field and 6-field cron expressions
            if len(parts) == 6:  # AWS cron format: minute hour day month day-of-week year
                # Convert to standard cron format (remove year)
                cron_parts = parts[:5]
            elif len(parts) == 5:  # Standard cron format: minute hour day month day-of-week
                cron_parts = parts
                
                # Simple next run calculation for common patterns
                minute, hour, day, month, dow = cron_parts
                
                # Ensure we're working with a timezone-aware datetime
                if current_time.tzinfo is None:
                    app_timezone = pytz.timezone('UTC')  # Always use UTC for scheduling
                    current_time = app_timezone.localize(current_time)
                
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
        app_timezone = pytz.timezone('UTC')  # Always use UTC for scheduling
        # Create a timezone-aware datetime using pytz's localize method
        now = app_timezone.localize(datetime.now().replace(tzinfo=None))
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
        eventbridge_rules = []
        app_timezone = pytz.timezone('UTC')  # Always use UTC for scheduling
        # Create a timezone-aware datetime using pytz's localize method
        current_time = app_timezone.localize(datetime.now().replace(tzinfo=None))
        
        instances = Instance.query.filter_by(is_active=True).all()
        
        for instance in instances:
            try:
                # Get basic instance info and next run time
                schedule = instance.backup_frequency
                next_run = calculate_next_run(schedule, current_time)
                
                # Check for EventBridge rule for this instance
                rule_status = None
                try:
                    # Create EventBridge client
                    eventbridge_client = boto3.client(
                        'events',
                        region_name=instance.region,
                        aws_access_key_id=instance.access_key,
                        aws_secret_access_key=instance.secret_key
                    )
                    
                    # Try to get the backup rule
                    rule_name = f"AMIVault-Backup-{instance.instance_id}"
                    rule_response = eventbridge_client.describe_rule(Name=rule_name)
                    rule_status = {
                        'exists': True,
                        'state': rule_response.get('State', 'UNKNOWN'),
                        'schedule': rule_response.get('ScheduleExpression', ''),
                        'description': rule_response.get('Description', '')
                    }
                except Exception as e:
                    logger.warning(f"Error checking EventBridge rule for {instance.instance_id}: {e}")
                    rule_status = {
                        'exists': False,
                        'state': 'ERROR'
                    }
                
                scheduled_instances.append({
                    'instance_id': instance.instance_id,
                    'instance_name': instance.instance_name,
                    'schedule': schedule,
                    'next_run': next_run.isoformat() if next_run else None,
                    'next_run_human': time_until_filter(next_run) if next_run else None,
                    'rule_status': rule_status
                })
                
            except Exception as e:
                logger.error(f"Error processing instance {instance.instance_id}: {e}")
        
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
                            next_run = calculate_next_run(rule_detail['schedule'], current_time)
                            rule_detail['next_run'] = next_run.isoformat() if next_run else None
                            rule_detail['next_run_human'] = time_until_filter(next_run) if next_run else None
                        else:
                            rule_detail['next_run'] = None
                            rule_detail['next_run_human'] = None
                        
                        eventbridge_rules.append(rule_detail)
                        
                except Exception as e:
                    logger.error(f"Error listing EventBridge rules for region {region}: {e}")
        
        except Exception as e:
            logger.error(f"Error processing EventBridge rules: {e}")
        
        return jsonify({
            'scheduled_instances': scheduled_instances,
            'eventbridge_rules': eventbridge_rules,
            'current_time': current_time.isoformat(),
            'refresh_time': current_time.strftime('%Y-%m-%d %H:%M:%S') + ' ' + current_time.tzinfo.tzname(current_time)
        })
    
    except Exception as e:
        logger.error(f"Error refreshing schedules: {e}")
        return jsonify({'error': 'Failed to refresh schedules'}), 500

############################################################ Application Startup ############################################################

# def init_app():
#     """Initialize the application"""
#     with app.app_context():
#         try:
#             # Create database tables
#             db.create_all()
            
#             # Initialize database with default data
#             if not init_database():
#                 logger.error("Failed to initialize database")
#                 return False
            
#             # Start scheduler if not running
#             if not scheduler.running:
#                 scheduler.start()
#                 schedule_all_instance_backups()
#                 logger.info("✅ Backup scheduler started successfully")
            
#             return True
#         except Exception as e:
#             logger.error(f"Error initializing application: {e}")
#             return False

# if __name__ == '__main__':
#     try:
#         if init_app():
#             logger.info("🚀 Starting AWS Backup Manager")
#             app.run(host="0.0.0.0", port=5000)
#     except Exception as e:
#         logger.error(f"Error starting application: {e}")
#     finally:
#         # Cleanup scheduler on exit
#         if scheduler.running:
#             scheduler.shutdown()
#             logger.info("Scheduler shutdown complete")

def init_app():
    try:
        # Create database tables
        db.create_all()
        logger.info("✅ Database tables created successfully")
        
        # Create default admin user if it doesn't exist
        admin_username = os.environ.get('ADMIN_USERNAME', 'admin')
        admin_user = User.query.filter_by(username=admin_username).first()
        
        if not admin_user:
            admin_password = os.environ.get('ADMIN_PASSWORD', 'Admin123!')
            admin_email = os.environ.get('ADMIN_EMAIL', 'admin@example.com')
            
            admin_user = User(
                username=admin_username,
                email=admin_email,
                is_active=True
            )
            admin_user.set_password(admin_password)
            db.session.add(admin_user)
            db.session.commit()
            logger.info(f"✅ Default admin user '{admin_username}' created successfully")
        
        # Create default backup settings if they don't exist
        default_settings = BackupSettings.query.first()
        if not default_settings:
            # Get default backup settings from environment variables
            default_backup_frequency = os.environ.get('DEFAULT_BACKUP_FREQUENCY', '0 2 * * *')
            default_retention_days = int(os.environ.get('DEFAULT_RETENTION_DAYS', '7'))
            default_global_polling = os.environ.get('DEFAULT_GLOBAL_POLLING', '0 * * * *')  # Default hourly polling
            
            # If DEFAULT_GLOBAL_POLLING is not in env, set it to default value
            if 'DEFAULT_GLOBAL_POLLING' not in os.environ:
                os.environ['DEFAULT_GLOBAL_POLLING'] = default_global_polling
                logger.info(f"Set DEFAULT_GLOBAL_POLLING environment variable to '{default_global_polling}'")
            
            # Create default backup settings
            default_settings = BackupSettings(
                backup_frequency=default_backup_frequency,
                retention_days=default_retention_days,
                global_polling=default_global_polling
            )
            db.session.add(default_settings)
            db.session.commit()
            logger.info(f"✅ Default backup settings created: frequency='{default_backup_frequency}', retention={default_retention_days} days, global_polling='{default_global_polling}'")
        else:
            # Update global_polling from environment variable if needed
            env_global_polling = os.environ.get('DEFAULT_GLOBAL_POLLING')
            if env_global_polling and default_settings.global_polling != env_global_polling:
                default_settings.global_polling = env_global_polling
                db.session.commit()
                logger.info(f"✅ Updated global_polling to '{default_settings.global_polling}' from environment variable")
            elif not default_settings.global_polling:
                default_global_polling = '0 * * * *'  # Default hourly polling
                default_settings.global_polling = default_global_polling
                os.environ['DEFAULT_GLOBAL_POLLING'] = default_global_polling
                db.session.commit()
                logger.info(f"✅ Set default global_polling to '{default_global_polling}'")
        
        # Initialize scheduler
        if not scheduler.running:
            scheduler.start()
            logger.info("✅ Scheduler started successfully")
            
            # Schedule backups for active instances
            schedule_all_instance_backups()
            
            # Schedule AMI status polling for instances that need it
            schedule_ami_status_polling()
            logger.info("Scheduled AMI status polling job")
            
        return True
    except Exception as e:
        logger.error(f"Error during initialization: {e}")
        return False

if __name__ == '__main__':
    try:
        with app.app_context():
            if init_app():
                host = os.environ.get('FLASK_HOST', '0.0.0.0')
                port = int(os.environ.get('FLASK_PORT', 5000))
                logger.info("Starting AWS Backup Manager on {}:{}".format(host, port))
                app.run(host=host, port=port)
    except Exception as e:
        logger.error("Error starting application: {}".format(e))
    finally:
        # Cleanup scheduler on exit
        if scheduler.running:
            scheduler.shutdown()
            logger.info("Scheduler shutdown complete")