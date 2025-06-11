from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
import logging

logger = logging.getLogger(__name__)

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    extend_existing = True
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    two_factor_enabled = db.Column(db.Boolean, default=False, nullable=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def set_password(self, password):
        """Hash and set password"""
        if not password or len(password.strip()) == 0:
            raise ValueError("Password cannot be empty")
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check if provided password matches hash"""
        if not password:
            return False
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        db.session.commit()

    def __repr__(self):
        return f'<User {self.username}>'

class Instance(db.Model):
    """AWS EC2 Instance model for backup management"""
    __tablename__ = 'instances'
    extend_existing = True
    
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    instance_name = db.Column(db.String(100), nullable=False)
    access_key = db.Column(db.String(100), nullable=False)
    secret_key = db.Column(db.String(100), nullable=False)
    region = db.Column(db.String(20), nullable=False)
    backup_frequency = db.Column(db.String(64), nullable=False, default="0 2 * * *")  # Daily at 2 AM
    retention_days = db.Column(db.Integer, nullable=False, default=7)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    scheduler_type = db.Column(db.String(20), default='python', nullable=False)  # 'python' or 'eventbridge'
    
    # Relationship to backups
    backups = db.relationship('Backup', backref='instance_ref', lazy=True, cascade='all, delete-orphan')

    def validate_aws_credentials(self):
        """Validate AWS credentials and instance existence"""
        try:
            ec2_client = boto3.client(
                'ec2',
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )
            
            response = ec2_client.describe_instances(InstanceIds=[self.instance_id])
            
            if not response.get('Reservations'):
                return False, "Instance not found"
                
            # Update instance name from AWS if available
            reservations = response['Reservations']
            if reservations and reservations[0].get('Instances'):
                instance = reservations[0]['Instances'][0]
                tags = instance.get('Tags', [])
                for tag in tags:
                    if tag['Key'] == 'Name' and tag.get('Value'):
                        if self.instance_name != tag['Value']:
                            logger.info(f"Updating instance name from {self.instance_name} to {tag['Value']}")
                            self.instance_name = tag['Value']
                        break
            
            return True, "Valid"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidInstanceID.NotFound':
                return False, f"Instance '{self.instance_id}' not found"
            elif error_code in ['AuthFailure', 'UnauthorizedOperation']:
                return False, "Authentication failed - check credentials"
            else:
                return False, f"AWS Error: {str(e)}"
        except NoCredentialsError:
            return False, "Invalid AWS credentials"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def __repr__(self):
        return f'<Instance {self.instance_id}: {self.instance_name}>'

class BackupSettings(db.Model):
    """Global backup settings model"""
    __tablename__ = 'backup_settings'
    extend_existing = True
    
    id = db.Column(db.Integer, primary_key=True)
    retention_days = db.Column(db.Integer, default=7, nullable=False)
    backup_frequency = db.Column(db.String(64), default="0 2 * * *", nullable=False)  # Daily at 2 AM
    instance_id = db.Column(db.String(64), nullable=False, default="global-config")
    instance_name = db.Column(db.String(128), default="Global Settings")
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Notification settings
    email_notifications = db.Column(db.Boolean, default=False)
    notification_email = db.Column(db.String(120), nullable=True)
    
    # Advanced settings
    max_concurrent_backups = db.Column(db.Integer, default=5)
    backup_timeout_minutes = db.Column(db.Integer, default=60)

    def __repr__(self):
        return f'<BackupSettings retention={self.retention_days}d frequency={self.backup_frequency}>'

class Backup(db.Model):
    """Backup records model"""
    __tablename__ = 'backups'
    extend_existing = True
    
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.String(50), db.ForeignKey('instances.instance_id'), nullable=False)
    ami_id = db.Column(db.String(50), nullable=True)  # Changed from snapshot_id
    ami_name = db.Column(db.String(100), nullable=True)  # Added for AMI name
    status = db.Column(db.String(20), nullable=False, default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)  # Added for backup timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    size_gb = db.Column(db.Float, nullable=True)
    retention_days = db.Column(db.Integer, nullable=False, default=7)
    region = db.Column(db.String(20), nullable=True)  # Added for region information
    tags = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f'<Backup {self.ami_id} for {self.instance_id}>'

class AWSCredential(db.Model):
    """AWS Credentials model for storing reusable AWS credentials"""
    __tablename__ = 'aws_credentials'
    extend_existing = True
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    access_key = db.Column(db.String(100), nullable=False)
    secret_key = db.Column(db.String(100), nullable=False)
    region = db.Column(db.String(20), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Added user_id field
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Add relationship to User model
    user = db.relationship('User', backref=db.backref('aws_credentials', lazy=True))
    
    def validate_credentials(self):
        """Validate AWS credentials"""
        try:
            ec2_client = boto3.client(
                'ec2',
                region_name=self.region,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key
            )
            
            # Just list regions to verify credentials work
            ec2_client.describe_regions()
            return True, "Valid"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AuthFailure', 'UnauthorizedOperation']:
                return False, "Authentication failed - check credentials"
            else:
                return False, f"AWS Error: {str(e)}"
        except NoCredentialsError:
            return False, "Invalid AWS credentials"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def __repr__(self):
        return f'<AWSCredential {self.name} ({self.region})>'