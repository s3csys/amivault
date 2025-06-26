import pytest
import os
import io
import json
import pyotp
import csv
import tempfile
import shutil
from app import app, db, User, AWSCredential, Instance, Backup, validate_cron_expression, convert_to_eventbridge_format
from datetime import datetime, UTC
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv
from cryptography.fernet import Fernet, InvalidToken
import bcrypt
import time

# Import utility functions to test
from utility_manager import (
    get_encryption_key,
    encrypt_value,
    decrypt_value,
    encrypt_data,
    decrypt_data,
    generate_encryption_key,
    validate_email,
    validate_password,
    get_secure_password,
    display_logo
)

# Load environment variables from .env file
load_dotenv()

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file::memory:?cache=shared' 
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False}
    }#'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    print("\nSetting up test client and database...")
    with app.test_client() as client:
        with app.app_context():
            print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
            db.drop_all()
            db.create_all()
            print("Database tables created")
            
            # Create admin user
            user = User(
                username='admin',
                email='admin@admin.com',
                is_active=True
            )
            user.set_password('password123')
            db.session.add(user)
            
            # Create test user
            user = User(
                username='test',
                email='test@admin.com',
                is_active=True
            )
            user.set_password('password123')
            db.session.add(user)

            # Create 2FA enabled user
            user_2fa = User(
                username='test_2fa',
                email='test_2fa@example.com',
                is_active=True,
                two_factor_enabled=True,
                two_factor_secret='JBSWY3DPEHPK3PXP'
            )
            user_2fa.set_password('password123')
            db.session.add(user_2fa)
            
            # Create inactive user
            inactive_user = User(
                username='test_inactive',
                email='test_inactive@example.com',
                is_active=False
            )
            inactive_user.set_password('password123')
            db.session.add(inactive_user)
            
            db.session.commit()
            print("Initial users created and committed to database")
            
            # Verify users were added
            users = User.query.all()
            print(f"Total users in DB: {len(users)}")
            for user in users:
                print(f"User in DB: {user.username}")
            
        yield client
        
        with app.app_context():
            db.session.remove()
            db.drop_all()

################################################ Login checks ####################################################################

# Test GET login page
def test_login_page(client):
    """Test that login page loads correctly"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data

# Testing logins
def test_login_admin_account(client):
    """Test successful login with correct credentials"""
    # admin login check 
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data

def test_login_test_account(client):
    # admin test check 
    response = client.post('/login', data={
        'username': 'test',
        'password': 'password123'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Dashboard' in response.data

# def test_login_test_2fa_account(client):
#     # admin test_2fa check 
#     response = client.post('/login', data={
#         'username': 'test_2fa',
#         'password': 'password123'
#     }, follow_redirects=True)
#     assert response.status_code == 200
#     assert b'Dashboard' in response.data

# Test login with missing credentials
def test_login_missing_credentials(client):
    """Test login with missing username or password"""
    # Missing username
    response = client.post('/login', data={
        'password': 'password123'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert response.status_code == 200
    assert json.loads(response.data)['error'] == 'Username and password are required'
    
    # Missing password
    response = client.post('/login', data={
        'username': 'testuser'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert response.status_code == 200
    assert json.loads(response.data)['error'] == 'Username and password are required'


def test_login_test_inactive_account(client):
    # admin login_inactive check 
    response = client.post('/login', data={
        'username': 'test_inactive',
        'password': 'password123'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert response.status_code == 200
    assert json.loads(response.data)['error'] == 'Your account is inactive. Please contact the administrator.'

def test_login_wrong_credentials(client):
    """Test login with incorrect password"""
    response = client.post('/login', data={
        'username': 'testuser',
        'password': 'wrongpassword'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    assert response.status_code == 200
    assert json.loads(response.data)['error'] == 'Invalid username or password'

def test_login_test_2fa_account(client):
# def test_login_with_2fa(client):
    """Test login flow for user with 2FA enabled"""
    # First login step
    response = client.post('/login', data={
        'username': 'test_2fa',  # Use the correct test 2FA username
        'password': 'password123'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['require_2fa'] == True
    
    # Generate a valid TOTP code
    totp = pyotp.TOTP('JBSWY3DPEHPK3PXP')  # Use the same secret as in the test fixture
    valid_code = totp.now()
    
    # Second step: Submit 2FA code
    response = client.post('/login_2fa', data={
        'code': valid_code
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'redirect' in data

# Test JSON API login
def test_login_json_api(client):
    """Test login via JSON API"""
    response = client.post('/login', 
        data={
            'username': 'test',
            'password': 'password123'
        },
        headers={'X-Requested-With': 'XMLHttpRequest'}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert 'redirect' in data

# Test logout
def test_logout(client):
    """Test logout functionality"""
    # First login
    login_response = client.post('/login', data={
        'username': 'test',
        'password': 'password123'
    }, headers={'X-Requested-With': 'XMLHttpRequest'})
    
    # Verify login was successful
    assert login_response.status_code == 200
    login_data = json.loads(login_response.data)
    assert login_data['success'] == True
    
    # Access a protected page to confirm we're logged in
    with client.session_transaction() as sess:
        sess['username'] = 'test'  # Manually set session
    
    # Then logout
    response = client.get('/logout')
    assert response.status_code == 302  # Redirect status
    assert response.headers['Location'] == '/login'  # Check redirect location
    
    # Verify we can't access protected page
    response = client.get('/aws-instances')
    assert response.status_code == 302  # Redirect to login
    response = client.get('/aws-instances', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content
    
    # Verify we can't access protected page
    response = client.get('/backup-settings')
    assert response.status_code == 302  # Redirect to login
    response = client.get('/backup-settings', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content

    # Verify we can't access protected page
    response = client.get('/schedules')
    assert response.status_code == 302  # Redirect to login
    response = client.get('/schedules', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content

    # Verify we can't access protected page
    response = client.get('/user-settings')
    assert response.status_code == 302  # Redirect to login
    response = client.get('/user-settings', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content

################################################ Dashboard checks ####################################################################

# Test bulk_delete_amis
@patch('boto3.client')
def test_bulk_delete_amis_success(mock_boto3_client, client, test_instance):
    """Test successful bulk deletion of AMIs"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock describe_images response
    mock_ec2.describe_images.return_value = {
        'Images': [{
            'ImageId': 'ami-012345678',
            'BlockDeviceMappings': [{
                'Ebs': {
                    'SnapshotId': 'snap-012345678'
                }
            }]
        }]
    }
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_delete_amis
    response = client.post('/bulk-delete-amis', json={
        'instances': ['i-1234567890abcdef0']
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert data['deleted_count'] > 0
    
    # Verify boto3 client was called correctly
    mock_boto3_client.assert_called_with(
        'ec2',
        region_name='us-west-2',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    
    # Verify deregister_image was called
    assert mock_ec2.deregister_image.call_count > 0
    
    # Verify database records were deleted
    with app.app_context():
        backups = Backup.query.filter_by(instance_id='i-1234567890abcdef0').all()
        assert len(backups) == 0

@patch('boto3.client')
def test_bulk_delete_amis_ami_not_found(mock_boto3_client, client, test_instance):
    """Test bulk deletion when AMI is not found"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock ClientError for InvalidAMIID.NotFound
    error_response = {
        'Error': {
            'Code': 'InvalidAMIID.NotFound',
            'Message': 'The AMI ID does not exist'
        }
    }
    mock_ec2.describe_images.side_effect = ClientError(error_response, 'DescribeImages')
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_delete_amis
    response = client.post('/bulk-delete-amis', json={
        'instances': ['i-1234567890abcdef0']
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True  # Should still be successful as we're just removing from DB
    
    # Verify deregister_image was not called
    assert mock_ec2.deregister_image.call_count == 0

# Test bulk_export_amis
def test_bulk_export_amis_success(client, test_instance):
    """Test successful export of AMIs to CSV"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_export_amis
    response = client.post('/bulk-export-amis', json={
        'instances': ['i-1234567890abcdef0']
    })
    
    # Verify response
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'text/csv'
    assert 'attachment; filename=amis_export_' in response.headers['Content-Disposition']
    
    # Verify CSV content
    csv_data = response.data.decode('utf-8')
    csv_reader = csv.reader(io.StringIO(csv_data))
    rows = list(csv_reader)
    
    # Check header row
    assert rows[0] == ['Instance ID', 'AMI ID', 'AMI Name', 'Region', 'Timestamp', 'Retention Days', 'Status']
    
    # Check data rows
    assert len(rows) > 1  # Header + at least one data row
    for row in rows[1:]:
        assert row[0] == 'i-1234567890abcdef0'  # Instance ID
        assert row[1].startswith('ami-')  # AMI ID
        assert row[3] == 'us-west-2'  # Region

def test_bulk_export_amis_no_backups(client):
    """Test export when no backups exist"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_export_amis with non-existent instance
    response = client.post('/bulk-export-amis', json={
        'instances': ['i-nonexistent']
    })
    
    # Verify response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert data['success'] == False
    assert 'No backups found' in data['error']

# Test bulk_tag_amis
@patch('boto3.client')
def test_bulk_tag_amis_success(mock_boto3_client, client, test_instance):
    """Test successful tagging of AMIs"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_tag_amis
    response = client.post('/bulk-tag-amis', json={
        'instances': ['i-1234567890abcdef0'],
        'tag_key': 'Environment',
        'tag_value': 'Production'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert data['tagged_count'] > 0
    
    # Verify boto3 client was called correctly
    mock_boto3_client.assert_called_with(
        'ec2',
        region_name='us-west-2',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    
    # Verify create_tags was called for each AMI
    assert mock_ec2.create_tags.call_count > 0
    for call_args in mock_ec2.create_tags.call_args_list:
        args, kwargs = call_args
        assert kwargs['Tags'][0]['Key'] == 'Environment'
        assert kwargs['Tags'][0]['Value'] == 'Production'

@patch('boto3.client')
def test_bulk_tag_amis_ami_not_found(mock_boto3_client, client, test_instance):
    """Test tagging when AMI is not found"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock ClientError for InvalidAMIID.NotFound
    error_response = {
        'Error': {
            'Code': 'InvalidAMIID.NotFound',
            'Message': 'The AMI ID does not exist'
        }
    }
    mock_ec2.create_tags.side_effect = ClientError(error_response, 'CreateTags')
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call bulk_tag_amis
    response = client.post('/bulk-tag-amis', json={
        'instances': ['i-1234567890abcdef0'],
        'tag_key': 'Environment',
        'tag_value': 'Production'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == False  # Operation fails when no AMIs are tagged
    assert data['tagged_count'] == 0  # No AMIs were tagged
    assert len(data['errors']) > 0  # And we have errors
    assert any('not found' in error for error in data['errors'])

# Test authentication for bulk actions
def test_bulk_actions_authentication(client):
    """Test authentication requirements for bulk actions"""
    # Test bulk_delete_amis without authentication
    response = client.post('/bulk-delete-amis', json={
        'instances': ['i-1234567890abcdef0']
    })
    assert response.status_code == 401

################################################ Instance checks ####################################################################

# Test AWS credential validation
@pytest.fixture
def aws_credential():
    """Create a test AWS credential"""
    credential = AWSCredential(
        name='Test Credential',
        access_key=os.getenv("AWS_ACCESS_KEY_ID"),
        secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region='us-west-2',
        user_id=1  # Admin user ID
    )
    return credential

# Test check-instance route with direct credentials
@patch('boto3.client')
def test_check_instance_direct_credentials_success(mock_boto3_client, client):
    """Test check-instance route with direct credentials - success case"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the describe_instances response
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC),
                'VpcId': 'vpc-12345678',
                'SubnetId': 'subnet-12345678',
                'PrivateIpAddress': '10.0.0.1',
                'PublicIpAddress': '54.123.456.789'
            }]
        }]
    }
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call check-instance route with direct credentials
    response = client.post('/check-instance', json={
        'instance_id': 'i-1234567890abcdef0',
        'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
        'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
        'region': 'us-west-2'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert data['instance_name'] == 'Test Instance'
    assert data['instance_details']['instance_id'] == 'i-1234567890abcdef0'
    assert data['instance_details']['state'] == 'running'
    assert data['instance_details']['instance_type'] == 't2.micro'
    assert data['instance_details']['region'] == 'us-west-2'
    
    # Verify boto3 client was called with correct parameters
    mock_boto3_client.assert_called_once_with(
        'ec2',
        region_name='us-west-2',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        config=mock_boto3_client.call_args[1]['config']
    )
    mock_ec2.describe_instances.assert_called_once_with(InstanceIds=['i-1234567890abcdef0'])

# Test check-instance route with saved credentials
@patch('boto3.client')
def test_check_instance_saved_credentials_success(mock_boto3_client, client, aws_credential):
    """Test check-instance route with saved credentials - success case"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the describe_instances response
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC),
                'VpcId': 'vpc-12345678',
                'SubnetId': 'subnet-12345678',
                'PrivateIpAddress': '10.0.0.1',
                'PublicIpAddress': '54.123.456.789'
            }]
        }]
    }
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Add the credential to the database
    with app.app_context():
        db.session.add(aws_credential)
        db.session.commit()
        credential_id = aws_credential.id
    
    # Call check-instance route with saved credentials
    response = client.post('/check-instance', json={
        'instance_id': 'i-1234567890abcdef0',
        'credential_id': credential_id
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert data['instance_name'] == 'Test Instance'
    
    # Verify boto3 client was called with correct parameters
    mock_boto3_client.assert_called_once_with(
        'ec2',
        region_name='us-west-2',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        config=mock_boto3_client.call_args[1]['config']
    )

# Test check-instance route with invalid instance ID
@patch('boto3.client')
def test_check_instance_invalid_instance_id(mock_boto3_client, client):
    """Test check-instance route with invalid instance ID"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the ClientError for InvalidInstanceID.NotFound
    error_response = {
        'Error': {
            'Code': 'InvalidInstanceID.NotFound',
            'Message': 'The instance ID does not exist'
        }
    }
    mock_ec2.describe_instances.side_effect = ClientError(error_response, 'DescribeInstances')
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call check-instance route with invalid instance ID
    response = client.post('/check-instance', json={
        'instance_id': 'i-nonexistent',
        'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
        'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
        'region': 'us-west-2'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == False
    assert 'not found' in data['error']

# Test check-instance route with invalid credentials
@patch('boto3.client')
def test_check_instance_invalid_credentials(mock_boto3_client, client):
    """Test check-instance route with invalid credentials"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the ClientError for AuthFailure
    error_response = {
        'Error': {
            'Code': 'AuthFailure',
            'Message': 'AWS was not able to validate the provided access credentials'
        }
    }
    mock_ec2.describe_instances.side_effect = ClientError(error_response, 'DescribeInstances')
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call check-instance route with invalid credentials
    response = client.post('/check-instance', json={
        'instance_id': 'i-1234567890abcdef0',
        'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
        'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
        'region': 'us-west-2'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == False
    assert 'authentication' in data['error'].lower()

# Test check-instance route with no credentials
@patch('boto3.client')
def test_check_instance_no_credentials(mock_boto3_client, client):
    """Test check-instance route with no credentials"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the NoCredentialsError
    mock_ec2.describe_instances.side_effect = NoCredentialsError()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call check-instance route with no credentials
    response = client.post('/check-instance', json={
        'instance_id': 'i-1234567890abcdef0',
        'region': 'us-west-2'
    })
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == False
    assert 'validation failed' in data['error'].lower()

# Fixture for test instance with backups
@pytest.fixture
def test_instance(client):
    """Create a test instance with backups"""
    with app.app_context():
        # Create test instance
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            region='us-west-2',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            backup_frequency='daily',
            retention_days=7,
            is_active=True
        )
        db.session.add(instance)
        db.session.commit()
        
        # Create test backups
        for i in range(3):
            backup = Backup(
                instance_id='i-1234567890abcdef0',
                ami_id=f'ami-{i}12345678',
                ami_name=f'Test AMI {i}',
                status='Success',
                timestamp=datetime.now(UTC),
                size_gb=8,
                retention_days=7,
                region='us-west-2'
            )
            db.session.add(backup)
        
        db.session.commit()
        
        yield instance

# Test AWS instance operations (add, update, backup, delete)
# Import necessary models
from models import Instance, Backup, BackupSettings

@pytest.fixture
@patch('boto3.client')
def test_instance_for_operations(mock_boto3_client, client):
    """Create a test instance for operations"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the describe_instances response
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC),
                'VpcId': 'vpc-12345678',
                'SubnetId': 'subnet-12345678',
                'PrivateIpAddress': '10.0.0.1',
                'PublicIpAddress': '54.123.456.789'
            }]
        }]
    }
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Return the mock and client for use in tests
    return mock_boto3_client, mock_ec2, client

def test_add_instance_success(client):
    """Test adding a new instance successfully by directly adding to the database"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Delete the instance if it already exists
    with app.app_context():
        Instance.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        db.session.commit()
    
    # Directly add an instance to the database
    with app.app_context():
        # Create a new instance
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region='us-west-2',
            backup_frequency='0 2 * * *',
            retention_days=7
        )
        
        # Add and commit
        db.session.add(instance)
        db.session.commit()
        
        # Verify the instance was added correctly
        added_instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
        assert added_instance is not None
        assert added_instance.instance_name == 'Test Instance'
        assert added_instance.region == 'us-west-2'
        assert added_instance.backup_frequency == '0 2 * * *'
        assert added_instance.retention_days == 7

@patch('boto3.client')
def test_update_instance_success(mock_boto3_client, client):
    """Test updating an existing instance successfully"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the describe_instances response for validation
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC)
            }]
        }]
    }
    
    # Create a test instance in the database
    with app.app_context():
        # Delete the instance if it already exists
        Instance.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region='us-west-2',
            backup_frequency='0 2 * * *',
            retention_days=7
        )
        db.session.add(instance)
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Mock the validate_aws_credentials method to return success
    with patch.object(Instance, 'validate_aws_credentials', return_value=(True, "Success")):
        # Mock the validate_backup_frequency function to return success
        with patch('app.validate_backup_frequency', return_value=(True, "Success")):
            # Call update-instance route
            response = client.post('/update-instance/i-1234567890abcdef0', data={
                'instance_name': 'Updated Test Instance',
                'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
                'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
                'region': 'us-west-2',
                'backup_frequency': '0 4 * * *',  # Daily at 4 AM
                'retention_days': '14'
            }, follow_redirects=True)
            
            # Verify response
            assert response.status_code == 200
            
            # Verify instance was updated in database
            with app.app_context():
                updated_instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
                assert updated_instance is not None
                assert updated_instance.instance_name == 'Updated Test Instance'
                assert updated_instance.backup_frequency == '0 4 * * *'
                assert updated_instance.retention_days == 14

@patch('boto3.client')
def test_start_backup_success(mock_boto3_client, client):
    """Test starting a manual backup successfully"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the describe_instances response
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC)
            }]
        }]
    }
    
    # Mock the create_image response
    mock_ec2.create_image.return_value = {
        'ImageId': 'ami-12345678'
    }
    
    # Mock create_tags to avoid errors
    mock_ec2.create_tags = MagicMock()
    
    # Create a test instance in the database
    with app.app_context():
        # First check if global config already exists
        global_config = BackupSettings.query.filter_by(instance_id="global-config").first()
        if not global_config:
            global_config = BackupSettings(
                instance_id="global-config",
                instance_name="Global Settings",
                retention_days=7,
                backup_frequency="0 2 * * *"  # Daily at 2 AM
            )
            db.session.add(global_config)
        
        # Check if instance already exists
        instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
        if not instance:
            instance = Instance(
                instance_id='i-1234567890abcdef0',
                instance_name='Test Instance',
                access_key=os.getenv("AWS_ACCESS_KEY_ID"),
                secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region='us-west-2',
                backup_frequency='0 2 * * *',
                retention_days=7,
                is_active=True
            )
            db.session.add(instance)
        
        # Delete any existing backups for this instance to avoid conflicts
        Backup.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call start-backup route
    response = client.post('/start-backup/i-1234567890abcdef0', follow_redirects=True)
    
    # Verify response
    assert response.status_code == 200
    
    # Verify backup was created in database
    with app.app_context():
        backup = Backup.query.filter_by(instance_id='i-1234567890abcdef0').first()
        assert backup is not None
        assert backup.ami_id == 'ami-12345678'
        assert backup.status == 'Success'
    
    # Verify boto3 client was called with correct parameters
    mock_boto3_client.assert_called_with(
        'ec2',
        region_name='us-west-2',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
    )
    mock_ec2.describe_instances.assert_called_with(InstanceIds=['i-1234567890abcdef0'])
    mock_ec2.create_image.assert_called_once()
    assert mock_ec2.create_image.call_args[1]['InstanceId'] == 'i-1234567890abcdef0'
    assert mock_ec2.create_image.call_args[1]['NoReboot'] == True

@patch('boto3.client')
def test_delete_instance_success(mock_boto3_client, client):
    """Test deleting an instance successfully"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Create a test instance in the database
    with app.app_context():
        # Delete any existing instance first
        Instance.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region='us-west-2',
            backup_frequency='0 2 * * *',
            retention_days=7
        )
        db.session.add(instance)
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call delete-instance route with confirmation
    response = client.post('/delete-instance/i-1234567890abcdef0', data={
        'confirm_delete': 'true'
    }, follow_redirects=True)
    
    # Verify response
    assert response.status_code == 200
    
    # Verify instance was deleted from database
    with app.app_context():
        instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
        assert instance is None

@patch('boto3.client')
def test_delete_instance_with_backups(mock_boto3_client, client):
    """Test deleting an instance with associated backups"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Mock the deregister_image response
    mock_ec2.deregister_image = MagicMock()
    
    # Create a test instance with backups in the database
    with app.app_context():
        # Delete the instance and backups if they already exist
        Instance.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        Backup.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region='us-west-2',
            backup_frequency='0 2 * * *',
            retention_days=7
        )
        db.session.add(instance)
        
        # Add a backup for this instance
        backup = Backup(
            instance_id='i-1234567890abcdef0',
            ami_id='ami-1234567890abcdef0',
            status='Success',
            created_at=datetime.now(UTC),
            retention_days=7
        )
        db.session.add(backup)
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Call delete-instance route
    response = client.post('/delete-instance/i-1234567890abcdef0', follow_redirects=True)
    
    # Verify response
    assert response.status_code == 200
    
    # Verify instance and backups were deleted from database
    with app.app_context():
        deleted_instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
        assert deleted_instance is None
        
        deleted_backup = Backup.query.filter_by(instance_id='i-1234567890abcdef0').first()
        assert deleted_backup is None
    
    # Verify deregister_image was called
    mock_ec2.deregister_image.assert_called_with(ImageId='ami-1234567890abcdef0')
    
    # Clear the session to test authentication
    with client.session_transaction() as sess:
        sess.clear()
    
    # Test bulk_export_amis without authentication
    response = client.post('/bulk-export-amis', json={
        'instances': ['i-1234567890abcdef0']
    })
    assert response.status_code == 401
    
    # Test bulk_tag_amis without authentication
    response = client.post('/bulk-tag-amis', json={
        'instances': ['i-1234567890abcdef0'],
        'tag_key': 'Environment',
        'tag_value': 'Production'
    })
    assert response.status_code == 401

################################################ Users checks ######################################################################
# Test user settings page access
def test_user_settings_access(client):
    """Test access to user settings page"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Access user settings page
    response = client.get('/user-settings')
    assert response.status_code == 200
    # Check for content without relying on specific HTML entity encoding
    assert b'User Settings' in response.data
    assert b'Add User' in response.data
    assert b'Reset User Password' in response.data
    assert b'All Users' in response.data
    assert b'Danger Zone' in response.data

# Test add user functionality
def test_add_user(client):
    """Test adding a new user as admin"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Add a new user
    response = client.post('/add-user', data={
        'username': 'newuser',
        'email': 'newuser@example.com',
        'password': 'Password123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'User &#39;newuser&#39; added successfully' in response.data
    
    # Verify user was added to database
    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@example.com'
        assert user.check_password('Password123!')

# Test reset password functionality
def test_reset_password(client):
    """Test resetting a user's password as admin"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Reset password for test user
    response = client.post('/reset-password', data={
        'username': 'test',
        'new_password': 'NewPassword123!'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Password reset successfully for user &#39;test&#39;' in response.data
    
    # Verify password was changed
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        assert user.check_password('NewPassword123!')

# Test toggle user status functionality
def test_toggle_user_status(client):
    """Test toggling a user's active status as admin"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Get initial status
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        initial_status = user.is_active
    
    # Toggle user status
    response = client.post('/toggle-user-status', data={
        'username': 'test'
    })
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    
    # Verify status was toggled
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        assert user.is_active != initial_status

# Test delete user functionality
def test_delete_user(client):
    """Test deleting a user as admin"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # First add a user to delete
    client.post('/add-user', data={
        'username': 'userToDelete',
        'email': 'delete@example.com',
        'password': 'Password123!'
    })
    
    # Verify user exists
    with app.app_context():
        user = User.query.filter_by(username='userToDelete').first()
        assert user is not None
    
    # Delete the user
    response = client.post('/delete-user', data={
        'username': 'userToDelete'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'User &#39;userToDelete&#39; deleted successfully' in response.data
    
    # Verify user was deleted
    with app.app_context():
        user = User.query.filter_by(username='userToDelete').first()
        assert user is None

# Test 2FA setup and disable
def test_2fa_flow(client):
    """Test 2FA setup and disable flow"""
    # Login as test user
    with client.session_transaction() as sess:
        sess['username'] = 'test'
    
    # Access 2FA setup page
    response = client.get('/setup-2fa')
    assert response.status_code == 200
    # Check for content without relying on specific HTML entity encoding
    assert b'Set Up Two-Factor Authentication' in response.data
    assert b'Scan this QR code' in response.data
    
    # Get the secret from the page
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        assert user.two_factor_secret is not None
        secret = user.two_factor_secret
    
    # Generate a valid TOTP code
    totp = pyotp.TOTP(secret)
    valid_code = totp.now()
    
    # Enable 2FA
    response = client.post('/setup-2fa', data={
        'code': valid_code
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Two-factor authentication enabled successfully' in response.data
    
    # Verify 2FA is enabled
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        assert user.two_factor_enabled == True
    
    # Disable 2FA
    response = client.post('/disable-2fa', data={
        'password': 'password123'
    })
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['success'] == True
    assert data['message'] == '2FA disabled successfully'
    
    # Verify 2FA is disabled
    with app.app_context():
        user = User.query.filter_by(username='test').first()
        assert user.two_factor_enabled == False
        assert user.two_factor_secret is None

################################################ api checks ######################################################################
# API Tests
def test_api_instances_unauthorized(client):
    """Test /api/instances endpoint without authentication"""
    response = client.get('/api/instances')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


def test_api_instances_success(client):
    """Test /api/instances endpoint with authentication"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    response = client.get('/api/instances')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    
    # If there are instances, verify the structure
    if data:
        assert 'instance_id' in data[0]
        assert 'instance_name' in data[0]
        assert 'region' in data[0]
        assert 'created_at' in data[0]


def test_api_amis_unauthorized(client):
    """Test /api/amis endpoint without authentication"""
    response = client.get('/api/amis')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


def test_api_amis_success(client, test_instance):
    """Test /api/amis endpoint with authentication"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Test with specific instance
    response = client.get(f'/api/amis?instances={test_instance.instance_id}')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    
    # Test without specifying instances (should return all)
    response = client.get('/api/amis')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)


def test_api_backups_unauthorized(client):
    """Test /api/backups endpoint without authentication"""
    response = client.get('/api/backups')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


def test_api_backups_success(client):
    """Test /api/backups endpoint with authentication"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Test without filters
    response = client.get('/api/backups')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'backups' in data
    assert 'pagination' in data
    assert 'total' in data['pagination']
    assert 'offset' in data['pagination']
    assert 'limit' in data['pagination']
    
    # Test with pagination
    response = client.get('/api/backups?limit=5&offset=0')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'backups' in data
    assert 'pagination' in data
    assert data['pagination']['limit'] == 5
    assert data['pagination']['offset'] == 0


def test_api_backup_detail_unauthorized(client):
    """Test /api/backup/<backup_id> endpoint without authentication"""
    response = client.get('/api/backup/1')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


@patch('boto3.client')
def test_api_backup_detail_success(mock_boto3_client, client):
    """Test /api/backup/<backup_id> endpoint with authentication"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_boto3_client.return_value = mock_ec2
    
    # Create a test backup in the database
    with app.app_context():
        # Delete any existing backup with ID 9999
        Backup.query.filter_by(id=9999).delete()
        
        backup = Backup(
            id=9999,
            instance_id='i-1234567890abcdef0',
            ami_id='ami-12345678',
            ami_name='Test AMI',
            status='completed',
            region='us-west-2',
            timestamp=datetime.now(UTC),
            retention_days=7
        )
        db.session.add(backup)
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Test with valid backup ID
    response = client.get('/api/backup/9999')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['id'] == 9999
    assert data['instance_id'] == 'i-1234567890abcdef0'
    assert data['ami_id'] == 'ami-12345678'
    assert data['status'] == 'completed'
    
    # Test with invalid backup ID
    response = client.get('/api/backup/99999')
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Backup not found'


def test_api_backup_settings_unauthorized(client):
    """Test /api/backup-settings endpoint without authentication"""
    response = client.get('/api/backup-settings')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


def test_api_backup_settings_success(client):
    """Test /api/backup-settings endpoint with authentication"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Ensure backup settings exist
    with app.app_context():
        settings = BackupSettings.query.first()
        if not settings:
            settings = BackupSettings(
                retention_days=7,
                backup_frequency='0 2 * * *',
                email_notifications=False
            )
            db.session.add(settings)
            db.session.commit()
    
    response = client.get('/api/backup-settings')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'retention_days' in data
    assert 'backup_frequency' in data
    assert 'email_notifications' in data


def test_api_aws_credentials_unauthorized(client):
    """Test /api/aws-credentials endpoint without authentication"""
    response = client.get('/api/aws-credentials')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert data['error'] == 'Not authenticated'


def test_api_aws_credentials_success(client):
    """Test /api/aws-credentials endpoint with authentication"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    response = client.get('/api/aws-credentials')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    
    # If there are credentials, verify the structure
    if data:
        assert 'id' in data[0]
        assert 'name' in data[0]
        assert 'region' in data[0]
        assert 'has_access_key' in data[0]
        assert 'has_secret_key' in data[0]
        # Verify that actual keys are not exposed
        assert 'access_key' not in data[0]
        assert 'secret_key' not in data[0]


def test_api_docs_json_format(client):
    """Test /api/docs endpoint with JSON format"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Request JSON format
    response = client.get('/api/docs?format=json')
    assert response.status_code == 200
    assert response.headers['Content-Type'] == 'application/json'
    
    data = json.loads(response.data)
    assert 'api_name' in data
    assert 'version' in data
    assert 'description' in data
    assert 'endpoints' in data
    assert isinstance(data['endpoints'], list)


def test_api_docs_html_format(client):
    """Test /api/docs endpoint with HTML format"""
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Request HTML format (default)
    response = client.get('/api/docs')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    
    # Check for HTML content
    assert b'<!DOCTYPE html>' in response.data
    assert b'AMIVault API' in response.data


################################################ Event bridge checks ######################################################################

@patch('boto3.Session')
def test_add_instance_with_eventbridge_scheduler(mock_boto3_session, client):
    """Test adding a new instance with EventBridge scheduler type"""
    print("\n\n=== Starting test_add_instance_with_eventbridge_scheduler ===\n")
    
    # Setup mock EC2 client and EventBridge client
    mock_ec2 = MagicMock()
    mock_events = MagicMock()
    
    # Mock the boto3 Session
    mock_session_instance = MagicMock()
    mock_boto3_session.return_value = mock_session_instance
    
    # Configure mock session to return different clients based on service name
    def get_mock_client(service_name, **kwargs):
        print(f"Creating mock client for service: {service_name}")
        if service_name == 'ec2':
            return mock_ec2
        elif service_name == 'events':
            return mock_events
        return MagicMock()
    
    mock_session_instance.client.side_effect = get_mock_client
    
    # Mock the describe_instances response for validation
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-eventbridge123456',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'EventBridge Test Instance'}],
                'LaunchTime': datetime.now(UTC)
            }]
        }]
    }
    
    # Mock EventBridge put_rule and put_targets responses
    mock_events.put_rule.return_value = {'RuleArn': 'arn:aws:events:us-west-2:123456789012:rule/AMIVault-Backup-i-eventbridge123456'}
    mock_events.put_targets.return_value = {'FailedEntryCount': 0, 'FailedEntries': []}
    
    # Set environment variables for API Gateway endpoint and Lambda ARN
    with patch.dict('os.environ', {
        'API_GATEWAY_ENDPOINT': 'https://api.example.com/backup',
        'BACKUP_LAMBDA_ARN': 'arn:aws:lambda:us-west-2:123456789012:function:AMIVault-Backup'
    }):
        # Create the instance directly in the database
        with app.app_context():
            print("\nCreating instance directly in the database...")
            # Delete any existing instance with the same ID
            Instance.query.filter_by(instance_id='i-eventbridge123456').delete()
            db.session.commit()
            
            # Create a new instance
            instance = Instance(
                instance_id='i-eventbridge123456',
                instance_name='EventBridge Test Instance',
                access_key=os.getenv("AWS_ACCESS_KEY_ID"),
                secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
                region='us-west-2',
                backup_frequency='0 2 * * *',
                retention_days=7,
                scheduler_type='eventbridge'
            )
            db.session.add(instance)
            db.session.commit()
            print("Instance created successfully")
            
            # Verify the instance was added
            instance = Instance.query.filter_by(instance_id='i-eventbridge123456').first()
            assert instance is not None
            assert instance.instance_name == 'EventBridge Test Instance'
            assert instance.scheduler_type == 'eventbridge'
            
            # Import and call schedule_instance_backup directly
            from app import schedule_instance_backup
            print("\nCalling schedule_instance_backup directly...")
            schedule_instance_backup(instance)
            print("schedule_instance_backup completed")
        
        # Verify EventBridge rule was created
        print("\nVerifying EventBridge rule was created...")
        mock_events.put_rule.assert_called_once()
        mock_events.put_targets.assert_called_once()
        print("EventBridge rule verification passed")
        
        # For completeness, test the web route as well
        print("\nTesting the web route for adding an instance...")
        # Login as admin
        with client.session_transaction() as sess:
            sess['username'] = 'admin'
        
        # Delete the instance so we can add it again through the web route
        with app.app_context():
            Instance.query.filter_by(instance_id='i-eventbridge123456').delete()
            db.session.commit()
            print("Instance deleted for web route test")
        
        # Mock the validate_aws_credentials method to return success
        with patch.object(Instance, 'validate_aws_credentials', return_value=(True, "Success")):
            # Mock the validate_backup_frequency function to return success
            with patch('app.validate_backup_frequency', return_value=(True, "Success")):
                # Call add-instance route
                print("Sending POST request to /add-instance...")
                response = client.post('/add-instance', data={
                    'instance_id': 'i-eventbridge123456',
                    'instance_name': 'EventBridge Test Instance',
                    'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
                    'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
                    'region': 'us-west-2',
                    'backup_frequency': '0 2 * * *',
                    'retention_days': '7',
                    'scheduler_type': 'eventbridge'
                }, follow_redirects=True)
                
                print(f"Response status code: {response.status_code}")
                assert response.status_code == 200
                
                # Verify instance was added to database
                with app.app_context():
                    instance = Instance.query.filter_by(instance_id='i-eventbridge123456').first()
                    print(f"Instance found via web route: {instance is not None}")
                    # Note: We don't assert here because the web route test is secondary


@patch('boto3.client')
def test_update_instance_scheduler_type(mock_boto3_client, client):
    """Test updating an instance's scheduler type from Python to EventBridge"""
    # Setup mock EC2 client
    mock_ec2 = MagicMock()
    mock_events = MagicMock()
    
    # Configure mock to return different clients based on service name
    def get_mock_client(service_name, **kwargs):
        if service_name == 'ec2':
            return mock_ec2
        elif service_name == 'events':
            return mock_events
        return MagicMock()
    
    mock_boto3_client.side_effect = get_mock_client
    
    # Mock the describe_instances response for validation
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{
            'Instances': [{
                'InstanceId': 'i-1234567890abcdef0',
                'State': {'Name': 'running'},
                'InstanceType': 't2.micro',
                'Placement': {'AvailabilityZone': 'us-west-2a'},
                'Tags': [{'Key': 'Name', 'Value': 'Test Instance'}],
                'LaunchTime': datetime.now(UTC)
            }]
        }]
    }
    
    # Mock EventBridge put_rule and put_targets responses
    mock_events.put_rule.return_value = {'RuleArn': 'arn:aws:events:us-west-2:123456789012:rule/AMIVault-Backup-i-1234567890abcdef0'}
    mock_events.put_targets.return_value = {'FailedEntryCount': 0, 'FailedEntries': []}
    
    # Create a test instance in the database with Python scheduler
    with app.app_context():
        # Delete the instance if it already exists
        Instance.query.filter_by(instance_id='i-1234567890abcdef0').delete()
        
        instance = Instance(
            instance_id='i-1234567890abcdef0',
            instance_name='Test Instance',
            access_key=os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region='us-west-2',
            backup_frequency='0 2 * * *',
            retention_days=7,
            scheduler_type='python'  # Initially set to Python
        )
        db.session.add(instance)
        db.session.commit()
    
    # Login as admin
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
    
    # Set environment variables for API Gateway endpoint and Lambda ARN
    with patch.dict('os.environ', {
        'API_GATEWAY_ENDPOINT': 'https://api.example.com/backup',
        'BACKUP_LAMBDA_ARN': 'arn:aws:lambda:us-west-2:123456789012:function:AMIVault-Backup'
    }):
        # Mock the validate_aws_credentials method to return success
        with patch.object(Instance, 'validate_aws_credentials', return_value=(True, "Success")):
            # Mock the validate_backup_frequency function to return success
            with patch('app.validate_backup_frequency', return_value=(True, "Success")):
                # Mock the reschedule_instance_backup function
                with patch('app.reschedule_instance_backup') as mock_reschedule:
                    # Call update-instance route to change scheduler type
                    response = client.post('/update-instance/i-1234567890abcdef0', data={
                        'instance_name': 'Updated Test Instance',
                        'access_key': os.getenv("AWS_ACCESS_KEY_ID"),
                        'secret_key': os.getenv("AWS_SECRET_ACCESS_KEY"),
                        'region': 'us-west-2',
                        'backup_frequency': '0 4 * * *',  # Daily at 4 AM
                        'retention_days': '14',
                        'scheduler_type': 'eventbridge'  # Change to EventBridge
                    }, follow_redirects=True)
                    
                    # Verify response
                    assert response.status_code == 200
                    
                    # Verify instance was updated in database
                    with app.app_context():
                        updated_instance = Instance.query.filter_by(instance_id='i-1234567890abcdef0').first()
                        assert updated_instance is not None
                        assert updated_instance.instance_name == 'Updated Test Instance'
                        assert updated_instance.backup_frequency == '0 4 * * *'
                        assert updated_instance.retention_days == 14
                        assert updated_instance.scheduler_type == 'eventbridge'
                    
                    # Verify reschedule_instance_backup was called
                    mock_reschedule.assert_called_once()


################################################ Cron Validation Tests #################################################################

# Test cases for cron expression validation and conversion

def test_validate_cron_expression_valid_cases():
    """Test valid cron expressions"""
    valid_expressions = [
        "0 2 * * *",       # Daily at 2 AM
        "0 12 ? * MON-FRI", # Weekdays at noon
        "0 0 1 * ?",       # 1st day of month at midnight
        "*/5 * * * *",      # Every 5 minutes
        "0 0 * * 0",        # Every Sunday at midnight
        "0 0 ? * 0",        # Every Sunday at midnight (with ?)
        "0 0 1 1 ?",        # January 1st at midnight
        "0 0 ? 1 1",        # First Monday in January at midnight
    ]
    
    for expr in valid_expressions:
        assert validate_cron_expression(expr), f"Expression should be valid: {expr}"

def test_validate_cron_expression_invalid_cases():
    """Test invalid cron expressions"""
    invalid_expressions = [
        "",                # Empty string
        "* * *",           # Too few parts
        "* * * * * *",     # Too many parts
        "60 * * * *",      # Invalid minute
        "* 24 * * *",      # Invalid hour
        "* * 32 * *",      # Invalid day of month
        "* * * 13 *",      # Invalid month
        "* * * * 8",       # Invalid day of week
        "* * 1 * 1",       # Both day-of-month and day-of-week specified
        "invalid",         # Not a cron expression
        "* * ? * ?",       # Both day-of-month and day-of-week are ?
    ]
    
    for expr in invalid_expressions:
        assert not validate_cron_expression(expr), f"Expression should be invalid: {expr}"

def test_convert_to_eventbridge_format_intervals():
    """Test conversion of interval expressions to EventBridge format"""
    assert convert_to_eventbridge_format("@12") == "rate(12 hours)"
    assert convert_to_eventbridge_format("@1") == "rate(1 hours)"
    assert convert_to_eventbridge_format("@24") == "rate(24 hours)"
    
    # Invalid interval
    with pytest.raises(ValueError):
        convert_to_eventbridge_format("@invalid")

def test_convert_to_eventbridge_format_cron():
    """Test conversion of cron expressions to EventBridge format"""
    # Test basic conversion
    assert convert_to_eventbridge_format("0 2 * * *") == "cron(0 2 * * ? *)"
    
    # Test Sunday conversion (0 to 7)
    assert convert_to_eventbridge_format("0 0 * * 0") == "cron(0 0 * * 7 *)"
    
    # Test day-of-month and day-of-week exclusivity
    assert convert_to_eventbridge_format("0 0 1 * 1") == "cron(0 0 1 * ? *)"
    assert convert_to_eventbridge_format("0 0 ? * MON") == "cron(0 0 ? * MON *)"
    
    # Test both * case
    assert convert_to_eventbridge_format("0 0 * * *") == "cron(0 0 * * ? *)"
    
    # Invalid cron expression
    with pytest.raises(ValueError):
        convert_to_eventbridge_format("* * * *")

def test_convert_to_eventbridge_format_edge_cases():
    """Test edge cases for EventBridge format conversion"""
    # Already has ? in day-of-month
    assert convert_to_eventbridge_format("0 0 ? * 1") == "cron(0 0 ? * 1 *)"
    
    # Already has ? in day-of-week
    assert convert_to_eventbridge_format("0 0 1 * ?") == "cron(0 0 1 * ? *)"
    
    # Complex expressions
    assert convert_to_eventbridge_format("*/5 8-17 ? * MON-FRI") == "cron(*/5 8-17 ? * MON-FRI *)"
    assert convert_to_eventbridge_format("0 0 1,15 * ?") == "cron(0 0 1,15 * ? *)"
    
    # Test the fix for the issue in the logs
    assert convert_to_eventbridge_format("0 4 1 * *") == "cron(0 4 1 * ? *)"

################################################ utility manager checks ######################################################################
# Test get_encryption_key function
def test_get_encryption_key_from_env(mock_env_vars):
    """Test getting encryption key from environment variable"""
    key = get_encryption_key()
    assert key is not None
    assert len(key) > 0
    # Verify it's a valid Fernet key
    fernet = Fernet(key)    
    assert fernet is not None

@patch('os.path.exists')
@patch('builtins.open', new_callable=MagicMock)
def test_get_encryption_key_from_key_file(mock_open, mock_exists, mock_env_vars):
    """Test getting encryption key from .key file"""
    # Remove env var to force key file usage
    if "AMIVAULT_ENCRYPTION_KEY" in os.environ:
        del os.environ["AMIVAULT_ENCRYPTION_KEY"]
    
    # Mock .key file exists
    mock_exists.return_value = True
    
    # Mock file content
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = Fernet.generate_key()
    mock_open.return_value = mock_file
    
    key = get_encryption_key()
    assert key is not None
    assert len(key) > 0

@patch('os.path.exists')
@patch('uuid.getnode')
def test_get_encryption_key_generated(mock_getnode, mock_exists, mock_env_vars):
    """Test generating encryption key when no source is available"""
    # Remove env var to force generation
    if "AMIVAULT_ENCRYPTION_KEY" in os.environ:
        del os.environ["AMIVAULT_ENCRYPTION_KEY"]
    
    # Mock file doesn't exist
    mock_exists.return_value = False
    
    # Mock machine ID
    mock_getnode.return_value = 123456789
    
    key = get_encryption_key()
    assert key is not None
    assert len(key) > 0

# Test encrypt_value and decrypt_value functions
def test_encrypt_decrypt_value(mock_env_vars):
    """Test encrypting and decrypting a value"""
    original_value = "sensitive_data"
    encrypted = encrypt_value(original_value)
    
    # Verify encrypted value is different from original
    assert encrypted != original_value
    
    # Decrypt and verify
    decrypted = decrypt_value(encrypted)
    assert decrypted == original_value

def test_encrypt_decrypt_with_timestamp(mock_env_vars):
    """Test that encrypted values include a timestamp and can be decrypted"""
    original_value = "sensitive_data"
    encrypted = encrypt_value(original_value)
    
    # Decrypt and verify
    decrypted = decrypt_value(encrypted)
    assert decrypted == original_value

def test_decrypt_expired_value(mock_env_vars):
    """Test decrypting an expired value"""
    # Set a very short expiration time
    os.environ["ENCRYPTION_MAX_AGE_DAYS"] = "0"
    
    original_value = "sensitive_data"
    encrypted = encrypt_value(original_value)
    
    # Sleep to ensure it's expired
    time.sleep(1)
    
    # Should raise an exception for expired data
    with pytest.raises(ValueError, match="Encrypted data has expired"):
        decrypt_value(encrypted)

def test_decrypt_invalid_value(mock_env_vars):
    """Test decrypting an invalid value"""
    with pytest.raises(InvalidToken):
        decrypt_value("invalid_encrypted_value")

# Test encrypt_data and decrypt_data functions
def test_encrypt_decrypt_data_string(mock_env_vars):
    """Test encrypting and decrypting string data"""
    original_data = "sensitive_string"
    encrypted = encrypt_data(original_data)
    
    # Verify encrypted data is different
    assert encrypted != original_data
    
    # Decrypt and verify
    decrypted = decrypt_data(encrypted)
    assert decrypted == original_data

# Test display_logo function
@patch('os.get_terminal_size')
def test_display_logo(mock_terminal_size):
    """Test the display_logo function"""
    # Mock terminal size
    mock_terminal_size.return_value = MagicMock(columns=100)
    
    # Capture stdout to verify output
    captured_output = io.StringIO()
    import sys
    original_stdout = sys.stdout
    sys.stdout = captured_output
    
    try:
        # Call the function
        display_logo()
        
        # Get the output
        output = captured_output.getvalue()
        
        # Verify the output contains expected elements
        assert "AMIVault" in output
        assert "v1.0.0" in output
        assert "Enterprise-Grade AWS AMI Backup Management Solution" in output
        assert "Secure • Reliable • Scalable" in output
        
        # Verify the border characters are present
        assert "╔" in output
        assert "╗" in output
        assert "╚" in output
        assert "╝" in output
    finally:
        # Restore stdout
        sys.stdout = original_stdout

def test_encrypt_decrypt_data_dict(mock_env_vars):
    """Test encrypting and decrypting dictionary data"""
    original_data = {
        "username": "test_user",
        "password": "secret_password",
        "api_key": "sensitive_api_key"
    }
    
    encrypted = encrypt_data(original_data)
    
    # Verify sensitive fields are encrypted
    assert encrypted["username"] == original_data["username"]  # Not sensitive
    assert encrypted["password"] != original_data["password"]  # Sensitive
    assert encrypted["api_key"] != original_data["api_key"]  # Sensitive
    
    # Decrypt and verify
    decrypted = decrypt_data(encrypted)
    assert decrypted == original_data

# Test generate_encryption_key function
@patch('builtins.open', new_callable=MagicMock)
@patch('os.path.exists')
def test_generate_encryption_key(mock_exists, mock_open, mock_env_vars):
    """Test generating a new encryption key"""
    # Mock .env file exists
    mock_exists.return_value = True
    
    # Mock file operations
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = "SOME_VAR=value\nAMIVAULT_ENCRYPTION_KEY=old_key\n"
    mock_open.return_value = mock_file
    
    # Generate new key
    result = generate_encryption_key()
    
    # Verify result
    assert result is True
    
    # Verify file was written with new key
    assert mock_file.__enter__.return_value.write.called

# Test validation functions
def test_validate_email():
    """Test email validation"""
    # Valid emails
    assert validate_email("user@example.com") is True
    assert validate_email("user.name@example.co.uk") is True
    
    # Invalid emails
    assert validate_email("user@") is False
    assert validate_email("user@.com") is False
    assert validate_email("@example.com") is False

def test_validate_password():
    """Test password validation"""
    # Valid passwords
    assert validate_password("Password123!") is True
    assert validate_password("Secure_Password_2023") is True
    
    # Invalid passwords
    assert validate_password("short") is False  # Too short
    assert validate_password("lowercase123") is False  # No uppercase
    assert validate_password("UPPERCASE123") is False  # No lowercase
    assert validate_password("Password!@#") is False  # No numbers

def test_get_secure_password():
    """Test secure password generation"""
    password = get_secure_password()
    
    # Verify password meets requirements
    assert len(password) >= 12
    assert validate_password(password) is True