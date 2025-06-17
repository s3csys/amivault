import pytest
from app import app, db, User, AWSCredential, Instance
from datetime import datetime, UTC
import json
import pyotp
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///file::memory:?cache=shared' 
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {'check_same_thread': False}
    }#'sqlite:///:memory:'
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            assert 'sqlite:///:memory:'
            db.drop_all()
            db.create_all()
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
            
        yield client
        
        with app.app_context():
            db.session.remove()
            db.drop_all()

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

# Test AWS credential validation
@pytest.fixture
def aws_credential():
    """Create a test AWS credential"""
    credential = AWSCredential(
        name='Test Credential',
        access_key='REMOVED_AWS_KEY',
        secret_key='REMOVED_AWS_SECRET',
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
        'access_key': 'REMOVED_AWS_KEY',
        'secret_key': 'REMOVED_AWS_SECRET',
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
        aws_access_key_id='REMOVED_AWS_KEY',
        aws_secret_access_key='REMOVED_AWS_SECRET',
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
        aws_access_key_id='REMOVED_AWS_KEY',
        aws_secret_access_key='REMOVED_AWS_SECRET',
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
        'access_key': 'REMOVED_AWS_KEY',
        'secret_key': 'REMOVED_AWS_SECRET',
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
        'access_key': 'REMOVED_AWS_KEY',
        'secret_key': 'REMOVED_AWS_SECRET',
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