import pytest
from app import app, db, User
from datetime import datetime, UTC
import json
import pyotp

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
    # Verify we're redirected to login
    response = client.get('/aws-instances', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content
    
    # Verify we can't access protected page
    response = client.get('/backup-settings')
    assert response.status_code == 302  # Redirect to login
    # Verify we're redirected to login
    response = client.get('/backup-settings', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content

    # Verify we can't access protected page
    response = client.get('/schedules')
    assert response.status_code == 302  # Redirect to login
    # Verify we're redirected to login
    response = client.get('/schedules', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content

    # Verify we can't access protected page
    response = client.get('/user-settings')
    assert response.status_code == 302  # Redirect to login
    # Verify we're redirected to login
    response = client.get('/user-settings', follow_redirects=True)
    assert b'Sign in to your account' in response.data  # Check for login page content