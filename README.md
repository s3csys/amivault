# AMIVault

AMIVault is a professional Flask-based web application for managing AWS EC2 AMI backups and schedules. It provides a secure, user-friendly dashboard to automate, view, and control AMI creation, deletion, and backup scheduling across multiple AWS accounts and regions.

![AMIVault Dashboard](https://via.placeholder.com/800x400?text=AMIVault+Dashboard)

---

## Features

- **Automated AMI Backups:**  
  Schedule and manage EC2 AMI backups with persistent job storage using APScheduler and SQLAlchemy. Support for both Python scheduler and AWS EventBridge.

- **Dashboard Interface:**  
  View, search, and manage all backups and schedules from a responsive web dashboard with real-time status updates.

- **Secure AMI Deletion:**  
  Deregister AMIs and delete associated snapshots, with credential prompts if instance records are missing.

- **Credential Management:**  
  AWS credentials are securely stored with proper encryption. Option to use temporary credentials for one-time operations.

- **User Management:**  
  Complete user authentication system with role-based access control, two-factor authentication (2FA), and account management.

- **Robust Error Handling:**  
  Comprehensive logging and error management with detailed feedback for all operations.

- **Extensible Codebase:**  
  Organized into modular, self-contained sections for easy integration and future expansion.

- **Multi-Region Support:**  
  Manage EC2 instances across multiple AWS regions from a single interface.

- **Backup Retention Policies:**  
  Configure custom retention periods for each instance to automatically clean up old AMIs.

---

## Tech Stack

- **Backend:** 
  - Flask 2.3.2 - Web framework
  - Flask-SQLAlchemy 3.1.1 - ORM for database operations
  - Flask-APScheduler 1.13.1 - Job scheduling
  - boto3 1.28.22 - AWS SDK for Python
  - pyotp 2.9.0 - Two-factor authentication

- **Frontend:** 
  - Bootstrap 5 - Responsive UI framework
  - SweetAlert2 - Enhanced alerts and modals
  - Jinja2 3.1.2 - Template engine

- **Security:**
  - Werkzeug 2.3.7 - Password hashing and security utilities
  - QR code generation for 2FA setup

- **Database:** 
  - SQLite (default, easily extendable to PostgreSQL/MySQL)

- **Python Version:** 3.8+

---

## Getting Started

### Prerequisites

- Python 3.8 or newer
- pip package manager
- AWS account with appropriate permissions for EC2 management

### Installation

1. **Clone the Repository**
```bash
git clone https://github.com/s3csys/amivault.git
cd amivault
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure Environment Variables**

Create a `.env` file in the root directory with the following variables:

```
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development  # Change to 'production' for production deployment
SECRET_KEY=your_secure_secret_key  # Generate a strong random key

# Admin Account
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password  # Change from default
ADMIN_EMAIL=admin@example.com

# Logging Configuration
LOG_LEVEL=INFO
LOG_DIR=logs
```

4. **Initialize the Database**
```bash
python -c "from app import app, db; app.app_context().push(); db.create_all()"
```

5. **Run the Application**
```bash
python app.py
```

The app will be available at [http://localhost:8080/](http://localhost:8080/)

### Default Admin Account

If you don't set custom admin credentials in the `.env` file, the system will create:

- **Username:** `admin`
- **Password:** `your_secure_password`  

**⚠️ IMPORTANT:** Change the default password immediately in production environments!

---

## Usage Guide

### Dashboard

- **Main Dashboard:** Access `/` to view summary statistics and recent activity
- **Instances Management:** Add, edit, and delete EC2 instances for backup management
- **Backups Overview:** View all AMI backups with filtering and search capabilities

### Managing Instances

1. **Add Instance:**
   - Navigate to the Instances page
   - Click "Add Instance"
   - Enter AWS instance details including ID, region, and credentials
   - Set backup frequency (supports cron expressions or preset schedules)
   - Set retention period for automatic cleanup

2. **Edit Instance:**
   - Click the edit icon next to any instance
   - Update details as needed
   - Save changes

3. **Delete Instance:**
   - Click the delete icon next to any instance
   - Confirm deletion (this will not affect the actual EC2 instance)

### Managing Backups

1. **Create Manual Backup:**
   - Navigate to the instance details page
   - Click "Create Backup Now"
   - Enter an optional description

2. **View Backup Details:**
   - Click on any backup in the list to view details
   - See creation date, status, and associated snapshots

3. **Delete Backup:**
   - Click the delete icon next to any backup
   - Choose whether to delete associated snapshots
   - Confirm deletion

### User Management

1. **Enable Two-Factor Authentication:**
   - Navigate to user settings
   - Click "Enable 2FA"
   - Scan the QR code with an authenticator app
   - Enter the verification code to confirm

2. **User Settings:**
   - Change password
   - Update email address
   - Manage 2FA settings

---

## Advanced Configuration

### Scheduler Options

AMIVault supports two scheduler types:

1. **Python Scheduler (Default):**
   - Runs within the application process
   - Suitable for single-server deployments
   - Configure with `scheduler_type='python'` in instance settings

2. **AWS EventBridge:**
   - Uses AWS EventBridge for scheduling
   - Better for distributed deployments
   - Configure with `scheduler_type='eventbridge'` in instance settings

### Backup Frequency

Supports both cron expressions and interval notation:

- **Cron Expression:** `0 2 * * *` (Daily at 2 AM)
- **Interval Notation:** `daily`, `weekly`, `monthly`

### Logging

Configure logging behavior through environment variables:

- `LOG_LEVEL`: Sets the logging level (DEBUG, INFO, WARNING, ERROR)
- `LOG_DIR`: Directory for log files
- `LOG_FORMAT`: Custom log format
- `LOG_MAX_BYTES`: Maximum log file size before rotation
- `LOG_BACKUP_COUNT`: Number of backup log files to keep

---

## Deployment

### Docker Deployment

A Dockerfile is included for containerized deployment:

```bash
# Build the Docker image
docker build -t amivault .

# Run the container
docker run -d -p 8080:8080 --name amivault-app amivault
```

### Production Considerations

1. **Database:**
   - For production, consider using PostgreSQL or MySQL instead of SQLite
   - Update the `SQLALCHEMY_DATABASE_URI` in your configuration

2. **Security:**
   - Use HTTPS in production (configure with a reverse proxy like Nginx)
   - Set a strong `SECRET_KEY` environment variable
   - Change default admin credentials
   - Enable 2FA for all admin accounts

3. **Scaling:**
   - For high-availability setups, use AWS EventBridge scheduler
   - Consider using a load balancer for multiple application instances

---

## Testing

AMIVault includes a comprehensive test suite using pytest:

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest test_app.py

# Run with verbose output
python -m pytest -v
```

The test suite covers:
- User authentication and 2FA
- Instance management
- Backup creation and deletion
- Scheduler functionality
- API endpoints

---

## API Documentation

AMIVault provides a RESTful API for integration with other systems:

- **Authentication:** `/api/login` (POST)
- **Instances:** `/api/instances` (GET, POST, PUT, DELETE)
- **Backups:** `/api/backups` (GET, POST, DELETE)
- **Schedules:** `/api/schedules` (GET, POST, PUT, DELETE)

API documentation is available at `/api/docs` when running in development mode.

---

## Security Features

- **Password Security:** Secure password hashing using Werkzeug
- **Two-Factor Authentication:** TOTP-based 2FA with QR code setup
- **Session Management:** Secure session handling with timeout
- **Input Validation:** Comprehensive validation for all user inputs
- **AWS Credential Security:** Proper encryption for stored credentials
- **CSRF Protection:** Cross-Site Request Forgery protection
- **Comprehensive Logging:** Security event logging for audit trails

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/YourFeature`)
3. Run tests to ensure everything works (`python -m pytest`)
4. Commit your changes (`git commit -m 'Add some feature'`)
5. Push to the branch (`git push origin feature/YourFeature`)
6. Open a pull request

### Development Guidelines

- Follow PEP 8 style guidelines
- Write tests for new features
- Update documentation as needed
- Maintain backward compatibility when possible

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Acknowledgments

- Flask and Flask extensions community
- AWS SDK for Python (boto3) team
- Bootstrap and SweetAlert2 for UI components
- All contributors to the project

---

**AMIVault** — Secure, Automated, and Extensible AWS AMI Backup Management.

[Report Issues](https://github.com/s3csys/amivault/issues) | [Request Features](https://github.com/s3csys/amivault/issues)
