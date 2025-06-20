<div align="center">

# AMIVault

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.2-green.svg)](https://flask.palletsprojects.com/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**Professional AWS EC2 AMI Backup Management Solution**

![AMIVault Dashboard](https://via.placeholder.com/800x400?text=AMIVault+Dashboard)

*Secure, automated, and extensible AWS AMI backup management across multiple accounts and regions*

[Features](#features) • [Installation](#getting-started) • [Usage](#usage-guide) • [API](#api-documentation) • [Deployment](#deployment) • [Contributing](#contributing)

</div>

---

## Table of Contents

- [Overview](#amivault)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Default Admin Account](#default-admin-account)
- [Usage Guide](#usage-guide)
  - [Dashboard](#dashboard)
  - [Managing Instances](#managing-instances)
  - [Managing Backups](#managing-backups)
  - [User Management](#user-management)
- [Advanced Configuration](#advanced-configuration)
  - [Scheduler Options](#scheduler-options)
  - [Backup Frequency](#backup-frequency)
  - [Logging](#logging)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Production Considerations](#production-considerations)
- [Testing](#testing)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

---

## Overview

AMIVault is a professional Flask-based web application for managing AWS EC2 AMI backups and schedules. It provides a secure, user-friendly dashboard to automate, view, and control AMI creation, deletion, and backup scheduling across multiple AWS accounts and regions.

## Features

<table>
  <tr>
    <td width="50%">
      <h3>🔄 Automated AMI Backups</h3>
      <p>Schedule and manage EC2 AMI backups with persistent job storage using APScheduler and SQLAlchemy. Support for both Python scheduler and AWS EventBridge.</p>
    </td>
    <td width="50%">
      <h3>📊 Dashboard Interface</h3>
      <p>View, search, and manage all backups and schedules from a responsive web dashboard with real-time status updates.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🔒 Secure AMI Deletion</h3>
      <p>Deregister AMIs and delete associated snapshots, with credential prompts if instance records are missing.</p>
    </td>
    <td width="50%">
      <h3>🔑 Credential Management</h3>
      <p>AWS credentials are securely stored with proper encryption. Option to use temporary credentials for one-time operations.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>👥 User Management</h3>
      <p>Complete user authentication system with role-based access control, two-factor authentication (2FA), and account management.</p>
    </td>
    <td width="50%">
      <h3>⚠️ Robust Error Handling</h3>
      <p>Comprehensive logging and error management with detailed feedback for all operations.</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🧩 Extensible Codebase</h3>
      <p>Organized into modular, self-contained sections for easy integration and future expansion.</p>
    </td>
    <td width="50%">
      <h3>🌎 Multi-Region Support</h3>
      <p>Manage EC2 instances across multiple AWS regions from a single interface.</p>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <h3>⏱️ Backup Retention Policies</h3>
      <p>Configure custom retention periods for each instance to automatically clean up old AMIs.</p>
    </td>
  </tr>
</table>

---

## Tech Stack

<div align="center">

### Core Technologies

| Category | Technologies |
|:--------:|:------------:|
| ![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white) | ![Flask](https://img.shields.io/badge/Flask-2.3.2-green?style=for-the-badge&logo=flask&logoColor=white) |

</div>

### Backend Components

| Component | Description | Version |
|-----------|-------------|:-------:|
| **Flask** | Web framework | 2.3.2 |
| **Flask-SQLAlchemy** | ORM for database operations | 3.1.1 |
| **Flask-APScheduler** | Job scheduling | 1.13.1 |
| **boto3** | AWS SDK for Python | 1.28.22 |
| **pyotp** | Two-factor authentication | 2.9.0 |

### Frontend Components

| Component | Description | Version |
|-----------|-------------|:-------:|
| **Bootstrap** | Responsive UI framework | 5 |
| **SweetAlert2** | Enhanced alerts and modals | Latest |
| **Jinja2** | Template engine | 3.1.2 |

### Security Components

| Component | Description | Version |
|-----------|-------------|:-------:|
| **Werkzeug** | Password hashing and security utilities | 2.3.7 |
| **QR Code Generation** | For 2FA setup | Built-in |

### Database

- **Default:** SQLite (for development)
- **Production Options:** PostgreSQL, MySQL
- **ORM:** SQLAlchemy (database-agnostic)

---

## Getting Started

### Prerequisites

<table>
  <tr>
    <td><b>Requirement</b></td>
    <td><b>Details</b></td>
  </tr>
  <tr>
    <td>Python</td>
    <td>Version 3.8 or newer</td>
  </tr>
  <tr>
    <td>Package Manager</td>
    <td>pip (latest version recommended)</td>
  </tr>
  <tr>
    <td>AWS Account</td>
    <td>With EC2 management permissions</td>
  </tr>
  <tr>
    <td>Storage</td>
    <td>Minimum 100MB free disk space</td>
  </tr>
  <tr>
    <td>Memory</td>
    <td>Minimum 512MB RAM (1GB+ recommended)</td>
  </tr>
</table>

### Installation

<details open>
<summary><b>Step 1: Clone the Repository</b></summary>

```bash
# Clone the repository
git clone https://github.com/s3csys/amivault.git

# Navigate to project directory
cd amivault
```
</details>

<details open>
<summary><b>Step 2: Set Up Virtual Environment (Recommended)</b></summary>

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```
</details>

<details open>
<summary><b>Step 3: Install Dependencies</b></summary>

```bash
# Install required packages
pip install -r requirements.txt
```
</details>

<details open>
<summary><b>Step 4: Configure Environment Variables</b></summary>

Create a `.env` file in the root directory with the following variables:

```ini
# Flask Application Configuration
# Main Flask application file
FLASK_APP=app.py
# Environment mode: 'development' or 'production'
FLASK_ENV=development
# Enable debug mode for development (1=enabled, 0=disabled)
FLASK_DEBUG=1
# IP address to bind the server to (0.0.0.0 allows external connections)
FLASK_HOST=0.0.0.0
# Port number for the Flask application
FLASK_PORT=5000

# Security Configuration
# Secret key used for session encryption and CSRF protection
# IMPORTANT: Use a strong, unique value in production
SECRET_KEY=your_secure_secret_key  # Generate a strong random key

# Database Configuration
# SQLite database URL (can be changed to other database engines)
DATABASE_URL=sqlite:///amivault.db

# Default Admin User Configuration
# Default administrator username
ADMIN_USERNAME=admin
# Default administrator password (should be changed after first login)
ADMIN_PASSWORD=your_secure_password  # Change from default
# Default administrator email address
ADMIN_EMAIL=admin@example.com

# Backup Configuration
# Default cron expression for backup frequency (0 2 * * * = daily at 2 AM)
# Format: minute hour day-of-month month day-of-week
DEFAULT_BACKUP_FREQUENCY=0 2 * * *
# Default number of days to retain backups before automatic cleanup
DEFAULT_RETENTION_DAYS=7

# Logging Configuration
# Log level can be DEBUG, INFO, WARNING, ERROR, or CRITICAL
LOG_LEVEL=INFO
# Directory where log files are stored
LOG_DIR=logs
# Access log filename
ACCESS_LOG=access.log
# Error log filename
ERROR_LOG=error.log
# Application log filename
APP_LOG=app.log
# Format string for log entries
LOG_FORMAT=%(asctime)s - %(name)s - %(levelname)s - %(message)s
# Format for timestamps in logs
LOG_DATE_FORMAT=%Y-%m-%d %H:%M:%S
# Maximum size of log files before rotation (10MB)
LOG_MAX_BYTES=10485760
# Number of backup log files to keep
LOG_BACKUP_COUNT=5

# Application Debug Mode
# Set to True to enable detailed error messages and debugging features
# Set to False in production for security and performance
DEBUG_MODE=True

# AWS EventBridge Configuration
# ARN of the Lambda function to be used as EventBridge target for AMI backups
# This is automatically set when you switch an instance's scheduler type to "EventBridge"
# The Lambda function is deployed automatically and handles AMI creation
# Example: arn:aws:lambda:us-east-1:123456789012:function:amivault-backup
BACKUP_LAMBDA_ARN=

# API Gateway endpoint for EventBridge target (alternative to Lambda)
# This is the URL that the Lambda function will call back to update backup status
# For dynamic IP setups, this needs to be your public-facing URL that can receive callbacks
# Example: https://your-public-ip:5000/api/backup-callback or an API Gateway ARN
# Example ARN: arn:aws:execute-api:us-east-1:123456789012:abcdef123/prod/POST/backup
API_GATEWAY_ENDPOINT=
```

> **Note:** For production environments, use a secure random key generator for the `SECRET_KEY`.
</details>

<details open>
<summary><b>Step 5: Initialize the Database</b></summary>

```bash
# Create database tables
python helper.py --recreate-db
```
</details>

<details open>
<summary><b>Step 6: Run the Application</b></summary>

```bash
# Start the application
python app.py
```

The application will be available at [http://localhost:5000/](http://localhost:5000/)
</details>

### Default Admin Account

<div class="alert alert-warning">
<table>
  <tr>
    <td width="10%">⚠️</td>
    <td><b>SECURITY NOTICE</b></td>
  </tr>
  <tr>
    <td></td>
    <td>
      If you don't set custom admin credentials in the <code>.env</code> file, the system will create:<br>
      <ul>
        <li><b>Username:</b> <code>admin</code></li>
        <li><b>Password:</b> <code>your_secure_password</code></li>
      </ul>
      <b>IMPORTANT:</b> Change the default password immediately in production environments!
    </td>
  </tr>
</table>
</div>

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
   - Configure with `scheduler_type='python'` in instance settings

2. **AWS EventBridge:**
   - Uses AWS EventBridge for scheduling
   - Configure with `scheduler_type='eventbridge'` in instance settings
   - Lambda function is automatically deployed when EventBridge is selected
   - No manual configuration required

### AWS EventBridge Integration

AMIVault can integrate with AWS EventBridge for more reliable scheduling:

- **Cross-Account Support:** Schedule backups across multiple AWS accounts
- **High Availability:** EventBridge provides enterprise-grade reliability
- **Monitoring:** Built-in CloudWatch metrics and alarms

#### Fully Automated Setup

AMIVault now features a fully automated EventBridge integration process:

1. **Automatic Lambda Function Deployment:**
   - When you switch an instance's scheduler type to "EventBridge", AMIVault automatically:
     - Creates the necessary IAM role with appropriate permissions
     - Deploys a Lambda function for AMI creation
     - Configures permissions for EventBridge to invoke the function
     - Updates the `.env` file with the Lambda ARN

2. **No Manual Configuration Required:**
   - Simply select "EventBridge" as the scheduler type when adding or editing an instance
   - The application handles all the AWS resource creation and configuration
   - EventBridge rules are automatically created with the Lambda function as the target

3. **Automatic Callback Integration:**
   - The Lambda function automatically reports back to AMIVault when AMIs are created
   - Backup records are updated in the database without manual intervention

#### Key Components

1. **lambda_function.py:**
   - Automatically deployed to AWS Lambda when EventBridge scheduler is selected
   - Receives events from EventBridge with instance ID information
   - Creates AMI backups of the specified EC2 instance
   - Tags the AMI with relevant metadata
   - Sends a callback to the AMIVault application with the backup results

2. **lambda_callback.py:**
   - Flask Blueprint that handles callbacks from the Lambda function
   - Exposes the `/api/backup-callback` endpoint to receive backup status
   - Updates the AMIVault database with information about created AMIs
   - Maintains synchronization between AWS resources and the AMIVault database

### Backup Frequency

Supports both cron expressions and interval notation:

- **Cron Expression:** `0 2 * * *` (Daily at 2 AM)
- **Interval Notation:** `daily`, `weekly`, `monthly`

### Logging

Configure logging behavior through environment variables. These variables are directly used in `app.py` to configure the application's logging system:

```bash
# Logging Configuration
LOG_LEVEL=INFO                                                  # Logging level (DEBUG, INFO, WARNING, ERROR)
LOG_DIR=logs                                                    # Directory where log files are stored
LOG_FORMAT="%(asctime)s - %(name)s - %(levelname)s - %(message)s" # Format of log entries
LOG_DATE_FORMAT="%Y-%m-%d %H:%M:%S"                             # Format for timestamps in logs
LOG_MAX_BYTES=10485760                                          # Maximum size of log files before rotation (10MB)
LOG_BACKUP_COUNT=5                                              # Number of backup log files to keep
```

These variables control the following aspects of the logging system:

- `LOG_LEVEL`: Sets the logging level (DEBUG, INFO, WARNING, ERROR). Controls the verbosity of logs. If changed to "ERROR", only error and critical messages will be logged, while INFO, DEBUG, and WARNING messages will be filtered out. This setting affects both console output and the app.log file.

- `LOG_DIR`: Directory for log files. The application will create this directory if it doesn't exist.

- `LOG_FORMAT`: Custom log format string that determines how log entries are formatted. This directly configures the Python logging formatter used for all log handlers. Changing this will affect the structure of each log entry.

- `LOG_DATE_FORMAT`: Format for timestamps in log entries. This configures how dates and times appear in log messages. The application uses this with the formatter to ensure consistent timestamp formatting.

- `LOG_MAX_BYTES`: Maximum log file size before rotation (in bytes). When a log file reaches this size, it's renamed with a suffix (e.g., app.log.1) and a new log file is created. This prevents log files from growing too large and consuming excessive disk space.

- `LOG_BACKUP_COUNT`: Number of backup log files to keep when rotating logs. For example, with a value of 5, the application will maintain app.log plus app.log.1 through app.log.5. When app.log reaches the maximum size, app.log.5 is deleted, app.log.4 becomes app.log.5, and so on. This implements an automatic log retention policy without requiring additional scripts or maintenance.

The application creates three types of log files, all configured with the same rotation and backup settings:

1. **app.log**: General application logs at the configured LOG_LEVEL
2. **error.log**: Error-level logs only (not affected by LOG_LEVEL setting)
3. **access.log**: HTTP request logs from the Flask application (werkzeug logs)

Log rotation happens automatically through Python's `RotatingFileHandler`, which checks the file size before each write operation. No additional cron jobs or maintenance tasks are required for log rotation and cleanup.

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

AMIVault provides a comprehensive RESTful API for seamless integration with other systems and automation workflows.

<div align="center">

### API Overview

[![API Documentation](https://img.shields.io/badge/API_Docs-Available-success.svg)](http://localhost:8080/api/docs)
[![API Version](https://img.shields.io/badge/API_Version-v1-blue.svg)](http://localhost:8080/api/docs)

</div>

### Available Endpoints

<table>
  <tr>
    <th>Category</th>
    <th>Endpoint</th>
    <th>Method</th>
    <th>Description</th>
    <th>Authentication</th>
  </tr>
  <tr>
    <td rowspan="1">Authentication</td>
    <td><code>/api/login</code></td>
    <td>POST</td>
    <td>Authenticate and receive access token</td>
    <td>None</td>
  </tr>
  <tr>
    <td rowspan="1">Instances</td>
    <td><code>/api/instances</code></td>
    <td>GET</td>
    <td>List all EC2 instances</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="1">AMIs</td>
    <td><code>/api/amis</code></td>
    <td>GET</td>
    <td>List all AMIs</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="2">Backups</td>
    <td><code>/api/backups</code></td>
    <td>GET</td>
    <td>List all backups</td>
    <td>Required</td>
  </tr>
  <tr>
    <td><code>/api/backup/&lt;backup_id&gt;</code></td>
    <td>GET</td>
    <td>Get details for a specific backup</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="1">Settings</td>
    <td><code>/api/backup-settings</code></td>
    <td>GET</td>
    <td>Get backup configuration settings</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="1">Credentials</td>
    <td><code>/api/aws-credentials</code></td>
    <td>GET</td>
    <td>List stored AWS credentials</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="1">Schedules</td>
    <td><code>/api/schedules/refresh</code></td>
    <td>GET</td>
    <td>Refresh backup schedules</td>
    <td>Required</td>
  </tr>
  <tr>
    <td rowspan="1">Documentation</td>
    <td><code>/api/docs</code></td>
    <td>GET</td>
    <td>Interactive API documentation</td>
    <td>Required</td>
  </tr>
</table>

### Authentication

All API endpoints (except `/api/login`) require authentication using a JWT token.

```http
GET /api/instances HTTP/1.1
Host: localhost:8080
Authorization: Bearer <your_jwt_token>
Content-Type: application/json
```

### Interactive Documentation

Complete API documentation with request/response examples is available at `/api/docs` when running the application. This interactive documentation allows you to:

- Explore all available endpoints
- Test API calls directly from the browser
- View request/response schemas
- Understand authentication requirements

---

## Security Features

<div align="center">

### Security Overview

[![Security](https://img.shields.io/badge/Security-Enterprise_Grade-blue.svg)](https://github.com/s3csys/amivault)
[![2FA](https://img.shields.io/badge/2FA-Enabled-success.svg)](https://github.com/s3csys/amivault)
[![Encryption](https://img.shields.io/badge/Encryption-AES_256-green.svg)](https://github.com/s3csys/amivault)

</div>

AMIVault implements enterprise-grade security features to protect your AWS resources and user data:

<table>
  <tr>
    <td width="50%">
      <h3>🔒 Password Security</h3>
      <ul>
        <li>Secure password hashing using Werkzeug's PBKDF2 algorithm</li>
        <li>Salted hashes with high iteration count</li>
        <li>Password complexity requirements enforcement</li>
        <li>Protection against brute force attacks</li>
      </ul>
    </td>
    <td width="50%">
      <h3>🔐 Two-Factor Authentication (2FA)</h3>
      <ul>
        <li>TOTP-based (Time-based One-Time Password) authentication</li>
        <li>QR code setup for easy enrollment</li>
        <li>Compatible with Google Authenticator, Authy, and other TOTP apps</li>
        <li>Backup codes for emergency access</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>⏱️ Session Management</h3>
      <ul>
        <li>Secure session handling with configurable timeout</li>
        <li>Session invalidation on logout</li>
        <li>Prevention of session fixation attacks</li>
        <li>Secure cookie settings with HttpOnly and SameSite flags</li>
      </ul>
    </td>
    <td width="50%">
      <h3>✅ Input Validation</h3>
      <ul>
        <li>Comprehensive validation for all user inputs</li>
        <li>Protection against SQL injection</li>
        <li>Protection against XSS (Cross-Site Scripting)</li>
        <li>Sanitization of user-provided data</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🔑 AWS Credential Security</h3>
      <ul>
        <li>AES-256 encryption for stored credentials</li>
        <li>Key rotation capabilities</li>
        <li>Option for temporary credential usage</li>
        <li>Principle of least privilege for AWS operations</li>
      </ul>
    </td>
    <td width="50%">
      <h3>🛡️ CSRF Protection</h3>
      <ul>
        <li>Cross-Site Request Forgery protection</li>
        <li>Unique CSRF tokens for each session</li>
        <li>Token validation for all state-changing operations</li>
        <li>Protection against clickjacking with X-Frame-Options</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <h3>📝 Comprehensive Logging</h3>
      <ul>
        <li>Security event logging for audit trails</li>
        <li>Detailed logs for authentication attempts</li>
        <li>Resource access and modification tracking</li>
        <li>Log rotation and secure storage</li>
        <li>Configurable log levels and formats</li>
      </ul>
    </td>
  </tr>
</table>

### Security Best Practices

AMIVault follows industry-standard security best practices:

- Regular security updates and dependency scanning
- Defense-in-depth approach with multiple security layers
- Principle of least privilege for all operations
- Secure development lifecycle with code reviews and security testing

---

## Contributing

We welcome contributions from the community! Please follow these steps to contribute:

<div align="center">

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Contributors](https://img.shields.io/github/contributors/s3csys/amivault.svg)](https://github.com/s3csys/amivault/graphs/contributors)
[![Issues](https://img.shields.io/github/issues/s3csys/amivault.svg)](https://github.com/s3csys/amivault/issues)

</div>

### Contribution Process

1. **Fork the Repository**
   - Create your own fork of the project

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Implement Your Changes**
   - Add your feature or fix
   - Follow the development guidelines below

4. **Run Tests**
   ```bash
   python -m pytest
   ```

5. **Commit Your Changes**
   ```bash
   git commit -m 'Add: detailed description of your changes'
   ```

6. **Push to Your Branch**
   ```bash
   git push origin feature/YourFeature
   ```

7. **Open a Pull Request**
   - Submit a PR with a clear description of your changes
   - Link any relevant issues

### Development Guidelines

<table>
  <tr>
    <td width="33%"><b>Code Style</b></td>
    <td width="33%"><b>Testing</b></td>
    <td width="33%"><b>Documentation</b></td>
  </tr>
  <tr>
    <td>
      <ul>
        <li>Follow PEP 8 style guidelines</li>
        <li>Use meaningful variable names</li>
        <li>Keep functions small and focused</li>
        <li>Use type hints where appropriate</li>
      </ul>
    </td>
    <td>
      <ul>
        <li>Write tests for all new features</li>
        <li>Maintain >80% test coverage</li>
        <li>Include both unit and integration tests</li>
        <li>Test edge cases thoroughly</li>
      </ul>
    </td>
    <td>
      <ul>
        <li>Update documentation for new features</li>
        <li>Add docstrings to all functions</li>
        <li>Keep the README up to date</li>
        <li>Document API changes</li>
      </ul>
    </td>
  </tr>
</table>

### Code of Conduct

We expect all contributors to adhere to our Code of Conduct. Please be respectful and constructive in all interactions.

---

## License

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

</div>

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The MIT License is a permissive license that is short and to the point. It lets people do anything they want with your code as long as they provide attribution back to you and don't hold you liable.

---

## Acknowledgments

AMIVault stands on the shoulders of giants. We'd like to thank:

<table>
  <tr>
    <td width="50%">
      <h3>Open Source Communities</h3>
      <ul>
        <li>Flask and Flask extensions community</li>
        <li>AWS SDK for Python (boto3) team</li>
        <li>Python Software Foundation</li>
        <li>Open source security tools community</li>
      </ul>
    </td>
    <td width="50%">
      <h3>Frontend Technologies</h3>
      <ul>
        <li>Bootstrap team for responsive UI framework</li>
        <li>SweetAlert2 for enhanced user interactions</li>
        <li>Jinja2 template engine contributors</li>
        <li>JavaScript community</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td colspan="2">
      <h3>Contributors & Supporters</h3>
      <ul>
        <li>All individual contributors to the project</li>
        <li>Early adopters and testers who provided valuable feedback</li>
        <li>Organizations that have supported the development</li>
      </ul>
    </td>
  </tr>
</table>

---

<div align="center">

# AMIVault

**Secure, Automated, and Extensible AWS AMI Backup Management**

[Documentation](https://github.com/s3csys/amivault/wiki) | 
[Report Issues](https://github.com/s3csys/amivault/issues) | 
[Request Features](https://github.com/s3csys/amivault/issues) | 
[Contribute](https://github.com/s3csys/amivault/blob/main/CONTRIBUTING.md)

© 2023 S3CSYS Systems. All rights reserved.

</div>
