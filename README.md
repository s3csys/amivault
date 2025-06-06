# AmiVault

AmiVault is a professional Flask-based web application for managing AWS EC2 AMI backups and schedules. It provides a secure, user-friendly dashboard to automate, view, and control AMI creation, deletion, and backup scheduling across multiple AWS accounts and regions.

---

## Features

- **Automated AMI Backups:**  
  Schedule and manage EC2 AMI backups with persistent job storage using APScheduler and SQLAlchemy.

- **Dashboard Interface:**  
  View, search, and manage all backups and schedules from a responsive web dashboard.

- **Secure AMI Deletion:**  
  Deregister AMIs and delete associated snapshots, with credential prompts if instance records are missing.

- **Credential Management:**  
  Credentials are securely handled—never stored, only used transiently for AWS operations.

- **User Management:**  
  Default admin account creation; ready for extension with user authentication and role management.

- **Robust Error Handling:**  
  Clear feedback and error messages for all operations.

- **Extensible Codebase:**  
  Organized into modular, self-contained sections for easy integration and future expansion.

---

## Tech Stack

- **Backend:** Flask, Flask-SQLAlchemy, APScheduler
- **Frontend:** Bootstrap 5, SweetAlert2, Jinja2
- **AWS Integration:** boto3
- **Database:** SQLite (default, easily extendable to PostgreSQL/MySQL)
- **Python Version:** 3.8+

---

## Getting Started

### Prerequisites

- Python 3.8 or newer
- pip

### Installation

1. **Clone the Repository**
```bash
git clone https://github.com/yourusername/amivault.git
cd amivault
```

2. **Install Dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the Application**
```bash
python3 app.py
```

The app will be available at [http://localhost:8080/](http://localhost:8080/)

### Default Admin

- **Username:** `admin`
- **Password:** `admin123`  
*(Change this password immediately in production!)*

---

## Usage

- **Dashboard:**  
Access `/` to view and manage AMI backups and schedules.

- **Delete AMI:**  
Use the dashboard to deregister AMIs. If instance credentials are missing, you will be securely prompted for AWS access keys.

- **Schedules:**  
View and manage all scheduled backup jobs from the schedules page.

---

## Code Organization

- All modules and routes are organized in self-contained sections for clarity and easy integration.
- Dependency management is handled via `requirements.txt` for reproducible environments.

---

## Contributing

1. Fork the repository.
2. Create your feature branch (`git checkout -b feature/YourFeature`).
3. Commit your changes.
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

- Flask, Flask-SQLAlchemy, APScheduler, boto3, Bootstrap, SweetAlert2

---

**AmiVault** — Secure, Automated, and Extensible AWS AMI Backup Management.
