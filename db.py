import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_FILE = "database.db"

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()

        # Updated User table with email and profile_pic_url
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                profile_pic_url TEXT
            )
        ''')

        # AWS Credentials table
        c.execute('''
            CREATE TABLE IF NOT EXISTS aws_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                access_key TEXT,
                secret_key TEXT,
                region TEXT,
                instance_ids TEXT,
                retention_days INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')

        conn.commit()


def migrate_db():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT UNIQUE")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE users ADD COLUMN profile_pic_url TEXT")
        except sqlite3.OperationalError:
            pass
        conn.commit()

def add_user(username, password, email, profile_pic_url=None):
    hashed = generate_password_hash(password)
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, password, email, profile_pic_url) VALUES (?, ?, ?, ?)",
            (username, hashed, email, profile_pic_url)
        )
        conn.commit()

def validate_user(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result and check_password_hash(result[1], password):
            return result[0]  # Return user_id
    return None

def save_aws_config(user_id, access_key, secret_key, region, instance_ids, retention_days):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM aws_configs WHERE user_id = ?", (user_id,))
        c.execute('''
            INSERT INTO aws_configs (
                user_id, access_key, secret_key, region, instance_ids, retention_days
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, access_key, secret_key, region, instance_ids, retention_days))
        conn.commit()

def get_aws_config(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT access_key, secret_key, region, instance_ids, retention_days FROM aws_configs WHERE user_id = ?", (user_id,))
        return c.fetchone()

def get_user_by_id(user_id):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, profile_pic_url FROM users WHERE id=?", (user_id,))
        row = cursor.fetchone()
    if row:
        return {"username": row[0], "email": row[1], "profile_pic_url": row[2]}
    return {"username": "Unknown", "email": None, "profile_pic_url": None}

def get_user_by_email(email):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, profile_pic_url FROM users WHERE email=?", (email,))
        row = cursor.fetchone()
    if row:
        return {"username": row[0], "email": row[1], "profile_pic_url": row[2]}
    return {"username": "Unknown", "email": None, "profile_pic_url": None}
