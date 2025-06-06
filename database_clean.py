# init_db_runner.py
#from db import init_db
from app import db
#init_db()
db.create_all()
print("Database initialized.")
