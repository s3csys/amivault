from app import app, db, User

username = "admin"
password = "pass"
email = "muzammil.shaik55@gmail.com"

with app.app_context():
    # Check if the user already exists
    existing = User.query.filter_by(username=username).first()
    if existing:
        print(f"User '{username}' already exists.")
    else:
        user = User(username=username, email=email)
        user.set_password(password)
        # If you have a profile_pic_url field, add it here:
        # user.profile_pic_url = "https://example.com/images/admin.png"
        db.session.add(user)
        db.session.commit()
        print(f"User '{username}' added with email '{email}'.")
