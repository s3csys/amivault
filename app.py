import pyotp
import qrcode
import io
import base64
import boto3

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

############################################################ Models ############################################################

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password_hash = db.Column(db.String(120))
    email = db.Column(db.String(120))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Instance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    instance_id = db.Column(db.String(50))
    instance_name = db.Column(db.String(100))
    access_key = db.Column(db.String(100))
    secret_key = db.Column(db.String(100))
    region = db.Column(db.String(20), nullable=False)
    backup_frequency = db.Column(db.String(64), nullable=False) 
    retention_days = db.Column(db.Integer, nullable=False, default=7)   


class BackupSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retention_days = db.Column(db.Integer, default=7)
    backup_frequency = db.Column(db.String(50), default="0 2 * * *")  # 2AM daily

two_factor_secret = db.Column(db.String(32), nullable=True)

############################################################ Routes ############################################################

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    return render_template('dashboard.html', user=user)

#@app.route('/login', methods=['GET', 'POST'])
#def login():
#    if request.method == 'POST':
#        uname = request.form['username']
#        pwd = request.form['password']
#        user = User.query.filter_by(username=uname).first()
#        if user and user.check_password(pwd):
#            session['username'] = user.username
#            return redirect(url_for('dashboard'))
#        else:
#            flash("Invalid credentials", "danger")
#    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        user = User.query.filter_by(username=uname).first()
        if user and user.check_password(pwd):
            # Enforce 2FA if enabled and secret is set
            if user.two_factor_enabled and user.two_factor_secret:
                session['pending_2fa_user'] = user.username
                return redirect(url_for('two_factor'))
            # Normal login if 2FA not enabled
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials", "danger")
            return render_template('login.html')
    return render_template('login.html')


@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'pending_2fa_user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['pending_2fa_user']).first()
    if request.method == 'POST':
        code = request.form['code']
        totp = pyotp.TOTP(user.two_factor_secret)
        if totp.verify(code):
            session['username'] = user.username
            session.pop('pending_2fa_user')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid 2FA code', 'danger')
    return render_template('two_factor.html')

@app.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()

    if not user.two_factor_secret:
        # Generate a new secret
        secret = pyotp.random_base32()
        user.two_factor_secret = secret
        db.session.commit()
    else:
        secret = user.two_factor_secret

    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.email or user.username,
        issuer_name="YourAppName"
    )

    # Generate QR code as base64
    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    if request.method == 'POST':
        code = request.form['code']
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            user.two_factor_enabled = True
            db.session.commit()
            flash("2FA enabled successfully!", "success")
            return redirect(url_for('user_settings'))
        else:
            flash("Invalid code. Please try again.", "danger")

    return render_template('setup_2fa.html', qr_b64=qr_b64, secret=secret)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

############################################################ User Management ############################################################

@app.route('/user-settings', methods=['GET'])
def user_settings():
    if 'username' not in session:
        return redirect(url_for('login'))
    users = User.query.all()
    current_user = User.query.filter_by(username=session['username']).first()
    return render_template('user_settings.html', users=users, current_user=current_user)

@app.route('/add-user', methods=['POST'])
def add_user():
    user = User(
        username=request.form['username'],
        email=request.form['email']
    )
    user.set_password(request.form['password'])
    db.session.add(user)
    db.session.commit()
    flash("User added successfully", "success")
    return redirect(url_for('user_settings'))

@app.route('/delete-user', methods=['POST'])
def delete_user():
    uname = request.form['username']
    user = User.query.filter_by(username=uname).first()
    if user:
        db.session.delete(user)
        db.session.commit()
        flash("User deleted", "info")
    return redirect(url_for('user_settings'))

@app.route('/reset-password', methods=['POST'])
def reset_password():
    uname = request.form['username']
    new_pwd = request.form['new_password']
    user = User.query.filter_by(username=uname).first()
    if user:
        user.set_password(new_pwd)
        db.session.commit()
        flash("Password reset successful", "success")
    return redirect(url_for('user_settings'))

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'username' not in session:
        flash("You must be logged in to update your profile.", "danger")
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('user_settings'))

    # Update email (you can expand this to other fields as needed)
    new_email = request.form.get('email')
    if new_email:
        user.email = new_email
        db.session.commit()
        flash("Profile updated successfully.", "success")
    else:
        flash("Email cannot be empty.", "danger")
    return redirect(url_for('user_settings'))

#@app.route('/toggle-2fa', methods=['POST'])
#def toggle_2fa():
#    if 'username' not in session:
#        flash("You must be logged in.", "danger")
#        return redirect(url_for('login'))
#    user = User.query.filter_by(username=session['username']).first()
#    if not user:
#        flash("User not found.", "danger")
#        return redirect(url_for('user_settings'))
#
#    enable_2fa = 'enable_2fa' in request.form
#    # Here you would store the 2FA setting in your User model (add a field if needed)
#    # Example: user.two_factor_enabled = enable_2fa
#    # db.session.commit()
#    flash("Two-factor authentication setting updated (UI only, backend not implemented).", "success")
#    return redirect(url_for('user_settings'))

@app.route('/reinit-db', methods=['POST'])
def reinit_db():
    if 'username' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))

    # Only allow admin to perform this action
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.username != 'admin':
        flash("Only admin can reinitialize the database.", "danger")
        return redirect(url_for('user_settings'))

    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()

    # Create default admin user
    username = "admin"
    password = "admin123"  # Change in production!
    email = "admin@example.com"

    # Check if the user already exists (should not, but for safety)
    existing = User.query.filter_by(username=username).first()
    if existing:
        flash(f"User '{username}' already exists.", "info")
    else:
        user = User(username=username, email=email)
        user.set_password(password)
        # If you have a profile_pic_url field, add it here:
        # user.profile_pic_url = "https://example.com/images/admin.png"
        db.session.add(user)
        db.session.commit()
        flash(f"User '{username}' added with email '{email}'.", "success")

    flash("Database reinitialized. Default admin user recreated.", "success")
    return redirect(url_for('user_settings'))


@app.route('/toggle-2fa', methods=['POST'])
def toggle_2fa():
    if 'username' not in session:
        flash("You must be logged in.", "danger")
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('user_settings'))

    enable_2fa = 'enable_2fa' in request.form
    user.two_factor_enabled = enable_2fa
    db.session.commit()
    flash("Two-factor authentication setting updated.", "success")
    return redirect(url_for('user_settings'))

############################################################ AWS Instances ############################################################

@app.route('/aws-instances', methods=['GET'])
def manage_instances():
    if 'username' not in session:
        return redirect(url_for('login'))
    instances = Instance.query.all()
    return render_template('aws_instances.html', instances=instances)

#@app.route('/add-instance', methods=['POST'])
#def add_instance():
#    instance = Instance(
#        instance_id=request.form['instance_id'],
#        instance_name=request.form['instance_name'],
#        access_key=request.form['access_key'],
#        secret_key=request.form['secret_key']
#    )
#    db.session.add(instance)
#    db.session.commit()
#    flash("Instance added", "success")
#    return redirect(url_for('manage_instances'))

@app.route('/add-instance', methods=['GET', 'POST'])
def add_instance():
    if request.method == 'POST':
        instance_id = request.form.get('instance_id')
        instance_name = request.form.get('instance_name')
        access_key = request.form.get('access_key')
        secret_key = request.form.get('secret_key')
        backup_frequency = request.form.get('backup_frequency')
        custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
        retention_days = request.form.get('retention_days', 7)

        if backup_frequency == 'custom':
            backup_frequency = custom_backup_frequency
        if not backup_frequency:
            flash("Backup frequency is required.", "danger")
            return redirect(url_for('add_instance'))

        region = request.form.get('region')
        if region == 'custom':
            region = request.form.get('custom_region', '').strip()
        if not region:
            flash("Region is required.", "danger")
            return redirect(url_for('add_instance'))

        inst = Instance(
            instance_id=instance_id,
            instance_name=instance_name,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            backup_frequency=backup_frequency,
            retention_days=retention_days
        )
        db.session.add(inst)
        db.session.commit()
        flash('Instance added!', 'success')
        #return redirect(url_for('add_instance'))
    return render_template('aws_instances.html')


@app.route('/delete-instance/<instance_id>', methods=['POST'])
def delete_instance(instance_id):
    instance = Instance.query.filter_by(instance_id=instance_id).first()
    if instance:
        db.session.delete(instance)
        db.session.commit()
        flash("Instance deleted", "info")
    return redirect(url_for('manage_instances'))

#@app.route('/update_instance/<string:instance_id>', methods=['POST'])
#def update_instance(instance_id):
#    # Example: update the instance name or tag in the database
#    new_name = request.form.get('new_name')
#    instance = EC2Instance.query.filter_by(instance_id=instance_id).first()
#
#    if not instance:
#        flash(f"Instance with ID {instance_id} not found.", "error")
#        return redirect(url_for('manage_instances'))
#
#    instance.name = new_name
#    db.session.commit()
#    flash(f"Instance {instance_id} updated successfully!", "success")
#    return redirect(url_for('manage_instances'))


## List all instances
#@app.route('/instances')
#def list_instances():
#    instances = Instance.query.all()
#    return render_template('instances.html', instances=instances)

## Add a new instance
#@app.route('/add-instance', methods=['GET', 'POST'])
#def add_instance():
#    if request.method == 'POST':
#        instance_id = request.form['instance_id']
#        instance_name = request.form['instance_name']
#        access_key = request.form['access_key']
#        secret_key = request.form['secret_key']
#        backup_frequency = request.form.get('backup_frequency')
#        custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
#        retention_days = request.form.get('retention_days', 7)
#
#        # Region logic
#        region = request.form['region']
#        if region == 'custom':
#            region = request.form['custom_region'].strip()
#        if not region:
#            flash("Region is required.", "danger")
#            return redirect(url_for('add_instance'))
#
#        # Use custom backup frequency if selected
#        if backup_frequency == 'custom':
#            backup_frequency = custom_backup_frequency
#
#        # Create and save the instance
#        inst = Instance(
#            instance_id=instance_id,
#            instance_name=instance_name,
#            access_key=access_key,
#            secret_key=secret_key,
#            region=region,
#            backup_frequency=backup_frequency,
#            retention_days=retention_days
#        )
#        db.session.add(inst)
#        db.session.commit()
#        flash('Instance added!', 'success')
#        return redirect(url_for('list_instances'))  # Use the correct endpoint name
#
#    return render_template('add_instance.html')
#
# Update an existing instance
@app.route('/update-instance/<instance_id>', methods=['POST'])
def update_instance(instance_id):
    inst = Instance.query.filter_by(instance_id=instance_id).first_or_404()
    inst.instance_name = request.form['instance_name']
    backup_frequency = request.form.get('backup_frequency')
    custom_backup_frequency = request.form.get('custom_backup_frequency', '').strip()
    retention_days = request.form.get('retention_days', 7)

    # Use custom backup frequency if selected
    if backup_frequency == 'custom':
        backup_frequency = custom_backup_frequency
    inst.backup_frequency = backup_frequency
    inst.retention_days = retention_days
    db.session.commit()
    flash('Instance updated!', 'success')
    #return redirect(url_for('aws_instance.html'))
    return render_template('aws_instances.html')
#
## Delete an instance
#@app.route('/delete-instance/<instance_id>', methods=['POST'])
#def delete_instance(instance_id):
#    inst = Instance.query.filter_by(instance_id=instance_id).first_or_404()
#    db.session.delete(inst)
#    db.session.commit()
#    flash('Instance deleted!', 'success')
#    return redirect(url_for('list_instances'))

@app.route('/start-backup/<instance_id>', methods=['POST'])
def start_backup(instance_id):
    # TODO: Add your backup logic here
    # For example: backup_instance(instance_id)
    flash(f"Manual backup started for instance {instance_id}", "success")
    return redirect(url_for('manage_instances'))

############################################################ AWS Checker ############################################################
@app.route('/check-instance', methods=['POST'])
def check_instance():
    data = request.get_json()
    instance_id = data.get('instance_id')
    access_key = data.get('access_key')
    secret_key = data.get('secret_key')
    region = data.get('region')

    if not all([instance_id, access_key, secret_key, region]):
        return jsonify(success=False, error='Missing required fields')

    try:
        # Use boto3 client for more robust error handling
        ec2_client = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get('Reservations', [])
        if not reservations or not reservations[0].get('Instances'):
            return jsonify(success=False, error='Instance not found in this region/account.')

        instance = reservations[0]['Instances'][0]
        name = instance_id  # Default to ID
        tags = instance.get('Tags', [])
        for tag in tags:
            if tag['Key'] == 'Name' and tag.get('Value'):
                name = tag['Value']
                break
        return jsonify(success=True, instance_name=name)
    except Exception as e:
        # Return the AWS error message for debugging
        return jsonify(success=False, error=str(e))


############################################################ Notifications ############################################################
def add_notification(message, category='info'):
    if 'notifications' not in session:
        session['notifications'] = []
    session['notifications'].append({'message': message, 'category': category})
    session.modified = True
    flash(message, category)

@app.route('/clear-notifications', methods=['POST'])
def clear_notifications():
    session['notifications'] = []
    session.modified = True
    return redirect(request.referrer or url_for('instances'))

############################################################ Backup Settings ############################################################

@app.route('/backup-settings', methods=['GET'])
def backup_settings():
    config = BackupSettings.query.first()
    if not config:
        config = BackupSettings()
        db.session.add(config)
        db.session.commit()
    return render_template('backup_settings.html', config=config)

@app.route('/update-backup-settings', methods=['POST'])
def update_backup_settings():
    config = BackupSettings.query.first()
    if config:
        config.retention_days = int(request.form['retention_days'])
        config.backup_frequency = request.form['backup_frequency']
        db.session.commit()
        flash("Backup settings updated", "success")
    return redirect(url_for('backup_settings'))


############################################################ Run ############################################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Create default admin user if none exists
        if not User.query.filter_by(username='admin').first():
            default_admin = User(username='admin', email='admin@example.com')
            default_admin.set_password('admin123')  # 🔐 Change this in production!
            db.session.add(default_admin)
            db.session.commit()
            print("✅ Default admin user created: admin / admin123")

    app.run(host="0.0.0.0", port=8080, debug=True)
