import pyotp, qrcode, io, base64, boto3, pytz, os, csv, secrets


from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone, timedelta
from flask_apscheduler import APScheduler
from io import StringIO

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
    backup_frequency = db.Column(db.String(64), default="0 * * * *")
    instance_id = db.Column(db.String(64), nullable=False)
    instance_name = db.Column(db.String(128))
    ami_id = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default='Pending')  # 'Pending', 'Success', 'Failed'
    region = db.Column(db.String(32))
    log_url = db.Column(db.String(256))
    
class Backup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    retention_days = db.Column(db.Integer, default=7)
    instance_id = db.Column(db.String(64), db.ForeignKey('instance.instance_id'), nullable=False)
    instance_name = db.Column(db.String(128))
    ami_id = db.Column(db.String(64))
    ami_name = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(32), default='Pending')  # 'Pending', 'Success', 'Failed'
    region = db.Column(db.String(32))
    log_url = db.Column(db.String(256))

    # Relationship to Instance
    instance = db.relationship('Instance', backref='backups', lazy=True)


two_factor_secret = db.Column(db.String(32), nullable=True)

############################################################ Routes ############################################################

#@app.route('/')
#def dashboard():
#    if 'username' not in session:
#        return redirect(url_for('login'))
#    user = User.query.filter_by(username=session['username']).first()
#    return render_template('dashboard.html', user=user)

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['username']).first()
    # Query all backups, most recent first
    backups = Backup.query.order_by(Backup.timestamp.desc()).all()
    last_backup = backups[0] if backups else None
    return render_template('dashboard.html', user=user, backups=backups, last_backup=last_backup)


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
            if user.two_factor_enabled and user.two_factor_secret:
                session['pending_2fa_user'] = user.username
                # If AJAX, respond with JSON to trigger 2FA popup
                if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({'require_2fa': True})
                # Fallback for non-AJAX
                return render_template('login.html', require_2fa=True)
            # Normal login
            session['username'] = user.username
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
            else:
                return redirect(url_for('dashboard'))  # <-- Fix: redirect for normal POST
        else:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'success': False, 'error': 'Invalid credentials'})
            else:
                flash("Invalid credentials", "danger")
                return render_template('login.html')
    return render_template('login.html')



@app.route('/login_2fa', methods=['POST'])
def login_2fa():
    pending_user = session.get('pending_2fa_user')
    if not pending_user:
        return jsonify({'success': False, 'error': 'No 2FA session found. Please login again.'})
    user = User.query.filter_by(username=pending_user).first()
    if not user or not user.two_factor_enabled or not user.two_factor_secret:
        return jsonify({'success': False, 'error': '2FA not enabled for this user.'})
    code = request.form.get('code', '').strip()
    totp = pyotp.TOTP(user.two_factor_secret)
    if totp.verify(code):
        session.pop('pending_2fa_user')
        session['username'] = user.username
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    else:
        return jsonify({'success': False, 'error': 'Invalid 2FA code. Please try again.'})


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
        flash(f"{uname} User deleted", "info")
    return redirect(url_for('user_settings'))

@app.route('/reset_password', methods=['POST'])
def reset_password():
    username = request.form.get('username')
    new_password = request.form.get('new_password')
    if not username or not new_password:
        flash("Username and new password are required.", "error")
        return redirect(url_for('user_settings'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash(f"User '{username}' not found.", "error")
        return redirect(url_for('user_settings'))

    user.password = generate_password_hash(new_password)
    db.session.commit()
    flash(f"✅ Password reset complete for {username}.", "success")
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
    # Ensure user is logged in
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': "You must be logged in."}), 403

    # Only allow admin to perform this action
    user = User.query.filter_by(username=session['username']).first()
    if not user or user.username != 'admin':
        return jsonify({'status': 'error', 'message': "Only admin can reinitialize the database."}), 403

    # Get password from AJAX or generate a secure one
    data = request.get_json()
    password = data.get('password')
    if not password:
        password = secrets.token_urlsafe(16)

    username = "admin"
    email = "admin@example.com"

    # Drop all tables and recreate them
    db.drop_all()
    db.create_all()

    # Remove existing admin user if present
    existing = User.query.filter_by(username=username).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()

    # Create default admin user
    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'status': 'success',
        'username': username,
        'password': password,
        'email': email,
        'message': "Database reinitialized. Default admin user recreated."
    })


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
        region = request.form.get('region')
        
        # Handle custom region
        if region == 'custom':
            region = request.form.get('custom_region', '').strip()
        if not region:
            flash("Region is required.", "error")
            return redirect(url_for('add_instance'))
            
        # Handle custom backup frequency
        if backup_frequency == 'custom':
            backup_frequency = custom_backup_frequency
        if not backup_frequency:
            flash("Backup frequency is required.", "error")
            return redirect(url_for('add_instance'))
            
        # Validate AWS credentials and instance existence
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Create a session with the provided credentials
            session = boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=region
            )
            
            # Create EC2 client
            ec2 = session.client('ec2')
            
            # Check if instance exists and get its details
            response = ec2.describe_instances(InstanceIds=[instance_id])
            
            # If we get here, instance exists. Now check its name
            if 'Reservations' in response and response['Reservations']:
                instances = response['Reservations'][0]['Instances']
                if instances:
                    # Find the Name tag
                    actual_name = None
                    for tag in instances[0].get('Tags', []):
                        if tag['Key'] == 'Name':
                            actual_name = tag['Value']
                            break
                    
                    # If instance has a name tag and it doesn't match user input
                    if actual_name and actual_name != instance_name:
                        flash(f"Warning: AWS instance name is '{actual_name}', but you entered '{instance_name}'. The name has been updated.", "warning")
                        instance_name = actual_name
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'InvalidInstanceID.NotFound':
                flash(f"Instance ID '{instance_id}' not found in AWS. Please check the ID and try again.", "error")
            elif error_code == 'AuthFailure' or error_code == 'UnauthorizedOperation':
                flash("AWS authentication failed. Please check your access key and secret key.", "error")
            else:
                flash(f"AWS error: {str(e)}", "error")
            return redirect(url_for('add_instance'))
        except NoCredentialsError:
            flash("Invalid AWS credentials. Please check your access key and secret key.", "error")
            return redirect(url_for('add_instance'))
        except Exception as e:
            flash(f"Error validating AWS details: {str(e)}", "error")
            return redirect(url_for('add_instance'))

        # If validation passes, add the instance to the database
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
        flash('Instance added successfully!', 'success')
        return redirect('/aws-instances')
    
    # GET request - render the form
    return render_template('aws_instances.html')


@app.route('/delete-instance/<instance_id>', methods=['POST'])
def delete_instance(instance_id):
    instance = Instance.query.filter_by(instance_id=instance_id).first()
    if instance:
        db.session.delete(instance)
        db.session.commit()
        flash('Instance deleted!', 'success')
        #flash('Instance added!', 'success')
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

    # Reschedule all backup jobs so the new settings take effect
    reschedule_backups()
    schedule_all_instance_backups()

    flash('Instance updated!', 'success')
    return redirect('/aws-instances')
    #return redirect(url_for('aws-instances'))
    #return render_template('aws_instances.html')
#
## Delete an instance
#@app.route('/delete-instance/<instance_id>', methods=['POST'])
#def delete_instance(instance_id):
#    inst = Instance.query.filter_by(instance_id=instance_id).first_or_404()
#    db.session.delete(inst)
#    db.session.commit()
#    flash('Instance deleted!', 'success')
#    return redirect(url_for('list_instances'))

############################################################ Bulk Actions ############################################################

@app.route('/bulk-export-amis', methods=['POST'])
def bulk_export_amis():
    data = request.get_json()
    instance_ids = data.get('instances', [])
    amis = Backup.query.filter(Backup.instance_id.in_(instance_ids)).all()

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['AMI ID', 'Instance Name', 'Instance ID', 'Region', 'Timestamp', 'Status'])
    for ami in amis:
        writer.writerow([ami.ami_id, ami.instance_name, ami.instance_id, ami.region, ami.timestamp, ami.status])

    output = si.getvalue()
    response = make_response(output)
    response.headers["Content-Disposition"] = "attachment; filename=amis_export.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/bulk-tag-amis', methods=['POST'])
def bulk_tag_amis():
    data = request.get_json()
    instance_ids = data.get('instances', [])
    tag_key = data.get('tag_key')
    tag_value = data.get('tag_value')
    if not tag_key or not tag_value:
        flash('Tags added to selected AMIs.', 'success')
        return redirect('/')  # or your desired page

    tagged_amis = []
    errors = []

    for inst_id in instance_ids:
        inst = Instance.query.filter_by(instance_id=inst_id).first()
        if not inst:
            errors.append(f"Instance {inst_id} not found.")
            continue
        backups = Backup.query.filter_by(instance_id=inst_id).all()
        ec2 = boto3.client(
            'ec2',
            region_name=inst.region,
            aws_access_key_id=inst.access_key,
            aws_secret_access_key=inst.secret_key
        )
        for b in backups:
            try:
                ec2.create_tags(
                    Resources=[b.ami_id],
                    Tags=[{'Key': tag_key, 'Value': tag_value}]
                )
                tagged_amis.append(b.ami_id)
            except Exception as e:
                errors.append(f"Failed to tag {b.ami_id}: {e}")

    msg = f"Tagged AMIs: {', '.join(tagged_amis)}"
    if errors:
        msg += " | Errors: " + " | ".join(errors)
        flash(msg, "warning")
    else:
        flash(msg, "success")
    return redirect('/')  # or your backup records page


############################################################ AWS AMi Creaters ############################################################

@app.route('/start-backup/<instance_id>', methods=['POST'])
def start_backup(instance_id):
    inst = Instance.query.filter_by(instance_id=instance_id).first_or_404()
    retention_days = int(inst.retention_days) if hasattr(inst, 'retention_days') else 7
    aws_region = inst.region
    aws_access_key = inst.access_key
    aws_secret_key = inst.secret_key

    try:
        ec2 = boto3.client(
            'ec2',
            region_name=aws_region,
            aws_access_key_id=aws_access_key,
            aws_secret_access_key=aws_secret_key
        )

        # Get instance name
        tags_response = ec2.describe_tags(
            Filters=[
                {'Name': 'resource-id', 'Values': [instance_id]},
                {'Name': 'key', 'Values': ['Name']}
            ]
        )
        instance_name = None
        for tag in tags_response.get('Tags', []):
            if tag['Key'] == 'Name':
                instance_name = tag['Value']
                break

        if not instance_name:
            flash(f"Could not find 'Name' tag for {instance_id}.", "danger")
            return redirect(url_for('manage_instances'))

        # Create AMI
        zone = pytz.timezone('Asia/Kolkata')
        timestamp_str = datetime.now(zone).strftime("%Y_%m_%d_%I_%M_%p")
        ami_name = f"{instance_name}_{timestamp_str}"
        ami_response = ec2.create_image(
            InstanceId=instance_id,
            Name=ami_name,
            NoReboot=True
        )
        ami_id = ami_response['ImageId']

        # Create a pending backup record
        backup = Backup(
            instance_id=instance_id,
            instance_name=instance_name,
            #ami_id=ami_id,
            ami_name=ami_name, 
            timestamp=datetime.utcnow(),
            status='Pending',
            region=aws_region,
            retention_days=retention_days
        )
        db.session.add(backup)
        db.session.commit()

        # Tag the AMI
        ec2.create_tags(
            Resources=[ami_id],
            Tags=[
                {'Key': 'CreatedBy', 'Value': 'AutoBackup'},
                {'Key': 'InstanceName', 'Value': instance_name}
            ]
        )

        # Update backup record to Success and store ami_id
        backup.status = 'Success'
        backup.ami_id = ami_id
        db.session.commit()

        # (Cleanup code here...)

        flash(f"Manual backup started for instance {instance_id} (AMI: {ami_id})", "success")
    except Exception as e:
        # If backup record exists, update status to Failed
        if 'backup' in locals():
            backup.status = 'Failed'
            db.session.commit()
        flash(f"Backup failed: {str(e)}", "danger")

    return redirect(url_for('manage_instances'))


def get_effective_setting(instance_value, global_value):
    return instance_value if instance_value not in [None, '', 0] else global_value

# Scheduler config
class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)

def cleanup_old_amis(ec2, instance_name, retention_days):
    images_response = ec2.describe_images(
        Owners=['self'],
        Filters=[
            {'Name': 'tag:CreatedBy', 'Values': ['AutoBackup']},
            {'Name': 'tag:InstanceName', 'Values': [instance_name]}
        ]
    )
    now = datetime.now(timezone.utc)
    for image in images_response['Images']:
        creation_date = datetime.strptime(image['CreationDate'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        age_days = (now - creation_date).days
        if age_days > retention_days:
            ami_id_to_delete = image['ImageId']
            # Delete associated snapshots
            for mapping in image.get('BlockDeviceMappings', []):
                ebs = mapping.get('Ebs')
                if ebs and 'SnapshotId' in ebs:
                    try:
                        ec2.delete_snapshot(SnapshotId=ebs['SnapshotId'])
                        print(f"Deleted snapshot {ebs['SnapshotId']} for AMI {ami_id_to_delete}")
                    except Exception as e:
                        print(f"Could not delete snapshot {ebs['SnapshotId']}: {e}")
            # Deregister the AMI
            try:
                ec2.deregister_image(ImageId=ami_id_to_delete)
                print(f"Deregistered AMI {ami_id_to_delete} (age: {age_days} days)")
            except Exception as e:
                print(f"Could not deregister AMI {ami_id_to_delete}: {e}")

def backup_instance(instance_id):
    with app.app_context():
        inst = Instance.query.filter_by(instance_id=instance_id).first()
        global_config = BackupSettings.query.first()
        if not inst or not global_config:
            print(f"Instance or global config missing for {instance_id}")
            return

        retention_days = get_effective_setting(inst.retention_days, global_config.retention_days)
        region = inst.region
        access_key = inst.access_key
        secret_key = inst.secret_key

        try:
            ec2 = boto3.client(
                'ec2',
                region_name=region,
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key
            )
            # Get instance name from AWS tags
            tags_response = ec2.describe_tags(
                Filters=[
                    {'Name': 'resource-id', 'Values': [inst.instance_id]},
                    {'Name': 'key', 'Values': ['Name']}
                ]
            )
            instance_name = None
            for tag in tags_response.get('Tags', []):
                if tag['Key'] == 'Name':
                    instance_name = tag['Value']
                    break
            if not instance_name:
                print(f"No name tag for {inst.instance_id}")
                return

            # Create AMI
            zone = pytz.timezone('Asia/Kolkata')
            timestamp_str = datetime.now(zone).strftime("%Y_%m_%d_%I_%M_%p")
            ami_name = f"{instance_name}_{timestamp_str}"
            ami_response = ec2.create_image(
                InstanceId=inst.instance_id,
                Name=ami_name,
                NoReboot=True
            )
            ami_id = ami_response['ImageId']

            # Tag the AMI
            ec2.create_tags(
                Resources=[ami_id],
                Tags=[
                    {'Key': 'CreatedBy', 'Value': 'AutoBackup'},
                    {'Key': 'InstanceName', 'Value': instance_name}
                ]
            )

            # Record backup in DB
            backup = Backup(
                instance_id=inst.instance_id,
                instance_name=instance_name,
                ami_id=ami_id,
                ami_name=ami_name,
                timestamp=datetime.utcnow(),
                status='Success',
                region=region,
                retention_days=retention_days
            )
            db.session.add(backup)
            db.session.commit()

            print(f"Backup success for {inst.instance_id} at {datetime.utcnow()}")

            # Cleanup old AMIs and snapshots
            cleanup_old_amis(ec2, instance_name, retention_days)

        except Exception as e:
            print(f"Backup failed for {inst.instance_id}: {str(e)}")
            # Optionally record failure in DB

def schedule_all_instance_backups():
    with app.app_context():
        global_config = BackupSettings.query.first()
        instances = Instance.query.all()
        scheduled_ids = set()

        for inst in instances:
            job_id = f"backup_{inst.instance_id}"
            scheduled_ids.add(job_id)
            print(f"Rescheduling {inst.instance_id}: frequency={inst.backup_frequency}")

            # Remove any existing job with this ID before scheduling
            try:
                scheduler.remove_job(job_id)
                print(f"Removed old job: {job_id}")
            except Exception as e:
                # Only log if the job existed before
                if "No job by the id" not in str(e):
                    print(f"Could not remove job {job_id}: {e}")

            freq = get_effective_setting(
                getattr(inst, 'backup_frequency', None),
                global_config.backup_frequency if global_config else "5"
            )
            print(f"Scheduling {inst.instance_id} with freq: {freq}")

            # Schedule as interval or cron
            try:
                freq_int = int(freq)
                scheduler.add_job(
                    id=job_id,
                    func=backup_instance,
                    args=[inst.instance_id],
                    trigger='interval',
                    minutes=freq_int,
                    replace_existing=True
                )
                print(f"Scheduled backup for {inst.instance_id} every {freq_int} minutes.")
            except ValueError:
                cron_parts = freq.strip().split()
                if len(cron_parts) == 5:
                    scheduler.add_job(
                        id=job_id,
                        func=backup_instance,
                        args=[inst.instance_id],
                        trigger='cron',
                        minute=cron_parts[0],
                        hour=cron_parts[1],
                        day=cron_parts[2],
                        month=cron_parts[3],
                        day_of_week=cron_parts[4],
                        replace_existing=True
                    )
                    print(f"Scheduled backup for {inst.instance_id} with cron: {freq}")
                else:
                    print(f"Invalid backup frequency for {inst.instance_id}: {freq}")

        # Remove any jobs that are no longer associated with an active instance
        current_jobs = {job.id for job in scheduler.get_jobs()}
        for job_id in current_jobs:
            if job_id.startswith("backup_") and job_id not in scheduled_ids:
                try:
                    scheduler.remove_job(job_id)
                    print(f"Cleaned up stale job: {job_id}")
                except Exception as e:
                    print(f"Could not remove stale job {job_id}: {e}")

        print("Current scheduled jobs:", scheduler.get_jobs())


@app.route('/reschedule-backups')
def reschedule_backups():
    schedule_all_instance_backups()
    return "Rescheduled all instance backups!", 200

@app.route('/search-suggestions')
def search_suggestions():
    # Gather unique instance names, instance IDs, and AMI IDs from the database
    instance_names = [i.instance_name for i in Instance.query.with_entities(Instance.instance_name).distinct() if i.instance_name]
    instance_ids = [i.instance_id for i in Instance.query.with_entities(Instance.instance_id).distinct() if i.instance_id]
    ami_ids = [b.ami_id for b in Backup.query.with_entities(Backup.ami_id).distinct() if b.ami_id]
    # Combine and deduplicate
    suggestions = list(set(instance_names + instance_ids + ami_ids))
    return jsonify(suggestions)

#@app.route('/dashboard')
#def dashboard():
#    instances = Instance.query.all()  # Each Instance object should have .backup_frequency
#    return render_template('dashboard.html', instances=instances)

@app.route('/api/instances')
def api_instances():
    instances = Instance.query.all()
    return jsonify([{'instance_id': i.instance_id, 'instance_name': i.instance_name} for i in instances])

@app.route('/api/amis')
def api_amis():
    instance_ids = request.args.get('instances', '').split(',')
    amis = Backup.query.filter(Backup.instance_id.in_(instance_ids)).all()
    return jsonify([{'ami_id': b.ami_id, 'instance_name': b.instance_name} for b in amis])

@app.route('/bulk-delete-amis', methods=['POST'])
def bulk_delete_amis():
    data = request.get_json()
    instance_ids = data.get('instances', [])
    deleted_amis = []
    errors = []

    for inst_id in instance_ids:
        backups = Backup.query.filter_by(instance_id=inst_id).all()
        for b in backups:
            try:
                inst = Instance.query.filter_by(instance_id=inst_id).first()
                ec2 = boto3.client(
                    'ec2',
                    region_name=inst.region,
                    aws_access_key_id=inst.access_key,
                    aws_secret_access_key=inst.secret_key
                )
                # Deregister AMI
                ec2.deregister_image(ImageId=b.ami_id)
                # Delete associated snapshots
                image = ec2.describe_images(ImageIds=[b.ami_id])['Images'][0]
                for mapping in image.get('BlockDeviceMappings', []):
                    ebs = mapping.get('Ebs')
                    if ebs and 'SnapshotId' in ebs:
                        ec2.delete_snapshot(SnapshotId=ebs['SnapshotId'])
                deleted_amis.append(b.ami_id)
            except Exception as e:
                errors.append(f"Error deleting AMI {b.ami_id}: {e}")

        # Bulk delete all Backup records for this instance
        Backup.query.filter_by(instance_id=inst_id).delete(synchronize_session=False)
    db.session.commit()  # Commit after all deletes[2][4]

    if deleted_amis:
        flash(f"Deleted AMIs: {', '.join(deleted_amis)}", "success")
    if errors:
        flash("Some errors occurred: " + " | ".join(errors), "danger")

    return redirect('/')


############## delete ami working  #############################
@app.route('/delete-ami/<ami_id>', methods=['POST'])
def delete_ami(ami_id):
    backup = Backup.query.filter_by(ami_id=ami_id).first()
    if not backup:
        flash("AMI record not found.", "danger")
        return redirect(url_for('dashboard'))  # Replace with your actual backups page endpoint

    # Get AWS credentials and region from the instance or backup record
    instance = Instance.query.filter_by(instance_id=backup.instance_id).first()
    if not instance:
        flash("Instance record not found.", "danger")
        return redirect(url_for('dashboard'))

    try:
        ec2 = boto3.client(
            'ec2',
            region_name=backup.region,
            aws_access_key_id=instance.access_key,
            aws_secret_access_key=instance.secret_key
        )
        # Get AMI details to find associated snapshots
        image = ec2.describe_images(ImageIds=[ami_id])['Images'][0]

        # Deregister the AMI
        ec2.deregister_image(ImageId=ami_id)
        flash(f"AMI {ami_id} deregistered.", "success")

        # Delete associated snapshots
        deleted_snapshots = []
        for mapping in image.get('BlockDeviceMappings', []):
            ebs = mapping.get('Ebs')
            if ebs and 'SnapshotId' in ebs:
                try:
                    ec2.delete_snapshot(SnapshotId=ebs['SnapshotId'])
                    deleted_snapshots.append(ebs['SnapshotId'])
                except Exception as e:
                    flash(f"Failed to delete snapshot {ebs['SnapshotId']}: {e}", "danger")
        if deleted_snapshots:
            flash(f"Deleted snapshots: {', '.join(deleted_snapshots)}", "success")

        # Optionally, remove the backup record from the database
        db.session.delete(backup)
        db.session.commit()

    except Exception as e:
        flash(f"Error deleting AMI or snapshots: {e}", "danger")

    return redirect(url_for('dashboard'))


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

#@app.route('/backup-settings', methods=['GET'])
#def backup_settings():
#    config = BackupSettings.query.first()
#    if not config:
#        # Set a default instance_id (replace with your actual logic)
#        config = BackupSettings(instance_id="default-instance-id")
#        db.session.add(config)
#        db.session.commit()
#    return render_template('backup_settings.html', config=config)
#
#@app.route('/update-backup-settings', methods=['POST'])
#def update_backup_settings():
#    config = BackupSettings.query.first()
#    if config:
#        config.retention_days = int(request.form['retention_days'])
#        config.backup_frequency = request.form['backup_frequency']
#        db.session.commit()
#        flash("Backup settings updated", "success")
#    return redirect(url_for('backup_settings'))

@app.route('/backup-settings', methods=['GET'])
def backup_settings():
    config = BackupSettings.query.first()
    if not config:
        # Set a default instance_id (replace with your actual logic)
        config = BackupSettings(instance_id="default-instance-id")
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
        schedule_all_instance_backups()  # Reschedule jobs after global setting change
    return redirect(url_for('backup_settings'))

############################################################ Run ############################################################

if __name__ == '__main__' or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    with app.app_context():
        db.create_all()

        # Create default admin user if none exists
        if not User.query.filter_by(username='admin').first():
            default_admin = User(username='admin', email='admin@example.com')
            default_admin.set_password('admin123')  # 🔐 Change this in production!
            db.session.add(default_admin)
            db.session.commit()
            print("✅ Default admin user created: admin / admin123")

        # Create default backup settings if not exists
        if not BackupSettings.query.first():
            config = BackupSettings(instance_id="default-instance-id")
            db.session.add(config)
            db.session.commit()

        # Schedule all backups and start scheduler
        schedule_all_instance_backups()
        scheduler.start()

    # Only run the Flask app if this is the main process (not when imported by WSGI server)
    app.run(host="0.0.0.0", port=8080, debug=True)
