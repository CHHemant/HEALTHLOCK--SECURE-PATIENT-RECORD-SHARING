import os
import datetime
from datetime import timezone
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
from markupsafe import Markup
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from dotenv import load_dotenv
from io import BytesIO
from flask import send_file
from werkzeug.utils import secure_filename
import uuid
import smtplib
from email.message import EmailMessage
try:
    import qrcode
    from PIL import Image
    qrcode_available = True
except ImportError:
    qrcode_available = False
import base64
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    reportlab_available = True
except ImportError:
    reportlab_available = False

from crypto_utils import load_or_create_fernet, encrypt_text, decrypt_text

# Load environment variables from .env if present
load_dotenv()

# Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///healthlock.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = not app.debug
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=60)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Database
db = SQLAlchemy(app)

# Fernet
fernet = load_or_create_fernet(os.getenv('FERNET_KEY_PATH', 'fernet.key'))

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_qr_code(data):
    """Generate QR code and return as base64 string"""
    try:
        if not qrcode_available:
            app.logger.warning("QR code generation not available - qrcode library not installed")
            return None
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        img_base64 = base64.b64encode(buffer.getvalue()).decode()
        app.logger.info(f"QR code generated successfully for URL: {data[:50]}...")
        return f"data:image/png;base64,{img_base64}"
    except Exception as e:
        app.logger.error(f"Error generating QR code: {str(e)}")
        return None


def get_lan_ip():
    """Return the preferred LAN IP address for the current machine.

    This creates a UDP socket to a public IP and reads the socket's own address
    without sending any data. It's a common technique to discover the host's
    LAN IP even when hostname resolution returns 127.0.0.1.
    """
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # This doesn't need to be reachable; no packets are sent.
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            # Basic sanity check
            if ip and not ip.startswith('127.'):
                return ip
    except Exception:
        app.logger.debug('Failed to determine LAN IP via UDP trick', exc_info=True)
    # Fallback: try hostname lookup
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and not host_ip.startswith('127.'):
            return host_ip
    except Exception:
        app.logger.debug('Hostname lookup for LAN IP failed', exc_info=True)
    return None


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=True)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.Integer, default=0)  # epoch seconds
    emergency_code_hash = db.Column(db.String(255), nullable=True)
    emergency_code_expires = db.Column(db.Integer, default=0)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class PatientRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_name = db.Column(db.String(200), nullable=False)
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    has_pdf = db.Column(db.Boolean, default=False)
    pdf_filename = db.Column(db.String(255), nullable=True)

    created_by = db.relationship('User', backref=db.backref('records', lazy=True))


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    record_id = db.Column(db.Integer, db.ForeignKey('patient_record.id'), nullable=True)
    action = db.Column(db.String(64), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    details = db.Column(db.String(255), nullable=True)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    record = db.relationship('PatientRecord', backref=db.backref('audit_logs', lazy=True))


# DB initialization and default admin user
with app.app_context():
    db.create_all()
    # Ensure new security columns exist (SQLite runtime migration)
    try:
        cols = {c['name'] for c in db.session.execute(db.text("PRAGMA table_info(user)")).mappings()}
        to_add = []
        if 'failed_attempts' not in cols:
            to_add.append("ALTER TABLE user ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        if 'lockout_until' not in cols:
            to_add.append("ALTER TABLE user ADD COLUMN lockout_until INTEGER DEFAULT 0")
        if 'emergency_code_hash' not in cols:
            to_add.append("ALTER TABLE user ADD COLUMN emergency_code_hash VARCHAR(255)")
        if 'emergency_code_expires' not in cols:
            to_add.append("ALTER TABLE user ADD COLUMN emergency_code_expires INTEGER DEFAULT 0")
        if 'email' not in cols:
            to_add.append("ALTER TABLE user ADD COLUMN email VARCHAR(255)")
        for stmt in to_add:
            db.session.execute(db.text(stmt))
        if to_add:
            db.session.commit()
    except Exception:
        app.logger.debug('Column ensure failed (may already exist)', exc_info=True)
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin.set_password('admin')
        db.session.add(admin)
        db.session.commit()


# Auth helpers

@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.session.get(User, user_id)


def log_audit(user_id, record_id, action, details=None):
    entry = AuditLog(user_id=user_id, record_id=record_id, action=action, details=details)
    db.session.add(entry)
    db.session.commit()


def send_email(to_address: str, subject: str, body: str) -> bool:
    """Send an email using environment-configured SMTP.

    Expected environment variables:
      SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_USE_TLS ("1"/"0")
      SMTP_FROM (optional, defaults to SMTP_USER)
    Returns True if send attempted successfully, False otherwise.
    """
    try:
        host = os.getenv('SMTP_HOST')
        port = int(os.getenv('SMTP_PORT', '587'))
        user = os.getenv('SMTP_USER')
        pwd = os.getenv('SMTP_PASS')
        use_tls = os.getenv('SMTP_USE_TLS', '1') == '1'
        sender = os.getenv('SMTP_FROM') or user
        if not (host and port and user and pwd and sender and to_address):
            app.logger.warning('SMTP not fully configured; skipping real email send')
            return False
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = to_address
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            smtp.login(user, pwd)
            smtp.send_message(msg)
        app.logger.info(f"Email sent to {to_address}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email to {to_address}: {e}")
        return False


# TODO: Refactor routes into Flask blueprints for better maintainability.
# (This is a placeholder comment. Full refactor would require new files and moving code.)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('list_records'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not password or not confirm:
            flash('All fields are required.', 'warning')
            return render_template('register.html')
        if len(username) < 3 or len(username) > 80 or not username.isalnum():
            flash('Username must be 3-80 alphanumeric characters.', 'warning')
            return render_template('register.html')
        # Stronger password policy
        if len(password) < 8 or not any(c.islower() for c in password) or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash('Password must be 8+ chars with upper, lower, and number.', 'warning')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'warning')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')
        email = request.form.get('email', '').strip()
        # minimal email format check
        if '@' not in email or '.' not in email:
            flash('Please provide a valid email address.', 'warning')
            return render_template('register.html')
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('list_records'))
    if request.method == 'POST':
        now_ts = int(datetime.datetime.now(timezone.utc).timestamp())
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and now_ts < (user.lockout_until or 0):
            flash('Account locked due to multiple failed attempts. Use Emergency Login.', 'danger')
            return render_template('login.html', locked=True, username=username)
        if user and user.check_password(password):
            session['user_id'] = user.id
            # Reset counters
            user.failed_attempts = 0
            user.lockout_until = 0
            db.session.commit()
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('list_records'))
        else:
            # Increment per-user counters and lock after 5 attempts
            if user:
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= 5:
                    user.lockout_until = now_ts + 300  # 5 minutes
                    log_audit(user.id, None, 'account_locked', details=f"from {request.remote_addr}")
                    # Generate emergency code valid for 10 minutes
                    import secrets
                    code = secrets.token_hex(3)  # short 6 hex chars
                    from werkzeug.security import generate_password_hash
                    user.emergency_code_hash = generate_password_hash(code)
                    user.emergency_code_expires = now_ts + 600
                    db.session.commit()
                    # Email the emergency code if SMTP is configured
                    emailed = False
                    if user.email:
                        subject = 'HealthLock Emergency Access Code'
                        body = f"Hello {user.username},\n\nYour emergency access code is: {code}\nIt expires in 10 minutes. If you did not attempt to sign in, please secure your account immediately.\n\n– HealthLock"
                        emailed = send_email(user.email, subject, body)
                    if emailed:
                        flash('Account locked. Emergency code sent to your recovery email.', 'warning')
                    else:
                        flash('Account locked. Emergency code generated (SMTP not configured).', 'warning')
                    return redirect(url_for('emergency_login', username=username))
                db.session.commit()
            flash('Login failed. Invalid username or password.', 'danger')
            return render_template('login.html')
    return render_template('login.html')


@app.route('/emergency-login', methods=['GET', 'POST'])
def emergency_login():
    username = request.args.get('username', '')
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        code = request.form.get('code', '').strip()
        user = User.query.filter_by(username=username).first()
        if not user:
            flash('Invalid username.', 'danger')
            return render_template('emergency_login.html', username=username)
        now_ts = int(datetime.datetime.now(timezone.utc).timestamp())
        if not user.emergency_code_hash or not user.emergency_code_expires or now_ts > (user.emergency_code_expires or 0):
            flash('Emergency code expired. Please attempt normal login to generate a new code.', 'warning')
            return render_template('emergency_login.html', username=username)
        from werkzeug.security import check_password_hash
        if check_password_hash(user.emergency_code_hash, code):
            # Reset lock and log in
            user.failed_attempts = 0
            user.lockout_until = 0
            user.emergency_code_hash = None
            user.emergency_code_expires = 0
            db.session.commit()
            session['user_id'] = user.id
            log_audit(user.id, None, 'emergency_login', details=f"from {request.remote_addr}")
            flash('Emergency login successful. Please update your password if needed.', 'info')
            return redirect(url_for('list_records'))
        else:
            log_audit(user.id, None, 'emergency_login_failed', details=f"from {request.remote_addr}")
            flash('Invalid emergency code.', 'danger')
            return render_template('emergency_login.html', username=username)
    return render_template('emergency_login.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    """Request password reset by username."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('If that username exists, an email has been sent with reset instructions.', 'info')
            return render_template('forgot.html')
        
        if not user.email:
            flash('Account has no email on file. Unable to send reset link.', 'warning')
            return render_template('forgot.html')
        
        # Generate password reset token (valid for 1 hour)
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        reset_token = s.dumps(user.id)
        reset_url = url_for('reset', token=reset_token, _external=True)
        
        # Send email with reset link
        subject = 'Password Reset Request'
        body = f"""Hello {user.username},

You requested to reset your password. Click the link below to proceed:

{reset_url}

This link expires in 1 hour. If you did not request this, you can safely ignore this email.

– HealthLock Team"""
        
        if send_email(user.email, subject, body):
            flash('Password reset instructions have been sent to your email.', 'success')
        else:
            flash('Could not send email. SMTP may not be configured.', 'warning')
        
        return render_template('forgot.html')
    
    return render_template('forgot.html')


@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset(token):
    """Reset password using a valid reset token."""
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    try:
        user_id = s.loads(token, max_age=3600)  # Token valid for 1 hour
        user = db.session.get(User, user_id)
        if not user:
            flash('Invalid reset link.', 'danger')
            return redirect(url_for('login'))
    except (BadSignature, SignatureExpired):
        flash('Reset link has expired. Please request a new one.', 'danger')
        return redirect(url_for('forgot'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        
        if not password or not confirm:
            flash('Both password fields are required.', 'warning')
            return render_template('reset.html')
        
        # Enforce password policy
        if len(password) < 8 or not any(c.islower() for c in password) or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash('Password must be 8+ chars with upper, lower, and number.', 'warning')
            return render_template('reset.html')
        
        if password != confirm:
            flash('Passwords do not match.', 'warning')
            return render_template('reset.html')
        
        # Update password
        user.set_password(password)
        db.session.commit()
        log_audit(user.id, None, 'password_reset', details='via forgot password flow')
        
        flash('Password reset successful. Please log in with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset.html')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/records')
@login_required
def list_records():
    records = PatientRecord.query.order_by(PatientRecord.created_at.desc()).all()
    return render_template('records_list.html', records=records)


@app.route('/records/<int:record_id>')
@login_required
def view_record(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    try:
        decrypted_content = decrypt_text(fernet, record.encrypted_content)
    except (BadSignature, SignatureExpired):
        flash('Record content is corrupted or expired.', 'danger')
        return redirect(url_for('list_records'))
    return render_template('record_view.html', record=record, content=decrypted_content)


@app.route('/records/new', methods=['GET', 'POST'])
@login_required
def create_record():
    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        content = request.form.get('content', '')
        pdf_file = request.files.get('pdf_file')
        
        if not patient_name or not content:
            flash('Patient name and content are required.', 'warning')
            return render_template('record_new.html')
        if len(patient_name) < 2 or len(patient_name) > 200:
            flash('Patient name must be 2-200 characters.', 'warning')
            return render_template('record_new.html')
        if len(content) < 5:
            flash('Record content must be at least 5 characters.', 'warning')
            return render_template('record_new.html')
        
        # Handle PDF upload
        pdf_filename = None
        has_pdf = False
        if pdf_file and pdf_file.filename:
            if not allowed_file(pdf_file.filename):
                flash('Only PDF files are allowed.', 'warning')
                return render_template('record_new.html')
            
            # Generate secure filename
            file_ext = pdf_file.filename.rsplit('.', 1)[1].lower()
            pdf_filename = f"{uuid.uuid4().hex}.{file_ext}"
            pdf_file.save(os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename))
            has_pdf = True
        
        encrypted = encrypt_text(fernet, content)
        record = PatientRecord(
            patient_name=patient_name,
            encrypted_content=encrypted,
            created_by_user_id=get_current_user().id,
            has_pdf=has_pdf,
            pdf_filename=pdf_filename
        )
        db.session.add(record)
        db.session.commit()
        
        if has_pdf:
            flash('Record created with PDF attachment.', 'success')
        else:
            flash('Record created.', 'success')
        return redirect(url_for('list_records'))
    return render_template('record_new.html')


@app.route('/records/<int:record_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_record(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    if record.created_by_user_id != get_current_user().id:
        flash('You do not have permission to edit this record.', 'danger')
        return redirect(url_for('list_records'))

    if request.method == 'POST':
        patient_name = request.form.get('patient_name', '').strip()
        content = request.form.get('content', '')
        if not patient_name or not content:
            flash('Patient name and content are required.', 'warning')
            return render_template('record_edit.html', record=record)
        if len(patient_name) < 2 or len(patient_name) > 200:
            flash('Patient name must be 2-200 characters.', 'warning')
            return render_template('record_edit.html', record=record)
        if len(content) < 5:
            flash('Record content must be at least 5 characters.', 'warning')
            return render_template('record_edit.html', record=record)
        encrypted = encrypt_text(fernet, content)
        record.patient_name = patient_name
        record.encrypted_content = encrypted
        db.session.commit()
        flash('Record updated.', 'success')
        return redirect(url_for('list_records'))
    return render_template('record_edit.html', record=record)


@app.route('/records/<int:record_id>/delete', methods=['POST'])
@login_required
def delete_record(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    if record.created_by_user_id != get_current_user().id:
        flash('You do not have permission to delete this record.', 'danger')
        return redirect(url_for('list_records'))

    try:
        db.session.delete(record)
        db.session.commit()
        flash('Record deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting record: {e}', 'danger')
    return redirect(url_for('list_records'))


@app.route('/audit_logs')
@login_required
def view_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_log.html', logs=logs)


@app.route('/records/<int:record_id>/share', methods=['GET', 'POST'])
@login_required
def share_record(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    default_max_age = int(os.getenv('SHARE_TOKEN_MAX_AGE_SECONDS', '3600'))
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    
    if request.method == 'POST':
        # Get the selected time limit from the form
        try:
            selected_time = int(request.form.get('time_limit', default_max_age))
            # Ensure the time is within reasonable bounds (1 minute to 1 week)
            selected_time = max(60, min(selected_time, 604800))  # 1 minute to 1 week
        except (ValueError, TypeError):
            selected_time = default_max_age
        
        # Store both record_id and expiration time in the token
        token_data = {
            'record_id': record.id,
            'expires_at': datetime.datetime.now(timezone.utc).timestamp() + selected_time
        }
        token = s.dumps(token_data)
        
        # Generate the share URL with proper external access
        # Use the request host to ensure mobile devices can access it
        base_url = request.url_root.rstrip('/')
        share_url = f"{base_url}/share/{token}"
        
        # Log the generated URL for debugging
        app.logger.info(f"Generated share URL: {share_url} (expires in {selected_time} seconds)")
        
        # Public QR
        qr_code = generate_qr_code(share_url)

        # Try to also provide a LAN-based URL/QR for users on the same Wi-Fi
        lan_ip = get_lan_ip()
        lan_share_url = None
        lan_qr_code = None
        if lan_ip:
            # Use the same port that the request was received on
            try:
                request_port = request.environ.get('SERVER_PORT') or str(request.host).split(':')[-1]
            except Exception:
                request_port = None
            if request_port and request_port not in ('80', '443'):
                lan_share_url = f"http://{lan_ip}:{request_port}/share/{token}"
            else:
                lan_share_url = f"http://{lan_ip}/share/{token}"
            lan_qr_code = generate_qr_code(lan_share_url)
            app.logger.info(f"Generated LAN share URL: {lan_share_url}")
        else:
            app.logger.warning("Could not detect LAN IP address")

        return render_template('share_link.html', share_url=share_url, max_age=selected_time, qr_code=qr_code, lan_share_url=lan_share_url, lan_qr_code=lan_qr_code)
    return render_template('share_confirm.html', record=record, max_age=default_max_age)

@app.route('/share/<token>')
def open_shared_record(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    # Use a reasonable maximum age for token validation (1 week)
    max_age = 604800  # 1 week in seconds
    try:
        data = s.loads(token, max_age=max_age)
        record_id = data['record_id']
        
        # Check if the token has expired based on the custom expiration time
        if 'expires_at' in data:
            current_time = datetime.datetime.now(timezone.utc).timestamp()
            if current_time > data['expires_at']:
                return render_template('share_open.html', error='This link has expired.')
        
        record = PatientRecord.query.get(record_id)
        if not record:
            return render_template('share_open.html', error='Record not found.')
        content = decrypt_text(fernet, record.encrypted_content)
        # Audit: shared record viewed
        try:
            log_audit(None, record.id, 'share_view', details=f"from {request.remote_addr}")
        except Exception:
            app.logger.debug('audit log failed for share_view', exc_info=True)
        return render_template('share_open.html', record=record, content=content)
    except (BadSignature, SignatureExpired):
        return render_template('share_open.html', error='This link is invalid or has expired.')


@app.route('/share/<token>/pdf')
def share_pdf_view(token):
    """Secure, read-only PDF viewer for shared links.
    Renders a minimal PDF.js-based viewer with no download/print UI.
    """
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=604800)
        # Expiry enforcement
        if 'expires_at' in data and datetime.datetime.now(timezone.utc).timestamp() > data['expires_at']:
            return render_template('share_open.html', error='This link has expired.')
        record = PatientRecord.query.get(data['record_id'])
        if not record or not record.has_pdf or not record.pdf_filename:
            return render_template('share_open.html', error='No PDF is attached to this record.')
        file_url = url_for('share_pdf_file', token=token)
        try:
            log_audit(None, record.id, 'share_pdf_view', details=f"from {request.remote_addr}")
        except Exception:
            app.logger.debug('audit log failed for share_pdf_view', exc_info=True)
        return render_template('share_pdf_view.html', record=record, file_url=file_url)
    except (BadSignature, SignatureExpired):
        return render_template('share_open.html', error='This link is invalid or has expired.')


@app.route('/share/<token>/pdf/file')
def share_pdf_file(token):
    """Streams the PDF inline with headers discouraging download/print/caching."""
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=604800)
        if 'expires_at' in data and datetime.datetime.now(timezone.utc).timestamp() > data['expires_at']:
            return render_template('share_open.html', error='This link has expired.')
        record = PatientRecord.query.get(data['record_id'])
        if not record or not record.has_pdf or not record.pdf_filename:
            return render_template('share_open.html', error='No PDF is attached to this record.')
        response = send_from_directory(
            app.config['UPLOAD_FOLDER'],
            record.pdf_filename,
            as_attachment=False,
            mimetype='application/pdf'
        )
        try:
            log_audit(None, record.id, 'share_pdf_stream', details=f"from {request.remote_addr}")
        except Exception:
            app.logger.debug('audit log failed for share_pdf_stream', exc_info=True)
        # Best-effort hardening headers (cannot fully prevent download/screenshots)
        response.headers['Content-Disposition'] = 'inline; filename="document.pdf"'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # CSP sandbox to limit capabilities while allowing same-origin scripts to render
        response.headers['Content-Security-Policy'] = "sandbox allow-scripts allow-same-origin"
        return response
    except (BadSignature, SignatureExpired):
        return render_template('share_open.html', error='This link is invalid or has expired.')


@app.route('/records/<int:record_id>/pdf')
@login_required
def record_pdf(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    # Only the record owner can download PDF
    if record.created_by_user_id != get_current_user().id:
        flash('You do not have permission to download this record.', 'danger')
        return redirect(url_for('list_records'))
    
    try:
        decrypted_content = decrypt_text(fernet, record.encrypted_content)
    except (BadSignature, SignatureExpired):
        flash('Record content is corrupted or expired.', 'danger')
        return redirect(url_for('list_records'))
    
    if not reportlab_available:
        flash('PDF generation is not available. Please install reportlab.', 'error')
        return redirect(url_for('view_record', record_id=record_id))
    
    # Create PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Add content
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, height - 100, f"Patient Record #{record.id}")
    p.drawString(100, height - 130, f"Patient: {record.patient_name}")
    p.drawString(100, height - 160, f"Created: {record.created_at.strftime('%Y-%m-%d %H:%M')}")
    
    # Add record content
    p.setFont("Helvetica", 12)
    y_position = height - 200
    lines = decrypted_content.split('\n')
    for line in lines:
        if y_position < 100:  # Start new page if needed
            p.showPage()
            y_position = height - 50
        p.drawString(100, y_position, line[:80])  # Limit line length
        y_position -= 20
    
    p.save()
    buffer.seek(0)
    
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f'record_{record.id}_{record.patient_name}.pdf',
        mimetype='application/pdf'
    )


@app.route('/records/<int:record_id>/pdf_download')
@login_required
def download_record_pdf(record_id):
    record = PatientRecord.query.get_or_404(record_id)
    # Only the record owner can download the uploaded PDF
    if record.created_by_user_id != get_current_user().id:
        flash('You do not have permission to download this file.', 'danger')
        return redirect(url_for('list_records'))
    
    if not record.has_pdf or not record.pdf_filename:
        flash('No PDF file attached to this record.', 'warning')
        return redirect(url_for('view_record', record_id=record_id))
    
    try:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            record.pdf_filename, 
            as_attachment=True,
            download_name=f'record_{record.id}_{record.patient_name}_attachment.pdf'
        )
    except FileNotFoundError:
        flash('PDF file not found.', 'error')
        return redirect(url_for('view_record', record_id=record_id))


@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# Set up logging
if not app.debug:
    handler = RotatingFileHandler('app.log', maxBytes=100000, backupCount=3)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)

# Global security headers
@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-XSS-Protection', '0')
    # CSP with external CDN support for Bootstrap, FontAwesome, and Google Fonts
    csp = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; object-src 'none'"
    response.headers.setdefault('Content-Security-Policy', csp)
    return response

@app.errorhandler(404)
def not_found_error(error):
    app.logger.warning(f'404 Not Found: {error}')
    return render_template('error.html', code=404, message='Page not found.'), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'500 Internal Server Error: {error}', exc_info=True)
    return render_template('error.html', code=500, message='An internal error occurred.'), 500


if __name__ == '__main__':
    port = int(os.getenv('PORT', '5000'))
    app.run(debug=True, host='0.0.0.0', port=port)
