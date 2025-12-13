import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, Admin, OTP, Score
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-this')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'mysql+pymysql://root:@localhost/scorelock')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'scores')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('library'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('library'))

    if request.method == 'POST':
        login_type = request.form.get('login_type')

        if login_type == 'otp':
            otp_code = request.form.get('otp_code')
            otp = OTP.query.filter_by(code=otp_code, is_active=True).first()

            if otp:
                # Mark OTP as used
                otp.used_at = datetime.utcnow()
                db.session.commit()
                flash('Welcome! You have been authenticated with OTP.', 'success')
                return redirect(url_for('library'))
            else:
                flash('Invalid or expired OTP code.', 'danger')

        elif login_type == 'admin':
            username = request.form.get('username')
            password = request.form.get('password')
            admin = Admin.query.filter_by(username=username).first()

            if admin and admin.check_password(password):
                login_user(admin)
                flash(f'Welcome back, {username}!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/library')
def library():
    scores = Score.query.order_by(Score.uploaded_at.desc()).all()
    return render_template('library.html', scores=scores)

@app.route('/scores/<int:score_id>')
def view_score(score_id):
    score = Score.query.get_or_404(score_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], score.filename)

@app.route('/admin')
@login_required
def admin_dashboard():
    otps = OTP.query.filter_by(created_by=current_user.id).order_by(OTP.created_at.desc()).all()
    scores = Score.query.order_by(Score.uploaded_at.desc()).all()
    return render_template('admin.html', otps=otps, scores=scores)

