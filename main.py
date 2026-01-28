import os
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, Admin, OTP, Score, SiteSettings, Policy, PolicyAcceptance
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect, generate_csrf
from uuid import uuid4
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from urllib.parse import urlparse, urljoin
from sqlalchemy.exc import IntegrityError

ITEMS_PER_PAGE = 12

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-this')

# Database configuration with SQLite as default fallback
db_url = os.getenv('DATABASE_URL', 'sqlite:///scorelock.db')

# If using SQLite and path is relative, ensure it's in the app directory
if db_url.startswith('sqlite:///') and not db_url.startswith('sqlite:////'):
    # Extract the database filename
    db_filename = db_url.replace('sqlite:///', '')
    if not os.path.isabs(db_filename):
        # Make it relative to the app directory
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), db_filename)
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        db_url = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'scores')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # OTP sessions last 1 hour by default

# Initialize extensions
db.init_app(app)
csrf = CSRFProtect(app)

# Initialize rate limiter (in-memory backend). Limits are applied per remote IP.
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])

# Expose a helper in templates that returns the raw CSRF token string
def _csrf_token():
    try:
        return generate_csrf()
    except Exception:
        return ''

app.jinja_env.globals['csrf_token'] = _csrf_token

# Load translations from separate module
from translations import translations, available_languages

def t(key):
    """Translate key using current session language (fallback to English or key)."""
    lang = session.get('lang', 'en')
    return translations.get(lang, translations['en']).get(key, translations['en'].get(key, key))

app.jinja_env.globals['t'] = t
app.jinja_env.globals['available_languages'] = available_languages

@app.context_processor
def inject_site_settings():
    """Inject site settings into all templates"""
    try:
        settings = SiteSettings.get_settings()
        return {'site_settings': settings}
    except Exception:
        # Return defaults if database isn't initialized yet
        return {'site_settings': None}


def is_safe_url(target):
    """Return True if the target URL is same-origin (safe) relative to the request host."""
    try:
        host_url = request.host_url
        ref_url = urlparse(host_url)
        test_url = urlparse(urljoin(host_url, target))
        return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc
    except Exception:
        return False


@app.route('/set_language', methods=['POST'])
def set_language():
    lang = request.form.get('lang')
    if lang in translations:
        session['lang'] = lang
    # Redirect back to referring page if it's same-origin; otherwise go to index
    ref = request.referrer
    if ref and is_safe_url(ref):
        return redirect(ref)
    return redirect(url_for('index'))

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

def is_authorized():
    """Return True if the request is authenticated via admin login or OTP session."""
    try:
        return current_user.is_authenticated or session.get('otp_authenticated')
    except Exception:
        return False

# File upload helper functions

def validate_and_process_upload(file_obj, allowed_extensions, max_size_bytes, file_type_name, filename_prefix):
    """
    Validate and process an uploaded file.

    Args:
        file_obj: FileStorage object from request.files
        allowed_extensions: Set of allowed file extensions (e.g., {'.png', '.jpg'})
        max_size_bytes: Maximum allowed file size in bytes
        file_type_name: Display name for error messages (e.g., 'Logo', 'Favicon')
        filename_prefix: Prefix for the saved filename (e.g., 'logo_', 'favicon_')

    Returns:
        Tuple of (success: bool, filename: str or None, error_message: str or None)
    """
    if not file_obj or file_obj.filename == '':
        return False, None, None

    # Validate file type
    file_ext = os.path.splitext(file_obj.filename.lower())[1]
    if file_ext not in allowed_extensions:
        ext_list = ', '.join(sorted(allowed_extensions)).upper()
        return False, None, f'{file_type_name} must be one of: {ext_list}'

    # Read and validate file size
    data = file_obj.read()
    if len(data) > max_size_bytes:
        size_mb = max_size_bytes / (1024 * 1024)
        return False, None, f'{file_type_name} file is too large (max {size_mb:.0f}MB)'

    # Generate secure filename
    filename = secure_filename(file_obj.filename)
    if not filename:
        filename = f"{uuid4().hex}{file_ext}"

    filename = filename.replace(os.path.sep, '_').replace('/', '_').lstrip('.')
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
    filename = f"{filename_prefix}{timestamp}{filename}"

    return True, filename, data

def save_uploaded_file(filename, data, old_filename=None):
    """
    Save an uploaded file to the static folder with path validation.

    Args:
        filename: The secure filename to save as
        data: Binary file data
        old_filename: Optional old filename to delete

    Returns:
        Tuple of (success: bool, error_message: str or None)
    """
    static_folder = os.path.join(app.root_path, 'static')
    filepath = os.path.join(static_folder, filename)

    # Validate path to prevent traversal attacks
    static_folder_abs = os.path.abspath(static_folder)
    filepath_abs = os.path.abspath(filepath)

    try:
        if os.path.commonpath([static_folder_abs, filepath_abs]) != static_folder_abs:
            app.logger.error('Detected attempted path traversal in file upload: %s', filepath_abs)
            return False, 'Invalid upload path'
    except Exception as e:
        app.logger.exception('Error validating upload path: %s', e)
        return False, 'Invalid upload path'

    # Delete old file if it exists
    if old_filename:
        old_filepath = os.path.join(static_folder, old_filename)
        try:
            if os.path.exists(old_filepath):
                os.remove(old_filepath)
        except Exception as e:
            app.logger.exception('Failed to remove old file %s: %s', old_filename, e)

    # Save new file
    try:
        with open(filepath, 'wb') as f:
            f.write(data)
        return True, None
    except Exception as e:
        app.logger.exception('Failed to save file %s: %s', filename, e)
        return False, f'Failed to save {filename}'

def delete_static_file(filename):
    """
    Delete a file from the static folder.

    Args:
        filename: The filename to delete

    Returns:
        bool: True if successful or file didn't exist, False on error
    """
    if not filename:
        return True

    static_folder = os.path.join(app.root_path, 'static')
    filepath = os.path.join(static_folder, filename)

    try:
        if os.path.exists(filepath):
            os.remove(filepath)
        return True
    except Exception as e:
        app.logger.exception('Failed to delete file %s: %s', filename, e)
        return False

# Routes
@app.route('/')
def index():
    # Allow access if admin logged in or OTP session present
    if current_user.is_authenticated or session.get('otp_authenticated'):
        return redirect(url_for('library'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
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

                # Create a short-lived session flag for OTP-authenticated users
                session.permanent = True
                session['otp_authenticated'] = True
                session['otp_id'] = otp.id

                # Get or create session ID for policy tracking
                if 'policy_session_id' not in session:
                    session['policy_session_id'] = str(uuid4())

                # Check if this session needs to accept policies
                session_id = session['policy_session_id']
                pending_policies = PolicyAcceptance.get_pending_policies_for_session(session_id)
                if pending_policies:
                    # Redirect to policy acceptance page
                    return redirect(url_for('policy_acceptance'))

                flash('Welcome! You have been authenticated with OTP for limited access.', 'success')
                return redirect(url_for('library'))
            else:
                flash('Invalid or expired OTP code.', 'danger')

        elif login_type == 'admin':
            username = request.form.get('username')
            password = request.form.get('password')
            admin = Admin.query.filter_by(username=username).first()

            if admin and admin.check_password(password):
                login_user(admin)
                # Avoid echoing username (user-controlled) into a flash message to prevent possible XSS
                flash('Welcome back!', 'success')
                return redirect(url_for('admin_dashboard'))
            else:
                flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear OTP session flag if present
    session.pop('otp_authenticated', None)
    session.pop('otp_id', None)

    # If admin is logged in, log them out
    if current_user.is_authenticated:
        logout_user()
        flash('You have been logged out.', 'info')
    else:
        flash('Session cleared.', 'info')
    return redirect(url_for('login'))

@app.route('/library')
def library():
    if not is_authorized():
        flash('Please login to access the library.', 'warning')
        return redirect(url_for('login'))

    # Check if OTP user has accepted all policies
    if session.get('otp_authenticated'):
        session_id = session.get('policy_session_id')

        # If session_id is missing, create one for proper policy tracking
        if not session_id:
            session['policy_session_id'] = str(uuid4())
            session_id = session['policy_session_id']

        pending_policies = PolicyAcceptance.get_pending_policies_for_session(session_id)
        if pending_policies:
            flash('You must accept all policies to access the library.', 'warning')
            return redirect(url_for('policy_acceptance'))

    # Support simple search via ?q=term (searches title and composer, case-insensitive)
    q = request.args.get('q', '')
    # Sanitize and limit length to avoid abuse
    q = q.strip()
    max_query_length = 200
    if len(q) > max_query_length:
        q = q[:max_query_length]

    # View type: 'tiles' (default) or 'list'
    view = request.args.get('view', 'tiles')
    if view not in ['tiles', 'list']:
        view = 'tiles'

    # Sorting parameter
    sort = request.args.get('sort', 'date_desc')
    valid_sorts = ['date_desc', 'date_asc', 'title_asc', 'title_desc', 'composer_asc']
    if sort not in valid_sorts:
        sort = 'date_desc'

    # Pagination parameters
    page_raw = request.args.get('page', 1)
    try:
        page = int(page_raw)
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    per_page = ITEMS_PER_PAGE  # number of items per page

    # Build base query
    if not q:
        query = Score.query
    else:
        # Escape SQL LIKE wildcards so user input is treated literally.
        # Replace backslash first to avoid double-escaping.
        q_escaped = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        like_pattern = f"%{q_escaped}%"
        # Pass escape='\\' so the DB knows how to interpret backslash escapes.
        query = Score.query.filter(
            (Score.title.ilike(like_pattern, escape='\\')) | (Score.composer.ilike(like_pattern, escape='\\'))
        )

    # Apply sorting
    if sort == 'date_desc':
        query = query.order_by(Score.uploaded_at.desc())
    elif sort == 'date_asc':
        query = query.order_by(Score.uploaded_at.asc())
    elif sort == 'title_asc':
        query = query.order_by(Score.title.asc())
    elif sort == 'title_desc':
        query = query.order_by(Score.title.desc())
    elif sort == 'composer_asc':
        query = query.order_by(Score.composer.asc(), Score.title.asc())

    # Use SQLAlchemy pagination to avoid loading all results into memory
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    scores = pagination.items

    return render_template('library.html', scores=scores, q=q, pagination=pagination, view=view, sort=sort)

@app.route('/scores/<int:score_id>')
def view_score(score_id):
    if not is_authorized():
        flash('Please login to access the score.', 'warning')
        return redirect(url_for('login'))

    # Check if OTP user has accepted all policies
    if session.get('otp_authenticated'):
        session_id = session.get('policy_session_id')

        # If session_id is missing, create one for proper policy tracking
        if not session_id:
            session['policy_session_id'] = str(uuid4())
            session_id = session['policy_session_id']

        pending_policies = PolicyAcceptance.get_pending_policies_for_session(session_id)
        if pending_policies:
            flash('You must accept all policies to access scores.', 'warning')
            return redirect(url_for('policy_acceptance'))

    score = Score.query.get_or_404(score_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], score.filename)

@app.route('/admin')
@login_required
def admin_dashboard():
    otps = OTP.query.filter_by(created_by=current_user.id).order_by(OTP.created_at.desc()).all()
    scores = Score.query.order_by(Score.uploaded_at.desc()).all()
    settings = SiteSettings.get_settings()
    policies = Policy.query.order_by(Policy.created_at.desc()).all()
    return render_template('admin.html', otps=otps, scores=scores, settings=settings, policies=policies)

@app.route('/admin/generate-otp', methods=['POST'])
@login_required
@limiter.limit("20 per hour")
def generate_otp():
    # Check if a custom code was provided
    custom_code = request.form.get('custom_code', '').strip()

    if custom_code:
        # Validate custom code
        if len(custom_code) < 6:
            flash('Custom OTP code must be at least 6 characters long.', 'danger')
            return redirect(url_for('admin_dashboard'))

        if len(custom_code) > 20:
            flash('Custom OTP code must be at most 20 characters long.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Check if code already exists
        existing = OTP.query.filter_by(code=custom_code).first()
        if existing:
            flash('This OTP code already exists. Please choose a different one.', 'danger')
            return redirect(url_for('admin_dashboard'))

        code = custom_code
    else:
        # Generate random code
        code = OTP.generate_code()

    new_otp = OTP(code=code, created_by=current_user.id)
    db.session.add(new_otp)
    db.session.commit()
    flash(f'OTP generated: {code}', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/deactivate-otp/<int:otp_id>', methods=['POST'])
@login_required
def deactivate_otp(otp_id):
    otp = OTP.query.get_or_404(otp_id)
    if otp.created_by == current_user.id:
        otp.is_active = False
        db.session.commit()
        flash('OTP deactivated successfully.', 'success')
    else:
        flash('You can only deactivate your own OTPs.', 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    # Validate inputs
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Check if current password is correct
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Check if new passwords match
    if new_password != confirm_password:
        flash('New passwords do not match.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Validate password strength
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Update password
    try:
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password changed successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to change password: %s', e)
        flash('Failed to change password.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit-score/<int:score_id>', methods=['POST'])
@login_required
def edit_score(score_id):
    score = Score.query.get_or_404(score_id)

    # Get form data
    title = request.form.get('title', '').strip()
    composer = request.form.get('composer', '').strip()

    # Validate title
    if not title:
        flash('Title is required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if len(title) > 200:
        flash('Title is too long (max 200 characters).', 'danger')
        return redirect(url_for('admin_dashboard'))

    if len(composer) > 200:
        flash('Composer name is too long (max 200 characters).', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Update score
    score.title = title
    score.composer = composer if composer else None

    try:
        db.session.commit()
        flash('Score details updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to update score: %s', e)
        flash('Failed to update score details.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/upload', methods=['POST'])
@login_required
def upload_score():
    if 'file' not in request.files:
        flash('No file provided.', 'danger')
        return redirect(url_for('admin_dashboard'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Quick filename extension check
    if not file.filename.lower().endswith('.pdf'):
        flash('Only PDF files are allowed.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Read file bytes (safe because MAX_CONTENT_LENGTH limits size)
    data = file.read()

    # Basic PDF magic header check
    if not data.startswith(b'%PDF'):
        flash('Uploaded file is not a valid PDF (invalid header).', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Try to parse the PDF to ensure it's not a disguised binary
    try:
        try:
            from PyPDF2 import PdfReader
        except ModuleNotFoundError:
            app.logger.exception('PyPDF2 library is not installed; cannot validate PDFs')
            flash('Server misconfiguration: PDF validation library not available.', 'danger')
            return redirect(url_for('admin_dashboard'))

        reader = PdfReader(BytesIO(data))
        # Ensure it has at least one page
        if len(getattr(reader, 'pages', [])) == 0:
            raise ValueError('PDF has no pages')
    except Exception as e:
        app.logger.exception('Uploaded file failed PDF validation: %s', e)
        flash('Uploaded file is not a valid PDF.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Safe filename and save bytes to disk
    filename = secure_filename(file.filename)
    # If secure_filename returned an empty name (e.g. filename only had disallowed chars), fall back
    if not filename:
        # Preserve PDF extension if original filename suggests it, otherwise no extension
        ext = '.pdf' if file.filename.lower().endswith('.pdf') else ''
        filename = f"{uuid4().hex}{ext}"

    # Ensure filename contains no path separators (defense in depth)
    filename = filename.replace(os.path.sep, '_').replace('/', '_')

    # Prevent hidden filenames starting with a dot
    filename = filename.lstrip('.')

    # Split base and extension, then compute allowed base length so that
    # timestamp + base + ext will not exceed 200 characters.
    base, ext = os.path.splitext(filename)
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
    max_total_len = 200
    max_base_len = max_total_len - len(ext) - len(timestamp)
    if max_base_len < 0:
        # If extension+timestamp alone exceed the limit, fall back to a UUID name
        filename = f"{timestamp}{uuid4().hex}{ext}"
    else:
        if len(base) > max_base_len:
            base = base[:max_base_len]
        filename = timestamp + base + ext

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Ensure final filepath is inside the configured upload folder (defense in depth)
    upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
    filepath_abs = os.path.abspath(filepath)
    try:
        if os.path.commonpath([upload_folder_abs, filepath_abs]) != upload_folder_abs:
            app.logger.error('Detected attempted path traversal in upload: %s', filepath_abs)
            flash('Invalid upload path.', 'danger')
            return redirect(url_for('admin_dashboard'))
    except Exception as e:
        app.logger.exception('Error validating upload path: %s', e)
        flash('Invalid upload path.', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        with open(filepath, 'wb') as f:
            f.write(data)
    except Exception as e:
        app.logger.exception('Failed to save uploaded file: %s', e)
        flash('Failed to save uploaded file.', 'danger')
        return redirect(url_for('admin_dashboard'))

    title = request.form.get('title', file.filename)
    composer = request.form.get('composer', '')

    score = Score(
        title=title,
        composer=composer,
        filename=filename,
        uploaded_by=current_user.id
    )
    db.session.add(score)
    db.session.commit()

    flash('Score uploaded successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/bulk-upload', methods=['GET', 'POST'])
@login_required
def bulk_upload_step1():
    if request.method == 'POST':
        # Handle multiple file uploads
        if 'files' not in request.files:
            flash('No files provided.', 'danger')
            return redirect(url_for('admin_dashboard'))

        files = request.files.getlist('files')

        if not files or all(f.filename == '' for f in files):
            flash('No files selected.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Validate and temporarily store files
        temp_files = []
        for file in files:
            if file.filename == '':
                continue

            # Quick filename extension check
            if not file.filename.lower().endswith('.pdf'):
                flash(f'File {file.filename} is not a PDF. Skipped.', 'warning')
                continue

            # Read file bytes
            data = file.read()

            # Basic PDF magic header check
            if not data.startswith(b'%PDF'):
                flash(f'File {file.filename} is not a valid PDF (invalid header). Skipped.', 'warning')
                continue

            # Try to parse the PDF
            try:
                try:
                    from PyPDF2 import PdfReader
                except ModuleNotFoundError:
                    app.logger.exception('PyPDF2 library is not installed; cannot validate PDFs')
                    flash('Server misconfiguration: PDF validation library not available.', 'danger')
                    return redirect(url_for('admin_dashboard'))

                reader = PdfReader(BytesIO(data))
                if len(getattr(reader, 'pages', [])) == 0:
                    raise ValueError('PDF has no pages')
            except Exception as e:
                app.logger.exception('File %s failed PDF validation: %s', file.filename, e)
                flash(f'File {file.filename} is not a valid PDF. Skipped.', 'warning')
                continue

            # Generate safe filename
            original_filename = file.filename
            filename = secure_filename(original_filename)

            if not filename:
                ext = '.pdf' if original_filename.lower().endswith('.pdf') else ''
                filename = f"{uuid4().hex}{ext}"

            filename = filename.replace(os.path.sep, '_').replace('/', '_')
            filename = filename.lstrip('.')

            # Add timestamp prefix
            base, ext = os.path.splitext(filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S_')
            max_total_len = 200
            max_base_len = max_total_len - len(ext) - len(timestamp)

            if max_base_len < 0:
                filename = f"{timestamp}{uuid4().hex}{ext}"
            else:
                if len(base) > max_base_len:
                    base = base[:max_base_len]
                filename = timestamp + base + ext

            # Save file temporarily
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            upload_folder_abs = os.path.abspath(app.config['UPLOAD_FOLDER'])
            filepath_abs = os.path.abspath(filepath)

            try:
                if os.path.commonpath([upload_folder_abs, filepath_abs]) != upload_folder_abs:
                    app.logger.error('Detected attempted path traversal in upload: %s', filepath_abs)
                    flash(f'Invalid upload path for {original_filename}.', 'danger')
                    continue
            except Exception as e:
                app.logger.exception('Error validating upload path: %s', e)
                flash(f'Invalid upload path for {original_filename}.', 'danger')
                continue

            try:
                with open(filepath, 'wb') as f:
                    f.write(data)
            except Exception as e:
                app.logger.exception('Failed to save uploaded file: %s', e)
                flash(f'Failed to save {original_filename}.', 'danger')
                continue

            # Extract title from filename (without extension and timestamp)
            # Remove timestamp prefix pattern (YYYYMMDD_HHMMSS_)
            display_name = base
            if len(display_name) > 17 and display_name[8] == '_' and display_name[15] == '_':
                display_name = display_name[16:]  # Remove timestamp prefix

            temp_files.append({
                'filename': filename,
                'original_filename': original_filename,
                'title': display_name
            })

        if not temp_files:
            flash('No valid PDF files were uploaded.', 'danger')
            return redirect(url_for('admin_dashboard'))

        # Store in session for step 2
        session['bulk_upload_files'] = temp_files
        return redirect(url_for('bulk_upload_step2'))

    return render_template('bulk_upload_step1.html')

@app.route('/admin/bulk-upload-step2', methods=['GET', 'POST'])
@login_required
def bulk_upload_step2():
    temp_files = session.get('bulk_upload_files')

    if not temp_files:
        flash('No files in bulk upload session. Please start over.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        # Process the form with all file details
        success_count = 0
        error_count = 0

        for i, file_info in enumerate(temp_files):
            title = request.form.get(f'title_{i}', '').strip()
            composer = request.form.get(f'composer_{i}', '').strip()

            if not title:
                flash(f'Skipped file {file_info["original_filename"]}: Title is required.', 'warning')
                error_count += 1
                continue

            if len(title) > 200:
                flash(f'Skipped file {file_info["original_filename"]}: Title is too long.', 'warning')
                error_count += 1
                continue

            if len(composer) > 200:
                flash(f'Skipped file {file_info["original_filename"]}: Composer name is too long.', 'warning')
                error_count += 1
                continue

            # Create score record
            score = Score(
                title=title,
                composer=composer if composer else None,
                filename=file_info['filename'],
                uploaded_by=current_user.id
            )

            try:
                db.session.add(score)
                db.session.commit()
                success_count += 1
            except Exception as e:
                db.session.rollback()
                app.logger.exception('Failed to save score: %s', e)
                flash(f'Failed to save {file_info["original_filename"]}.', 'danger')
                error_count += 1

        # Clear session
        session.pop('bulk_upload_files', None)

        if success_count > 0:
            flash(f'Successfully uploaded {success_count} score(s)!', 'success')
        if error_count > 0:
            flash(f'Failed to upload {error_count} score(s).', 'danger')

        return redirect(url_for('admin_dashboard'))

    return render_template('bulk_upload_step2.html', files=temp_files)

@app.route('/admin/delete-score/<int:score_id>', methods=['POST'])
@login_required
def delete_score(score_id):
    score = Score.query.get_or_404(score_id)

    # Prepare file paths
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], score.filename)
    backup_path = filepath + '.deleting'

    # If the file exists, atomically move it to a backup location first.
    # This lets us restore it if the DB deletion fails, avoiding inconsistency.
    if os.path.exists(filepath):
        try:
            # os.replace is atomic on the same filesystem and will overwrite if target exists
            os.replace(filepath, backup_path)
        except Exception as e:
            app.logger.exception('Failed to move score file before DB delete: %s', e)
            flash('Failed to delete the file due to filesystem error. Aborting deletion.', 'danger')
            return redirect(url_for('admin_dashboard'))
    else:
        # File is already missing; continue with DB deletion but warn the admin
        backup_path = None
        flash('File was not found on disk. Removing DB record to remain consistent.', 'warning')

    # Attempt to delete the DB record. If this fails, try to restore the file from backup.
    try:
        db.session.delete(score)
        db.session.commit()
    except Exception as e:
        app.logger.exception('Database error while deleting score record: %s', e)
        # Try to restore the file from backup if we moved it
        if backup_path:
            try:
                os.replace(backup_path, filepath)
                flash('Database error occurred; file was restored. Please try again.', 'danger')
            except Exception as restore_err:
                app.logger.exception('Failed to restore score file after DB failure: %s', restore_err)
                flash('Database error occurred and failed to restore file. Manual recovery required.', 'danger')
        else:
            flash('Database error occurred while deleting the record. Manual inspection required.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # DB delete succeeded — clean up the backup file if it exists
    if backup_path:
        try:
            if os.path.exists(backup_path):
                os.remove(backup_path)
        except Exception as cleanup_err:
            app.logger.exception('Failed to remove backup file after successful DB deletion: %s', cleanup_err)
            flash('Score record deleted but failed to remove temporary backup file; please delete it manually.', 'warning')

    flash('Score deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings', methods=['POST'])
@login_required
def update_site_settings():
    settings = SiteSettings.get_settings()

    # Update site name
    site_name = request.form.get('site_name', '').strip()
    if site_name:
        if len(site_name) > 100:
            flash('Site name is too long (max 100 characters).', 'danger')
            return redirect(url_for('admin_dashboard'))
        settings.site_name = site_name

    # Handle logo upload
    if 'logo' in request.files:
        logo_file = request.files['logo']
        success, result, data_or_error = validate_and_process_upload(
            logo_file,
            allowed_extensions={'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp'},
            max_size_bytes=2 * 1024 * 1024,  # 2MB
            file_type_name='Logo',
            filename_prefix='logo_'
        )

        if success:
            # result is the filename, data_or_error is the file data
            save_success, error_msg = save_uploaded_file(result, data_or_error, settings.logo_filename)
            if save_success:
                settings.logo_filename = result
            else:
                flash(error_msg, 'danger')
                return redirect(url_for('admin_dashboard'))
        elif result is not None:
            # Validation failed, data_or_error contains error message
            flash(data_or_error, 'danger')
            return redirect(url_for('admin_dashboard'))

    # Handle favicon upload
    if 'favicon' in request.files:
        favicon_file = request.files['favicon']
        success, result, data_or_error = validate_and_process_upload(
            favicon_file,
            allowed_extensions={'.ico', '.png', '.svg'},
            max_size_bytes=1024 * 1024,  # 1MB
            file_type_name='Favicon',
            filename_prefix='favicon_'
        )

        if success:
            # result is the filename, data_or_error is the file data
            save_success, error_msg = save_uploaded_file(result, data_or_error, settings.favicon_filename)
            if save_success:
                settings.favicon_filename = result
            else:
                flash(error_msg, 'danger')
                return redirect(url_for('admin_dashboard'))
        elif result is not None:
            # Validation failed, data_or_error contains error message
            flash(data_or_error, 'danger')
            return redirect(url_for('admin_dashboard'))

    # Update metadata
    settings.updated_by = current_user.id
    settings.updated_at = datetime.utcnow()

    try:
        db.session.commit()
        flash('Site settings updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to update site settings: %s', e)
        flash('Failed to update site settings.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/settings/clear', methods=['POST'])
@login_required
def clear_site_settings():
    settings = SiteSettings.get_settings()

    # Delete logo file if exists
    delete_static_file(settings.logo_filename)

    # Delete favicon file if exists
    delete_static_file(settings.favicon_filename)

    # Reset to defaults
    settings.site_name = 'ScoreLock'
    settings.logo_filename = None
    settings.favicon_filename = None
    settings.updated_by = current_user.id
    settings.updated_at = datetime.utcnow()

    try:
        db.session.commit()
        flash('Site settings have been reset to defaults!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to clear site settings: %s', e)
        flash('Failed to clear site settings.', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/policy-acceptance', methods=['GET', 'POST'])
def policy_acceptance():
    # Must be an OTP authenticated user
    if not session.get('otp_authenticated'):
        flash('Please login with OTP to continue.', 'warning')
        return redirect(url_for('login'))

    otp_id = session.get('otp_id')
    session_id = session.get('policy_session_id')

    if not otp_id or not session_id:
        flash('Session error. Please login again.', 'danger')
        return redirect(url_for('logout'))

    pending_policies = PolicyAcceptance.get_pending_policies_for_session(session_id)

    if not pending_policies:
        # All policies accepted, redirect to library
        return redirect(url_for('library'))

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'accept':
            # Record acceptance for all pending policies
            ip_address = request.remote_addr
            added_count = 0

            for policy in pending_policies:
                # Check if acceptance already exists (defense in depth)
                existing = PolicyAcceptance.query.filter_by(
                    session_id=session_id,
                    policy_id=policy.id
                ).first()

                if existing:
                    # Already accepted, skip
                    continue

                acceptance = PolicyAcceptance(
                    session_id=session_id,
                    otp_id=otp_id,
                    policy_id=policy.id,
                    ip_address=ip_address
                )
                db.session.add(acceptance)
                added_count += 1

            if added_count > 0:
                try:
                    db.session.commit()
                    flash('Thank you for accepting the policies. You may now access the library.', 'success')
                    return redirect(url_for('library'))
                except IntegrityError:
                    # Duplicate key violation - someone else already accepted or race condition
                    db.session.rollback()
                    # Check again if all policies are now accepted
                    remaining = PolicyAcceptance.get_pending_policies_for_session(session_id)
                    if not remaining:
                        flash('Thank you for accepting the policies. You may now access the library.', 'success')
                        return redirect(url_for('library'))
                    else:
                        flash('Some policies were already accepted. Please try again.', 'warning')
                except Exception as e:
                    db.session.rollback()
                    app.logger.exception('Failed to record policy acceptance: %s', e)
                    flash('Failed to record policy acceptance. Please try again.', 'danger')
            else:
                # All policies were already accepted
                flash('Thank you for accepting the policies. You may now access the library.', 'success')
                return redirect(url_for('library'))

        elif action == 'decline':
            # User declined - log them out
            flash('You must accept all policies to access the library. You have been logged out.', 'warning')
            return redirect(url_for('logout'))

    return render_template('policy_acceptance.html', policies=pending_policies)

@app.route('/policy/<int:policy_id>')
def view_policy(policy_id):
    """View full policy text"""
    policy = Policy.query.get_or_404(policy_id)

    # Only allow viewing active policies, unless user is an admin
    if not policy.is_active and not current_user.is_authenticated:
        # Return 404 to avoid revealing existence of inactive policies
        flash('Policy not found or no longer available.', 'warning')
        return redirect(url_for('index')), 404

    return render_template('policy_view.html', policy=policy)

@app.route('/admin/policies', methods=['GET', 'POST'])
@login_required
def manage_policies():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'create':
            name = request.form.get('name', '').strip()
            short_notice = request.form.get('short_notice', '').strip()
            full_policy = request.form.get('full_policy', '').strip()

            # Validation
            if not name:
                flash('Policy name is required.', 'danger')
                return redirect(url_for('manage_policies'))

            if len(name) > 200:
                flash('Policy name is too long (max 200 characters).', 'danger')
                return redirect(url_for('manage_policies'))

            if not short_notice:
                flash('Short notice is required.', 'danger')
                return redirect(url_for('manage_policies'))

            if not full_policy:
                flash('Full policy text is required.', 'danger')
                return redirect(url_for('manage_policies'))

            # Create policy
            policy = Policy(
                name=name,
                short_notice=short_notice,
                full_policy=full_policy,
                created_by=current_user.id
            )

            try:
                db.session.add(policy)
                db.session.commit()
                flash(f'Policy "{name}" created successfully!', 'success')
            except Exception as e:
                db.session.rollback()
                app.logger.exception('Failed to create policy: %s', e)
                flash('Failed to create policy.', 'danger')

            return redirect(url_for('manage_policies'))

    policies = Policy.query.order_by(Policy.created_at.desc()).all()
    return render_template('manage_policies.html', policies=policies)

@app.route('/admin/policies/<int:policy_id>/toggle', methods=['POST'])
@login_required
def toggle_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    policy.is_active = not policy.is_active

    try:
        db.session.commit()
        status = 'activated' if policy.is_active else 'deactivated'
        flash(f'Policy "{policy.name}" {status} successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to toggle policy: %s', e)
        flash('Failed to update policy status.', 'danger')

    return redirect(url_for('manage_policies'))

@app.route('/admin/policies/<int:policy_id>/delete', methods=['POST'])
@login_required
def delete_policy(policy_id):
    policy = Policy.query.get_or_404(policy_id)

    try:
        # Delete associated acceptances first (for database compatibility; CASCADE is also defined at DB level)
        PolicyAcceptance.query.filter_by(policy_id=policy_id).delete()
        db.session.delete(policy)
        db.session.commit()
        flash(f'Policy "{policy.name}" deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.exception('Failed to delete policy: %s', e)
        flash('Failed to delete policy.', 'danger')

    return redirect(url_for('manage_policies'))

if __name__ == '__main__':
    app.run(debug=True)
