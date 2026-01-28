from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

db = SQLAlchemy()

class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class OTP(db.Model):
    __tablename__ = 'otps'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', backref='created_otps')

    @staticmethod
    def generate_code():
        """Generate a secure random OTP code"""
        return secrets.token_urlsafe(12)

class Score(db.Model):
    __tablename__ = 'scores'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    composer = db.Column(db.String(200))
    filename = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', backref='uploaded_scores')

class SiteSettings(db.Model):
    __tablename__ = 'site_settings'

    id = db.Column(db.Integer, primary_key=True)
    site_name = db.Column(db.String(100), default='ScoreLock')
    logo_filename = db.Column(db.String(255), nullable=True)
    favicon_filename = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)

    admin = db.relationship('Admin', backref='settings_updates')

    @staticmethod
    def get_settings():
        """Get or create the site settings singleton"""
        settings = SiteSettings.query.first()
        if not settings:
            settings = SiteSettings()
            db.session.add(settings)
            db.session.commit()
        return settings

class Policy(db.Model):
    __tablename__ = 'policies'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    short_notice = db.Column(db.Text, nullable=False)
    full_policy = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=False)

    admin = db.relationship('Admin', backref='created_policies')

    @staticmethod
    def get_active_policies():
        """Get all active policies"""
        return Policy.query.filter_by(is_active=True).order_by(Policy.created_at.asc()).all()

class PolicyAcceptance(db.Model):
    __tablename__ = 'policy_acceptances'
    __table_args__ = (
        db.UniqueConstraint('session_id', 'policy_id', name='uq_session_policy'),
    )

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), nullable=False)  # Flask session ID
    otp_id = db.Column(db.Integer, db.ForeignKey('otps.id', ondelete='CASCADE'), nullable=False)  # For reference
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id', ondelete='CASCADE'), nullable=False)
    accepted_at = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45), nullable=True)  # Support IPv6

    otp = db.relationship('OTP', backref='policy_acceptances')
    policy = db.relationship('Policy', backref='acceptances')

    @staticmethod
    def check_session_policies_accepted(session_id):
        """Check if current session has accepted all active policies"""
        active_policies = Policy.get_active_policies()
        if not active_policies:
            return True  # No policies to accept

        active_policy_ids = {p.id for p in active_policies}
        accepted_policy_ids = {
            pa.policy_id for pa in PolicyAcceptance.query.filter_by(session_id=session_id).all()
        }

        return active_policy_ids.issubset(accepted_policy_ids)

    @staticmethod
    def get_pending_policies_for_session(session_id):
        """Get policies that haven't been accepted by this session"""
        active_policies = Policy.get_active_policies()
        if not active_policies:
            return []

        accepted_policy_ids = {
            pa.policy_id for pa in PolicyAcceptance.query.filter_by(session_id=session_id).all()
        }

        return [p for p in active_policies if p.id not in accepted_policy_ids]

