"""
MCP-Sec Gateway - Authentication Module
Provides login functionality and session management for the admin dashboard
"""

import os
import logging
import secrets
from functools import wraps

from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

# Setup logger for this module
logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__, template_folder='templates')

# Simple admin user class
class AdminUser(UserMixin):
    """Minimal user model for admin login"""
    def __init__(self, id="admin"):
        self.id = id
        
    @staticmethod
    def check_password(password):
        """Check if password matches the admin key"""
        admin_key = os.environ.get("ADMIN_KEY")
        
        if not admin_key:
            logger.warning("ADMIN_KEY environment variable not set. Using secure fallback.")
            admin_key = secrets.token_hex(16)
        
        return password == admin_key


# Admin login form
class LoginForm(FlaskForm):
    """Admin login form"""
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


# User loader for flask-login
@auth_bp.record_once
def on_load(state):
    """Initialize Flask-Login on blueprint registration"""
    app = state.app
    login_manager = app.extensions.get('login_manager')
    
    if login_manager:
        @login_manager.user_loader
        def load_user(user_id):
            if user_id == "admin":
                return AdminUser()
            return None


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page"""
    if current_user.is_authenticated:
        return redirect(url_for('admin_bp.admin_dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        if AdminUser.check_password(form.password.data):
            user = AdminUser()
            login_user(user, remember=form.remember.data)
            
            # Log successful login
            logger.info(f"Admin login successful from {request.remote_addr}")
            
            # Redirect to requested page or default to admin dashboard
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('admin_bp.admin_dashboard')
                
            flash('Login successful', 'success')
            return redirect(next_page)
        else:
            # Log failed attempt
            logger.warning(f"Failed admin login attempt from {request.remote_addr}")
            flash('Invalid password', 'danger')
    
    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    """Logout the user"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('root'))