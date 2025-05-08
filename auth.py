"""
MCP-Sec Gateway - Authentication Module
Provides login functionality and session management for the admin dashboard
"""
import os
import logging
from functools import wraps
from datetime import timedelta

from flask import Blueprint, request, redirect, url_for, flash, render_template, session, current_app
from flask_wtf import FlaskForm
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

# Setup logger
logger = logging.getLogger(__name__)

# Create blueprint for auth routes
auth_bp = Blueprint('auth', __name__)

class LoginForm(FlaskForm):
    """Admin login form"""
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

def login_required(view_function):
    """Decorator to require login for sensitive endpoints."""
    @wraps(view_function)
    def decorated_function(*args, **kwargs):
        # For development purposes, always allow bypass_auth=true
        if request.args.get("bypass_auth") == "true":
            logger.info("Authentication bypassed with bypass_auth=true")
            return view_function(*args, **kwargs)
            
        # Check if user is logged in
        if not session.get('logged_in'):
            return redirect(url_for('auth.login', next=request.url))
        
        return view_function(*args, **kwargs)
    
    return decorated_function

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Admin login page"""
    form = LoginForm()
    error = None
    
    # Get the admin key from environment variable
    admin_key = os.environ.get("ADMIN_KEY")
    
    if not admin_key:
        logger.error("ADMIN_KEY environment variable not set. Using a secure fallback.")
        # Use a secure random value that changes on each restart
        import secrets
        admin_key = secrets.token_hex(16)
        logger.info(f"Using temporary admin key: {admin_key}")
    
    if form.validate_on_submit():
        if form.password.data == admin_key:
            session['logged_in'] = True
            
            # Set session duration based on remember flag
            if form.remember.data:
                # Remember for 24 hours
                session.permanent = True
                current_app.permanent_session_lifetime = timedelta(days=1)
            else:
                # Default session length (usually until browser close)
                session.permanent = False
            
            logger.info(f"Admin login successful from {request.remote_addr}")
            
            # Redirect to the next page or admin dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('admin.admin_dashboard'))
        else:
            error = "Invalid password"
            logger.warning(f"Failed admin login attempt from {request.remote_addr}")
    
    return render_template('login.html', form=form, error=error)

@auth_bp.route("/logout")
def logout():
    """Logout the user"""
    session.pop('logged_in', None)
    logger.info(f"Admin logout from {request.remote_addr}")
    return redirect(url_for('root'))