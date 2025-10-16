from flask import Blueprint, request, jsonify, redirect, url_for, render_template, flash, session
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from models import User
from app import db
from core.security import security_manager
from core.rate_limiter import rate_limit
from core.acl import get_current_user
import re

auth_bp = Blueprint('auth', __name__)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    
    return True, "Password is valid"

@auth_bp.route('/register', methods=['GET', 'POST'])
@rate_limit(limit=10, window=300)  # 10 attempts per 5 minutes
def register():
    """User registration endpoint"""
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validation
        if not email or not password:
            error_msg = "Email and password are required"
            if request.is_json:
                return jsonify({"error": error_msg}), 400
            else:
                flash(error_msg, 'error')
                return render_template('register.html')
        
        if not validate_email(email):
            error_msg = "Invalid email format"
            if request.is_json:
                return jsonify({"error": error_msg}), 400
            else:
                flash(error_msg, 'error')
                return render_template('register.html')
        
        if password != confirm_password:
            error_msg = "Passwords do not match"
            if request.is_json:
                return jsonify({"error": error_msg}), 400
            else:
                flash(error_msg, 'error')
                return render_template('register.html')
        
        is_valid, password_msg = validate_password(password)
        if not is_valid:
            if request.is_json:
                return jsonify({"error": password_msg}), 400
            else:
                flash(password_msg, 'error')
                return render_template('register.html')
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            error_msg = "User with this email already exists"
            if request.is_json:
                return jsonify({"error": error_msg}), 409
            else:
                flash(error_msg, 'error')
                return render_template('register.html')
        
        # Create new user
        password_hash = security_manager.hash_password(password)
        
        new_user = User(
            email=email,
            password_hash=password_hash,
            role="user"
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        if request.is_json:
            return jsonify({
                "message": "User registered successfully",
                "user_id": new_user.id
            }), 201
        else:
            flash("Registration successful! Please log in.", 'success')
            return redirect(url_for('auth.login'))
    
    except Exception as e:
        db.session.rollback()
        error_msg = f"Registration failed: {str(e)}"
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        else:
            flash(error_msg, 'error')
            return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@rate_limit(limit=20, window=300)  # 20 attempts per 5 minutes
def login():
    """User login endpoint"""
    if request.method == 'GET':
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return render_template('login.html')
    
    try:
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            error_msg = "Email and password are required"
            if request.is_json:
                return jsonify({"error": error_msg}), 400
            else:
                flash(error_msg, 'error')
                return render_template('login.html')
        
        # Find user
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.is_active:
            error_msg = "Invalid credentials"
            if request.is_json:
                return jsonify({"error": error_msg}), 401
            else:
                flash(error_msg, 'error')
                return render_template('login.html')
        
        # Verify password
        if not security_manager.verify_password(password, user.password_hash):
            error_msg = "Invalid credentials"
            if request.is_json:
                return jsonify({"error": error_msg}), 401
            else:
                flash(error_msg, 'error')
                return render_template('login.html')
        
        # Create JWT tokens
        additional_claims = {
            "role": user.role,
            "email": user.email
        }
        
        tokens = security_manager.create_tokens(user.id, additional_claims)
        
        if request.is_json:
            return jsonify({
                "message": "Login successful",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role
                },
                "tokens": tokens
            }), 200
        else:
            # For web interface, use Flask-Login
            login_user(user, remember=True)
            # Store tokens in the session for API calls
            flash(tokens['access_token'], 'access_token')
            flash(tokens['refresh_token'], 'refresh_token')
            
            flash("Login successful!", 'success')
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('dashboard'))
    
    except Exception as e:
        error_msg = f"Login failed: {str(e)}"
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        else:
            flash(error_msg, 'error')
            return render_template('login.html')

@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token using refresh token"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401
        
        # Create new access token
        additional_claims = {
            "role": user.role,
            "email": user.email
        }
        
        new_access_token = create_access_token(
            identity=current_user_id,
            additional_claims=additional_claims
        )
        
        return jsonify({
            "access_token": new_access_token,
            "token_type": "Bearer"
        }), 200
    
    except Exception as e:
        return jsonify({"error": f"Token refresh failed: {str(e)}"}), 500

@auth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    """User logout endpoint"""
    if request.method == 'GET':
        # Web interface logout
        logout_user()
        flash("You have been logged out.", 'info')
        return redirect(url_for('index'))
    else:
        # API logout (JWT tokens are stateless, so this is informational)
        return jsonify({"message": "Logged out successfully"}), 200

@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    """Get user profile information"""
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        return jsonify({
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "created_at": user.created_at.isoformat(),
                "is_active": user.is_active
            }
        }), 200
    
    except Exception as e:
        return jsonify({"error": f"Profile fetch failed: {str(e)}"}), 500

@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
@rate_limit(limit=5, window=300)  # 5 attempts per 5 minutes
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        if not all([current_password, new_password, confirm_password]):
            return jsonify({"error": "All password fields are required"}), 400
        
        if new_password != confirm_password:
            return jsonify({"error": "New passwords do not match"}), 400
        
        # Validate new password
        is_valid, password_msg = validate_password(new_password)
        if not is_valid:
            return jsonify({"error": password_msg}), 400
        
        # Get current user
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Verify current password
        if not security_manager.verify_password(current_password, user.password_hash):
            return jsonify({"error": "Current password is incorrect"}), 401
        
        # Update password
        user.password_hash = security_manager.hash_password(new_password)
        db.session.commit()
        
        return jsonify({"message": "Password changed successfully"}), 200
    
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Password change failed: {str(e)}"}), 500
