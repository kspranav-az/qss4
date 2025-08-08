from functools import wraps
from flask import jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from flask_login import current_user
from models import User
from app import db

class RoleManager:
    """Role-based access control manager"""
    
    ROLES = {
        "admin": ["read", "write", "delete", "manage_users", "view_audit"],
        "manager": ["read", "write", "delete", "view_audit"],
        "user": ["read", "write"]
    }
    
    @classmethod
    def has_permission(cls, user_role: str, permission: str) -> bool:
        """Check if role has specific permission"""
        return permission in cls.ROLES.get(user_role, [])
    
    @classmethod
    def can_access_resource(cls, user_role: str, resource_owner_id: str, current_user_id: str) -> bool:
        """Check if user can access a resource (owner or admin)"""
        return (current_user_id == resource_owner_id or 
                cls.has_permission(user_role, "manage_users"))

def require_permission(permission: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                
                if not user or not user.is_active:
                    return jsonify({"error": "User not found or inactive"}), 401
                
                if not RoleManager.has_permission(user.role, permission):
                    return jsonify({"error": "Insufficient permissions"}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"Permission check failed: {e}")
                return jsonify({"error": "Authorization failed"}), 500
        
        return decorated_function
    return decorator

def require_role(required_role: str):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                
                if not user or not user.is_active:
                    return jsonify({"error": "User not found or inactive"}), 401
                
                if user.role != required_role and user.role != "admin":
                    return jsonify({"error": f"Role '{required_role}' required"}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"Role check failed: {e}")
                return jsonify({"error": "Authorization failed"}), 500
        
        return decorated_function
    return decorator

def require_resource_owner():
    """Decorator to require resource ownership or admin role"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            try:
                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                
                if not user or not user.is_active:
                    return jsonify({"error": "User not found or inactive"}), 401
                
                # Get resource owner from kwargs or URL parameters
                resource_user_id = kwargs.get('user_id') or kwargs.get('id')
                
                if not RoleManager.can_access_resource(user.role, resource_user_id, user_id):
                    return jsonify({"error": "Access denied"}), 403
                
                return f(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"Resource ownership check failed: {e}")
                return jsonify({"error": "Authorization failed"}), 500
        
        return decorated_function
    return decorator

def get_current_user():
    """Get current user from JWT token"""
    try:
        user_id = get_jwt_identity()
        return User.query.get(user_id)
    except:
        return None
