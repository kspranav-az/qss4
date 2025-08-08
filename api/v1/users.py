from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import User, FileRecord, AuditLog
from app import db
from core.security import security_manager
from core.rate_limiter import rate_limit
from core.acl import require_permission, require_role, get_current_user
from sqlalchemy import func

users_bp = Blueprint('users', __name__)

@users_bp.route('', methods=['GET'])
@jwt_required()
@require_role('admin')
@rate_limit(limit=30, window=300, per_user=True)  # 30 requests per 5 minutes
def list_users():
    """List all users (admin only)"""
    try:
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Filtering parameters
        role_filter = request.args.get('role')
        active_filter = request.args.get('active')
        search_query = request.args.get('search', '').strip()
        
        # Build query
        query = User.query
        
        if role_filter:
            query = query.filter(User.role == role_filter)
        
        if active_filter is not None:
            active_bool = active_filter.lower() in ['true', '1', 'yes']
            query = query.filter(User.is_active == active_bool)
        
        if search_query:
            query = query.filter(User.email.ilike(f'%{search_query}%'))
        
        # Sorting
        sort_by = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')
        
        valid_sort_fields = ['created_at', 'email', 'role']
        if sort_by in valid_sort_fields:
            sort_field = getattr(User, sort_by)
            if sort_order == 'asc':
                query = query.order_by(sort_field.asc())
            else:
                query = query.order_by(sort_field.desc())
        
        # Execute paginated query
        paginated = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Get file count for each user
        user_file_counts = dict(
            db.session.query(
                FileRecord.user_id,
                func.count(FileRecord.id).label('file_count')
            ).filter(
                FileRecord.deleted == False
            ).group_by(FileRecord.user_id).all()
        )
        
        # Format results
        users = []
        for user in paginated.items:
            user_info = {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
                "file_count": user_file_counts.get(user.id, 0)
            }
            users.append(user_info)
        
        return jsonify({
            "users": users,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginated.total,
                "pages": paginated.pages,
                "has_next": paginated.has_next,
                "has_prev": paginated.has_prev
            }
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"List users error: {e}")
        return jsonify({"error": f"Failed to list users: {str(e)}"}), 500

@users_bp.route('/<user_id>', methods=['GET'])
@jwt_required()
@require_role('admin')
def get_user(user_id):
    """Get detailed user information (admin only)"""
    try:
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Get user statistics
        file_count = FileRecord.query.filter_by(
            user_id=user_id,
            deleted=False
        ).count()
        
        total_size = db.session.query(
            func.sum(FileRecord.size)
        ).filter(
            FileRecord.user_id == user_id,
            FileRecord.deleted == False
        ).scalar() or 0
        
        # Recent activity
        recent_logs = AuditLog.query.filter_by(
            user_id=user_id
        ).order_by(AuditLog.timestamp.desc()).limit(10).all()
        
        return jsonify({
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
                "statistics": {
                    "file_count": file_count,
                    "total_storage_bytes": total_size,
                    "total_storage_mb": round(total_size / (1024 * 1024), 2)
                },
                "recent_activity": [
                    {
                        "event_type": log.event_type,
                        "timestamp": log.timestamp.isoformat(),
                        "details": log.details
                    }
                    for log in recent_logs
                ]
            }
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Get user error: {e}")
        return jsonify({"error": f"Failed to get user: {str(e)}"}), 500

@users_bp.route('/<user_id>/role', methods=['PUT'])
@jwt_required()
@require_role('admin')
@rate_limit(limit=10, window=300, per_user=True)  # 10 role changes per 5 minutes
def change_user_role(user_id):
    """Change user role (admin only)"""
    try:
        data = request.get_json()
        new_role = data.get('role', '').strip()
        
        # Validate role
        valid_roles = ['user', 'manager', 'admin']
        if new_role not in valid_roles:
            return jsonify({
                "error": f"Invalid role. Must be one of: {', '.join(valid_roles)}"
            }), 400
        
        # Find user
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Prevent self-demotion from admin
        current_user_id = get_jwt_identity()
        if user_id == current_user_id and user.role == 'admin' and new_role != 'admin':
            return jsonify({
                "error": "Cannot demote yourself from admin role"
            }), 400
        
        old_role = user.role
        user.role = new_role
        db.session.commit()
        
        # Create audit log
        audit_log = AuditLog(
            event_type="role_change",
            table_name="users",
            row_id=user_id,
            user_id=current_user_id,
            details={
                "target_user_id": user_id,
                "target_user_email": user.email,
                "old_role": old_role,
                "new_role": new_role
            }
        )
        db.session.add(audit_log)
        db.session.commit()
        
        current_app.logger.info(f"Role changed: user {user_id} from {old_role} to {new_role}")
        
        return jsonify({
            "message": "User role updated successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Change role error: {e}")
        return jsonify({"error": f"Failed to change role: {str(e)}"}), 500

@users_bp.route('/<user_id>/status', methods=['PUT'])
@jwt_required()
@require_role('admin')
@rate_limit(limit=10, window=300, per_user=True)  # 10 status changes per 5 minutes
def change_user_status(user_id):
    """Change user active status (admin only)"""
    try:
        data = request.get_json()
        is_active = data.get('is_active')
        
        if is_active is None:
            return jsonify({"error": "is_active field is required"}), 400
        
        # Find user
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Prevent self-deactivation
        current_user_id = get_jwt_identity()
        if user_id == current_user_id and not is_active:
            return jsonify({
                "error": "Cannot deactivate your own account"
            }), 400
        
        old_status = user.is_active
        user.is_active = bool(is_active)
        db.session.commit()
        
        # Create audit log
        action = "activated" if is_active else "deactivated"
        audit_log = AuditLog(
            event_type="user_status_change",
            table_name="users",
            row_id=user_id,
            user_id=current_user_id,
            details={
                "target_user_id": user_id,
                "target_user_email": user.email,
                "old_status": old_status,
                "new_status": is_active,
                "action": action
            }
        )
        db.session.add(audit_log)
        db.session.commit()
        
        current_app.logger.info(f"User {action}: {user_id}")
        
        return jsonify({
            "message": f"User {action} successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "is_active": user.is_active
            }
        }), 200
    
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Change status error: {e}")
        return jsonify({"error": f"Failed to change status: {str(e)}"}), 500

@users_bp.route('/<user_id>/files', methods=['GET'])
@jwt_required()
@require_role('admin')
def get_user_files(user_id):
    """Get files for specific user (admin only)"""
    try:
        # Check if user exists
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Query user's files
        query = FileRecord.query.filter_by(
            user_id=user_id,
            deleted=False
        ).order_by(FileRecord.created_at.desc())
        
        paginated = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Format results
        files = []
        for file_record in paginated.items:
            file_info = {
                "file_id": file_record.id,
                "filename": file_record.original_filename,
                "size": file_record.size,
                "mime_type": file_record.mime_type,
                "created_at": file_record.created_at.isoformat(),
                "file_hash": file_record.file_hash,
                "blockchain_txn_id": file_record.blockchain_txn_id
            }
            files.append(file_info)
        
        return jsonify({
            "user": {
                "id": user.id,
                "email": user.email
            },
            "files": files,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": paginated.total,
                "pages": paginated.pages,
                "has_next": paginated.has_next,
                "has_prev": paginated.has_prev
            }
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Get user files error: {e}")
        return jsonify({"error": f"Failed to get user files: {str(e)}"}), 500

@users_bp.route('/stats', methods=['GET'])
@jwt_required()
@require_role('admin')
def get_user_stats():
    """Get overall user statistics (admin only)"""
    try:
        # User statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        inactive_users = total_users - active_users
        
        # Role breakdown
        role_stats = db.session.query(
            User.role,
            func.count(User.id).label('count')
        ).group_by(User.role).all()
        
        # File statistics by user
        user_file_stats = db.session.query(
            User.email,
            func.count(FileRecord.id).label('file_count'),
            func.sum(FileRecord.size).label('total_size')
        ).outerjoin(FileRecord, 
            (FileRecord.user_id == User.id) & (FileRecord.deleted == False)
        ).group_by(User.id, User.email).order_by(
            func.count(FileRecord.id).desc()
        ).limit(10).all()
        
        # Recent user registrations
        recent_users = User.query.order_by(
            User.created_at.desc()
        ).limit(5).all()
        
        return jsonify({
            "stats": {
                "total_users": total_users,
                "active_users": active_users,
                "inactive_users": inactive_users,
                "role_breakdown": [
                    {"role": rs.role, "count": rs.count}
                    for rs in role_stats
                ],
                "top_users_by_files": [
                    {
                        "email": ufs.email,
                        "file_count": ufs.file_count or 0,
                        "total_size_mb": round((ufs.total_size or 0) / (1024 * 1024), 2)
                    }
                    for ufs in user_file_stats
                ],
                "recent_registrations": [
                    {
                        "id": user.id,
                        "email": user.email,
                        "role": user.role,
                        "created_at": user.created_at.isoformat()
                    }
                    for user in recent_users
                ]
            }
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Get user stats error: {e}")
        return jsonify({"error": f"Failed to get user statistics: {str(e)}"}), 500
