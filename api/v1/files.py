from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from werkzeug.datastructures import FileStorage
from models import FileRecord, User
from app import db
from services.file_service import file_service
from services.download_token import download_token_service
from services.sandbox import security_sandbox
from core.rate_limiter import rate_limit
from core.acl import require_permission, get_current_user, require_resource_owner
import io
import json

files_bp = Blueprint('files', __name__)

@files_bp.route('/upload', methods=['POST'])
@jwt_required()
@rate_limit(limit=10, window=600, per_user=True)  # 10 uploads per 10 minutes per user
# In files.py

def upload_file():
    """
    Upload file with validation, compression, encryption, and storage
    Supports multipart/form-data upload
    """
    try:
        current_user_id = get_jwt_identity()
        user = get_current_user()
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        if 'file' not in request.files:
            return jsonify({"error": "No file provided"}), 400
        
        uploaded_file = request.files['file']
        
        if uploaded_file.filename == '':
            return jsonify({"error": "No file selected"}), 400
        
        metadata_str = request.form.get('metadata', '{}')
        try:
            metadata = json.loads(metadata_str) if metadata_str else {}
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid metadata JSON"}), 400
        
        filename = secure_filename(uploaded_file.filename)
        if not filename:
            return jsonify({"error": "Invalid filename"}), 400
        
        current_app.logger.info(f"File upload request: {filename} from user {current_user_id}")
        
        # --- START: MODIFIED SECTION ---
        # Read the entire file content into a bytes object once.
        file_content = uploaded_file.read()
        
        # Security validation: Pass a NEW, independent stream.
        security_stream = io.BytesIO(file_content)
        security_result = security_sandbox.validate_file_security(security_stream, filename)
        
        if not security_result["safe"]:
            current_app.logger.warning(f"File security validation failed: {security_result}")
            return jsonify({
                "error": "File security validation failed",
                "details": security_result["errors"]
            }), 400
        
        if security_result["warnings"]:
            current_app.logger.info(f"File security warnings: {security_result['warnings']}")
        
        # Upload file using file service: Pass another NEW, independent stream.
        upload_stream = io.BytesIO(file_content)
        # --- END: MODIFIED SECTION ---
        
        current_app.logger.debug("[UPLOAD] Before calling file_service.upload_file")
        try:
            upload_result = file_service.upload_file(
                file_stream=upload_stream, # Use the new upload_stream
                filename=filename,
                user_id=current_user_id,
                metadata=metadata
            )
            current_app.logger.debug("[UPLOAD] After file_service.upload_file")
        except Exception as e:
            current_app.logger.error(f"[UPLOAD] Error in file_service.upload_file: {str(e)}", exc_info=True)
            raise
        
        return jsonify({
            "message": "File uploaded successfully",
            "file": upload_result
        }), 201
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        current_app.logger.error(f"File upload error: {str(e)}\n{error_trace}")
        return jsonify({
            "error": "An error occurred while uploading the file",
            "details": str(e),
            "type": type(e).__name__
        }), 500
@files_bp.route('/<file_id>/token', methods=['POST'])
@jwt_required()
@rate_limit(limit=20, window=300, per_user=True)  # 20 tokens per 5 minutes per user
def create_download_token(file_id):
    """Create one-time download token for file"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json() or {}
        ttl_seconds = data.get('ttl_seconds', 60)
        
        # Validate TTL
        if ttl_seconds < 1 or ttl_seconds > 3600:
            return jsonify({"error": "TTL must be between 1 and 3600 seconds"}), 400
        
        # Create token
        token_info = download_token_service.create_token(
            file_id=file_id,
            user_id=current_user_id,
            ttl_seconds=ttl_seconds
        )
        
        return jsonify(token_info), 200
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        current_app.logger.error(f"Token creation error: {e}")
        return jsonify({"error": f"Token creation failed: {str(e)}"}), 500

@files_bp.route('/<file_id>/download', methods=['GET'])
@rate_limit(limit=30, window=300)  # 30 downloads per 5 minutes per IP
def download_file(file_id):
    """Download file using one-time token"""
    try:
        token = request.args.get('token')
        
        if not token:
            return jsonify({"error": "Download token required"}), 400
        
        # Validate and consume token
        token_data = download_token_service.validate_and_consume_token(token)
        
        if not token_data:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        # Verify file ID matches token
        if token_data["file_id"] != file_id:
            return jsonify({"error": "Token does not match file"}), 400
        
        # Download file
        file_stream = file_service.download_file(
            file_id=file_id,
            user_id=token_data["user_id"]
        )
        
        # Get file record for metadata
        file_record = FileRecord.query.get(file_id)
        if not file_record:
            return jsonify({"error": "File not found"}), 404
        
        current_app.logger.info(f"File download: {file_id} using token")
        
        # Return file stream
        return send_file(
            file_stream,
            as_attachment=True,
            download_name=file_record.original_filename,
            mimetype=file_record.mime_type
        )
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        current_app.logger.error(f"File download error: {e}")
        return jsonify({"error": f"Download failed: {str(e)}"}), 500

@files_bp.route('/list', methods=['GET'])
@jwt_required()
@rate_limit(limit=60, window=300, per_user=True)  # 60 requests per 5 minutes per user
def list_files():
    """List files for current user"""
    try:
        current_user_id = get_jwt_identity()
        user = get_current_user()
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        # Pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        # Build query
        query = FileRecord.query.filter_by(deleted=False)
        
        # Non-admin users see only their files
        if user.role != "admin":
            query = query.filter_by(user_id=current_user_id)
        
        # Sorting
        sort_by = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')
        
        valid_sort_fields = ['created_at', 'original_filename', 'size', 'mime_type']
        if sort_by in valid_sort_fields:
            sort_field = getattr(FileRecord, sort_by)
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
            
            # Include user info for admins
            if user.role == "admin":
                file_info["user_id"] = file_record.user_id
                file_info["user_email"] = file_record.user.email
            
            files.append(file_info)
        
        return jsonify({
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
        current_app.logger.error(f"List files error: {e}")
        return jsonify({"error": f"Failed to list files: {str(e)}"}), 500

@files_bp.route('/<file_id>', methods=['GET'])
@jwt_required()
def get_file_info(file_id):
    """Get detailed file information"""
    try:
        current_user_id = get_jwt_identity()
        
        file_info = file_service.get_file_info(file_id, current_user_id)
        
        if not file_info:
            return jsonify({"error": "File not found or access denied"}), 404
        
        return jsonify({"file": file_info}), 200
    
    except Exception as e:
        current_app.logger.error(f"Get file info error: {e}")
        return jsonify({"error": f"Failed to get file info: {str(e)}"}), 500

@files_bp.route('/<file_id>', methods=['DELETE'])
@jwt_required()
@rate_limit(limit=10, window=300, per_user=True)  # 10 deletions per 5 minutes per user
def delete_file(file_id):
    """Soft delete file"""
    try:
        current_user_id = get_jwt_identity()
        
        success = file_service.delete_file(file_id, current_user_id)
        
        if not success:
            return jsonify({"error": "File not found or access denied"}), 404
        
        return jsonify({"message": "File deleted successfully"}), 200
    
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        current_app.logger.error(f"Delete file error: {e}")
        return jsonify({"error": f"Delete failed: {str(e)}"}), 500

@files_bp.route('/<file_id>/tokens', methods=['GET'])
@jwt_required()
def list_file_tokens(file_id):
    """List active download tokens for file"""
    try:
        current_user_id = get_jwt_identity()
        user = get_current_user()
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        # Check file access
        file_record = FileRecord.query.filter_by(
            id=file_id,
            deleted=False
        ).first()
        
        if not file_record:
            return jsonify({"error": "File not found"}), 404
        
        # Check permissions
        if file_record.user_id != current_user_id and user.role != "admin":
            return jsonify({"error": "Access denied"}), 403
        
        # List active tokens
        tokens = download_token_service.list_active_tokens(current_user_id)
        
        # Filter tokens for this file
        file_tokens = [
            token for token in tokens 
            if token["file_id"] == file_id
        ]
        
        return jsonify({"tokens": file_tokens}), 200
    
    except Exception as e:
        current_app.logger.error(f"List file tokens error: {e}")
        return jsonify({"error": f"Failed to list tokens: {str(e)}"}), 500

@files_bp.route('/tokens/<token>/revoke', methods=['POST'])
@jwt_required()
def revoke_token(token):
    """Revoke download token"""
    try:
        current_user_id = get_jwt_identity()
        
        success = download_token_service.revoke_token(token, current_user_id)
        
        if not success:
            return jsonify({"error": "Token not found or access denied"}), 404
        
        return jsonify({"message": "Token revoked successfully"}), 200
    
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
    except Exception as e:
        current_app.logger.error(f"Revoke token error: {e}")
        return jsonify({"error": f"Token revocation failed: {str(e)}"}), 500

@files_bp.route('/stats', methods=['GET'])
@jwt_required()
def get_file_stats():
    """Get file statistics for current user"""
    try:
        current_user_id = get_jwt_identity()
        user = get_current_user()
        
        if not user:
            return jsonify({"error": "User not found"}), 401
        
        # Build base query
        if user.role == "admin":
            # Admin sees all files
            query = FileRecord.query.filter_by(deleted=False)
        else:
            # Users see only their files
            query = FileRecord.query.filter_by(
                user_id=current_user_id,
                deleted=False
            )
        
        # Calculate statistics
        total_files = query.count()
        total_size = db.session.query(
            db.func.sum(FileRecord.size)
        ).filter(
            FileRecord.deleted == False,
            FileRecord.user_id == current_user_id if user.role != "admin" else True
        ).scalar() or 0
        
        # File type breakdown
        file_types = db.session.query(
            FileRecord.mime_type,
            db.func.count(FileRecord.id).label('count')
        ).filter(
            FileRecord.deleted == False,
            FileRecord.user_id == current_user_id if user.role != "admin" else True
        ).group_by(FileRecord.mime_type).all()
        
        return jsonify({
            "stats": {
                "total_files": total_files,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "file_types": [
                    {"mime_type": ft.mime_type, "count": ft.count}
                    for ft in file_types
                ]
            }
        }), 200
    
    except Exception as e:
        current_app.logger.error(f"Get stats error: {e}")
        return jsonify({"error": f"Failed to get statistics: {str(e)}"}), 500
