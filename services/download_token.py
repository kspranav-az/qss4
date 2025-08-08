import uuid
import time
from typing import Optional, Dict, Any
from flask import current_app
from models import DownloadToken, FileRecord
from app import db
from core.redis_client import redis_client
from core.security import security_manager

class DownloadTokenService:
    """Redis-backed one-time download token management with atomic operations"""
    
    def __init__(self):
        self.redis = redis_client
        self.default_ttl = 60  # 1 minute default
        self.max_ttl = 3600   # 1 hour maximum
    
    def create_token(self, file_id: str, user_id: str, ttl_seconds: int = None) -> Dict[str, Any]:
        """
        Create one-time download token
        
        Args:
            file_id: ID of file for download
            user_id: ID of user creating token
            ttl_seconds: Token TTL in seconds (default: 60)
        
        Returns:
            Dictionary with token information
        """
        try:
            # Validate parameters
            ttl_seconds = ttl_seconds or self.default_ttl
            if ttl_seconds > self.max_ttl:
                ttl_seconds = self.max_ttl
            
            # Check if file exists and user has access
            file_record = FileRecord.query.filter_by(
                id=file_id,
                deleted=False
            ).first()
            
            if not file_record:
                raise ValueError("File not found")
            
            # Check permissions
            if file_record.user_id != user_id:
                from models import User
                user = User.query.get(user_id)
                if not user or user.role not in ["admin", "manager"]:
                    raise PermissionError("Access denied")
            
            # Generate secure token
            token = security_manager.generate_secure_token(32)
            
            # Create token data
            token_data = {
                "file_id": file_id,
                "user_id": user_id,
                "created_at": int(time.time()),
                "ttl_seconds": ttl_seconds,
                "used": False,
                "filename": file_record.original_filename
            }
            
            # Store in Redis with TTL
            redis_key = f"download_token:{token}"
            if not self.redis.set(redis_key, token_data, ttl=ttl_seconds):
                raise RuntimeError("Failed to store token in Redis")
            
            # Optionally store in database for audit
            db_token = DownloadToken(
                token=token,
                file_id=file_id,
                user_id=user_id,
                ttl_seconds=ttl_seconds
            )
            
            db.session.add(db_token)
            db.session.commit()
            
            current_app.logger.info(f"Download token created: {token[:8]}... for file {file_id}")
            
            return {
                "token": token,
                "ttl_seconds": ttl_seconds,
                "expires_at": int(time.time()) + ttl_seconds,
                "file_id": file_id,
                "filename": file_record.original_filename
            }
            
        except Exception as e:
            current_app.logger.error(f"Token creation failed: {e}")
            db.session.rollback()
            raise RuntimeError(f"Token creation failed: {e}")
    
    def validate_and_consume_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate and atomically consume one-time token using Redis Lua script
        
        Args:
            token: Download token
        
        Returns:
            Token data if valid and unused, None otherwise
        """
        try:
            redis_key = f"download_token:{token}"
            
            # Lua script for atomic token validation and consumption
            lua_script = """
            local key = KEYS[1]
            local token_data = redis.call('GET', key)
            
            if not token_data then
                return nil
            end
            
            -- Parse token data (assuming JSON format)
            local data = cjson.decode(token_data)
            
            -- Check if already used
            if data.used then
                return nil
            end
            
            -- Mark as used
            data.used = true
            data.used_at = tonumber(ARGV[1])
            
            -- Update in Redis
            redis.call('SET', key, cjson.encode(data))
            
            return token_data
            """
            
            # Execute Lua script atomically
            result = self.redis.client.eval(
                lua_script,
                1,
                redis_key,
                int(time.time())
            )
            
            if not result:
                current_app.logger.warning(f"Invalid or expired token: {token[:8]}...")
                return None
            
            # Parse token data
            import json
            token_data = json.loads(result)
            
            # Update database record
            db_token = DownloadToken.query.filter_by(token=token).first()
            if db_token:
                db_token.used = True
                db.session.commit()
            
            current_app.logger.info(f"Token consumed: {token[:8]}... for file {token_data['file_id']}")
            
            return token_data
            
        except Exception as e:
            current_app.logger.error(f"Token validation failed: {e}")
            return None
    
    def get_token_info(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get token information without consuming it
        
        Args:
            token: Download token
        
        Returns:
            Token information if valid, None otherwise
        """
        try:
            redis_key = f"download_token:{token}"
            token_data = self.redis.get(redis_key)
            
            if not token_data:
                return None
            
            # Add remaining TTL
            ttl = self.redis.client.ttl(redis_key)
            if ttl > 0:
                token_data["remaining_ttl"] = ttl
            else:
                token_data["remaining_ttl"] = 0
            
            return token_data
            
        except Exception as e:
            current_app.logger.error(f"Get token info failed: {e}")
            return None
    
    def revoke_token(self, token: str, user_id: str) -> bool:
        """
        Revoke (delete) a token
        
        Args:
            token: Download token to revoke
            user_id: ID of user revoking token
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get token data first
            token_data = self.get_token_info(token)
            if not token_data:
                return False
            
            # Check if user can revoke this token
            if token_data["user_id"] != user_id:
                from models import User
                user = User.query.get(user_id)
                if not user or user.role != "admin":
                    raise PermissionError("Cannot revoke token")
            
            # Delete from Redis
            redis_key = f"download_token:{token}"
            self.redis.delete(redis_key)
            
            # Update database record
            db_token = DownloadToken.query.filter_by(token=token).first()
            if db_token:
                db_token.used = True  # Mark as used to prevent future use
                db.session.commit()
            
            current_app.logger.info(f"Token revoked: {token[:8]}...")
            return True
            
        except Exception as e:
            current_app.logger.error(f"Token revocation failed: {e}")
            return False
    
    def list_active_tokens(self, user_id: str) -> list:
        """
        List active tokens for a user
        
        Args:
            user_id: ID of user
        
        Returns:
            List of active token information
        """
        try:
            # Get tokens from database (Redis scan would be expensive)
            db_tokens = DownloadToken.query.filter_by(
                user_id=user_id,
                used=False
            ).all()
            
            active_tokens = []
            
            for db_token in db_tokens:
                # Check if token still exists in Redis
                redis_key = f"download_token:{db_token.token}"
                token_data = self.redis.get(redis_key)
                
                if token_data:
                    ttl = self.redis.client.ttl(redis_key)
                    active_tokens.append({
                        "token": db_token.token[:8] + "...",  # Partial token for security
                        "file_id": db_token.file_id,
                        "created_at": db_token.created_at.isoformat(),
                        "ttl_seconds": db_token.ttl_seconds,
                        "remaining_ttl": ttl if ttl > 0 else 0
                    })
            
            return active_tokens
            
        except Exception as e:
            current_app.logger.error(f"List tokens failed: {e}")
            return []
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens from database
        
        Returns:
            Number of tokens cleaned up
        """
        try:
            # Find tokens that don't exist in Redis anymore
            all_tokens = DownloadToken.query.filter_by(used=False).all()
            cleaned_count = 0
            
            for token in all_tokens:
                redis_key = f"download_token:{token.token}"
                if not self.redis.exists(redis_key):
                    token.used = True  # Mark as used/expired
                    cleaned_count += 1
            
            if cleaned_count > 0:
                db.session.commit()
                current_app.logger.info(f"Cleaned up {cleaned_count} expired tokens")
            
            return cleaned_count
            
        except Exception as e:
            current_app.logger.error(f"Token cleanup failed: {e}")
            db.session.rollback()
            return 0

# Global download token service instance
download_token_service = DownloadTokenService()
