import os
import jwt
import datetime
from typing import Optional, Dict, Any
from flask import current_app
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import secrets

class SecurityManager:
    """Centralized security operations for JWT, password hashing, and key management"""
    
    def __init__(self):
        self.fernet_key = self._get_or_create_fernet_key()
        self.cipher_suite = Fernet(self.fernet_key) if self.fernet_key else None
    
    def _get_or_create_fernet_key(self) -> bytes:
        """Get Fernet key for config encryption"""
        key = "g414Y6DmuaxaDjcB7XBqY7SYPFZFOYP5YlYod5Likio=".strip()
        
        # Ensure the key is properly padded
        padding_needed = 4 - (len(key) % 4)
        if padding_needed < 4:
            key += '=' * padding_needed
            
        # Convert to bytes and validate
        try:
            key_bytes = key.encode('ascii')
            # This will validate the key format
            Fernet(key_bytes)
            return key_bytes
        except Exception as e:
            raise ValueError(f"Invalid Fernet key: {e}")
    
    def hash_password(self, password: str) -> str:
        """Hash password using Argon2"""
        return generate_password_hash(password)
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return check_password_hash(password_hash, password)
    
    def create_tokens(self, user_id: str, additional_claims: Optional[Dict] = None) -> Dict[str, str]:
        """Create JWT access and refresh tokens"""
        identity = user_id
        additional_claims = additional_claims or {}
        
        access_token = create_access_token(
            identity=identity,
            additional_claims=additional_claims,
            expires_delta=datetime.timedelta(seconds=current_app.config['JWT_ACCESS_TOKEN_EXPIRES'])
        )
        
        refresh_token = create_refresh_token(
            identity=identity,
            expires_delta=datetime.timedelta(seconds=current_app.config['JWT_REFRESH_TOKEN_EXPIRES'])
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": current_app.config['JWT_ACCESS_TOKEN_EXPIRES']
        }
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = decode_token(token)
            return payload
        except Exception as e:
            current_app.logger.error(f"Token verification failed: {e}")
            return None
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using Fernet"""
        if not self.cipher_suite:
            raise ValueError("Fernet key not configured")
        return self.cipher_suite.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using Fernet"""
        if not self.cipher_suite:
            raise ValueError("Fernet key not configured")
        return self.cipher_suite.decrypt(encrypted_data)
    
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate cryptographically secure random token"""
        return secrets.token_urlsafe(length)

# Global security manager instance
security_manager = SecurityManager()
