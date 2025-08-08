import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application configuration using Pydantic BaseSettings"""
    
    # Database
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///qss4.db")
    
    # Redis
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Security
    secret_key: str = os.getenv("SESSION_SECRET", "dev-secret-key-change-in-production")
    jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "jwt-secret-change-in-production")
    jwt_access_token_expires: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))
    jwt_refresh_token_expires: int = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "2592000"))
    
    # Encryption
    kyber_private_key_path: str = os.getenv("KYBER_PRIVATE_KEY_PATH", "keys/kyber_private.key")
    kyber_public_key_path: str = os.getenv("KYBER_PUBLIC_KEY_PATH", "keys/kyber_public.key")
    fernet_key: Optional[str] = os.getenv("FERNET_KEY")
    
    # Storage
    storage_backend: str = os.getenv("STORAGE_BACKEND", "local_fs")
    storage_path: str = os.getenv("STORAGE_PATH", "./storage")
    max_file_size: int = int(os.getenv("MAX_FILE_SIZE", "104857600"))  # 100MB default
    
    # Blockchain
    polygon_rpc_url: str = os.getenv("POLYGON_RPC_URL", "https://polygon-rpc.com")
    polygon_private_key: Optional[str] = os.getenv("POLYGON_PRIVATE_KEY")
    audit_contract_address: Optional[str] = os.getenv("AUDIT_CONTRACT_ADDRESS")
    
    # Rate limiting
    rate_limit_enabled: bool = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
    rate_limit_per_minute: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
    
    # Compression
    compression_level: int = int(os.getenv("COMPRESSION_LEVEL", "3"))
    
    class Config:
        env_file = ".env"

# Global settings instance
settings = Settings()
