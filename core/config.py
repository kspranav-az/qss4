import os
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application configuration using Pydantic BaseSettings"""

    class Config:
        extra = 'ignore'

    # --- Values are now hardcoded below ---

    # Database
    database_url: str = "postgresql://qss4:qss4_password@postgres:5432/qss4"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # Security
    secret_key: str = "e280dc6679266140a7cc810792cd754bffe7cb7f66e56d320655b9e014ae4dd6"
    jwt_secret_key: str = "b16a12c19e27e1fcd61d29638fe5e5536b3dc4be4a4608d766a10806cdf54ea8"
    jwt_access_token_expires: int = 3600
    jwt_refresh_token_expires: int = 2592000

    # Encryption
    kyber_private_key_path: str = "keys/kyber_private.key"
    kyber_public_key_path: str = "keys/kyber_public.key"
    fernet_key: str = "g414Y6DmuaxaDjcB7XBqY7SYPFZFOYP5YlYod5Likio="

    # Storage
    storage_backend: str = "local_fs"
    storage_path: str = "/app/storage"
    max_file_size: int = 104857600  # 100MB default

    # Blockchain
    polygon_rpc_url: str = "https://polygon-rpc.com"
    polygon_private_key: Optional[str] = os.getenv("POLYGON_PRIVATE_KEY")
    audit_contract_address: Optional[str] = os.getenv("AUDIT_CONTRACT_ADDRESS")

    # Rate limiting
    rate_limit_enabled: bool = False
    rate_limit_per_minute: int = 60

    # Compression
    compression_level: int = 3

# Global settings instance
settings = Settings()