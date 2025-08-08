from abc import ABC, abstractmethod
from typing import BinaryIO, Optional, Dict, Any
from pathlib import Path

class BaseStorage(ABC):
    """Abstract base class for storage backends"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.backend_name = ""
    
    @abstractmethod
    def store(self, file_stream: BinaryIO, file_path: str) -> str:
        """
        Store file and return storage identifier/path
        
        Args:
            file_stream: Binary stream of file data
            file_path: Desired file path/key
        
        Returns:
            Storage identifier (path, key, etc.)
        """
        pass
    
    @abstractmethod
    def retrieve(self, storage_id: str) -> BinaryIO:
        """
        Retrieve file by storage identifier
        
        Args:
            storage_id: Storage identifier returned by store()
        
        Returns:
            Binary stream of file data
        """
        pass
    
    @abstractmethod
    def delete(self, storage_id: str) -> bool:
        """
        Delete file by storage identifier
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def exists(self, storage_id: str) -> bool:
        """
        Check if file exists
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            True if exists, False otherwise
        """
        pass
    
    @abstractmethod
    def get_size(self, storage_id: str) -> Optional[int]:
        """
        Get file size in bytes
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            File size in bytes or None if not found
        """
        pass
    
    def get_metadata(self, storage_id: str) -> Dict[str, Any]:
        """
        Get storage metadata for file
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            Metadata dictionary
        """
        return {
            "storage_id": storage_id,
            "backend": self.backend_name,
            "exists": self.exists(storage_id),
            "size": self.get_size(storage_id)
        }
    
    def list_files(self, prefix: str = "") -> list:
        """
        List files with optional prefix filter
        
        Args:
            prefix: Optional prefix to filter files
        
        Returns:
            List of storage identifiers
        """
        # Default implementation returns empty list
        # Subclasses should override if listing is supported
        return []
    
    def get_url(self, storage_id: str, expires_in: int = 3600) -> Optional[str]:
        """
        Get temporary URL for file access (if supported)
        
        Args:
            storage_id: Storage identifier
            expires_in: URL expiration time in seconds
        
        Returns:
            Temporary URL or None if not supported
        """
        # Default implementation returns None
        # Subclasses can override for URL-based access
        return None

class StorageError(Exception):
    """Base exception for storage operations"""
    pass

class StorageNotFoundError(StorageError):
    """Exception for file not found in storage"""
    pass

class StoragePermissionError(StorageError):
    """Exception for storage permission errors"""
    pass

class StorageCapacityError(StorageError):
    """Exception for storage capacity/quota errors"""
    pass
