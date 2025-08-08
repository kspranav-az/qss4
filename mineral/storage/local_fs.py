import os
import shutil
import hashlib
from pathlib import Path
from typing import BinaryIO, Optional, Dict, Any
import io
import tempfile
from .base import BaseStorage, StorageError, StorageNotFoundError, StoragePermissionError

class LocalFileSystemStorage(BaseStorage):
    """Local filesystem storage implementation with secure file handling"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.backend_name = "local_fs"
        
        # Get storage root from config
        self.storage_root = Path(self.config.get("storage_path", "./storage"))
        
        # Create storage directory if it doesn't exist
        self.storage_root.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions on storage directory
        os.chmod(self.storage_root, 0o750)  # Owner: rwx, Group: r-x, Others: none
    
    def _get_secure_path(self, file_path: str) -> Path:
        """
        Generate secure file path preventing directory traversal
        
        Args:
            file_path: Requested file path
        
        Returns:
            Secure absolute path within storage root
        """
        # Remove any path traversal attempts
        clean_path = file_path.replace("..", "").replace("/", "_").replace("\\", "_")
        
        # Add hash prefix for better distribution
        hash_prefix = hashlib.sha256(clean_path.encode()).hexdigest()[:8]
        secure_filename = f"{hash_prefix}_{clean_path}"
        
        return self.storage_root / secure_filename
    
    def store(self, file_stream: BinaryIO, file_path: str) -> str:
        """
        Store file to local filesystem
        
        Args:
            file_stream: Binary stream of file data
            file_path: Desired file path/name
        
        Returns:
            Storage identifier (relative path from storage root)
        """
        try:
            secure_path = self._get_secure_path(file_path)
            
            # Ensure parent directory exists
            secure_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use temporary file for atomic write
            with tempfile.NamedTemporaryFile(
                dir=secure_path.parent,
                delete=False,
                prefix=".tmp_"
            ) as temp_file:
                
                # Copy data from stream to temporary file
                file_stream.seek(0)
                shutil.copyfileobj(file_stream, temp_file)
                temp_file.flush()
                os.fsync(temp_file.fileno())  # Force write to disk
                
                temp_path = Path(temp_file.name)
            
            # Atomic move to final location
            temp_path.rename(secure_path)
            
            # Set secure file permissions
            os.chmod(secure_path, 0o640)  # Owner: rw, Group: r, Others: none
            
            # Return relative path as storage identifier
            return str(secure_path.relative_to(self.storage_root))
            
        except OSError as e:
            if e.errno == 28:  # No space left on device
                raise StorageError(f"Storage capacity exceeded: {e}")
            elif e.errno in [13, 30]:  # Permission denied
                raise StoragePermissionError(f"Storage permission error: {e}")
            else:
                raise StorageError(f"Failed to store file: {e}")
        except Exception as e:
            raise StorageError(f"Unexpected storage error: {e}")
    
    def retrieve(self, storage_id: str) -> BinaryIO:
        """
        Retrieve file from local filesystem
        
        Args:
            storage_id: Storage identifier (relative path)
        
        Returns:
            Binary stream of file data
        """
        try:
            file_path = self.storage_root / storage_id
            
            # Security check: ensure path is within storage root
            if not file_path.resolve().is_relative_to(self.storage_root.resolve()):
                raise StoragePermissionError("Path traversal attempt detected")
            
            if not file_path.exists():
                raise StorageNotFoundError(f"File not found: {storage_id}")
            
            if not file_path.is_file():
                raise StorageError(f"Path is not a file: {storage_id}")
            
            # Read file into memory stream
            with open(file_path, "rb") as f:
                data = f.read()
            
            return io.BytesIO(data)
            
        except (StorageError, StorageNotFoundError, StoragePermissionError):
            raise
        except OSError as e:
            if e.errno == 13:  # Permission denied
                raise StoragePermissionError(f"Access denied: {storage_id}")
            else:
                raise StorageError(f"Failed to retrieve file: {e}")
        except Exception as e:
            raise StorageError(f"Unexpected retrieval error: {e}")
    
    def delete(self, storage_id: str) -> bool:
        """
        Delete file from local filesystem
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            True if successful, False otherwise
        """
        try:
            file_path = self.storage_root / storage_id
            
            # Security check: ensure path is within storage root
            if not file_path.resolve().is_relative_to(self.storage_root.resolve()):
                raise StoragePermissionError("Path traversal attempt detected")
            
            if not file_path.exists():
                return False
            
            # Secure deletion: overwrite file before deletion
            if file_path.is_file():
                self._secure_delete_file(file_path)
            
            file_path.unlink()
            return True
            
        except (StoragePermissionError):
            raise
        except Exception as e:
            print(f"Failed to delete file {storage_id}: {e}")
            return False
    
    def _secure_delete_file(self, file_path: Path) -> None:
        """
        Securely delete file by overwriting with random data
        
        Args:
            file_path: Path to file to securely delete
        """
        try:
            if not file_path.is_file():
                return
            
            file_size = file_path.stat().st_size
            
            # Overwrite file with random data (basic secure deletion)
            with open(file_path, "r+b") as f:
                for _ in range(3):  # Multiple passes
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                    
        except Exception as e:
            print(f"Warning: Secure deletion failed for {file_path}: {e}")
    
    def exists(self, storage_id: str) -> bool:
        """
        Check if file exists
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            True if exists, False otherwise
        """
        try:
            file_path = self.storage_root / storage_id
            
            # Security check: ensure path is within storage root
            if not file_path.resolve().is_relative_to(self.storage_root.resolve()):
                return False
            
            return file_path.exists() and file_path.is_file()
            
        except Exception:
            return False
    
    def get_size(self, storage_id: str) -> Optional[int]:
        """
        Get file size in bytes
        
        Args:
            storage_id: Storage identifier
        
        Returns:
            File size in bytes or None if not found
        """
        try:
            file_path = self.storage_root / storage_id
            
            # Security check: ensure path is within storage root
            if not file_path.resolve().is_relative_to(self.storage_root.resolve()):
                return None
            
            if file_path.exists() and file_path.is_file():
                return file_path.stat().st_size
            
            return None
            
        except Exception:
            return None
    
    def list_files(self, prefix: str = "") -> list:
        """
        List files with optional prefix filter
        
        Args:
            prefix: Optional prefix to filter files
        
        Returns:
            List of storage identifiers
        """
        try:
            files = []
            
            for file_path in self.storage_root.rglob("*"):
                if file_path.is_file():
                    relative_path = str(file_path.relative_to(self.storage_root))
                    if not prefix or relative_path.startswith(prefix):
                        files.append(relative_path)
            
            return sorted(files)
            
        except Exception as e:
            print(f"Failed to list files: {e}")
            return []
    
    def get_storage_info(self) -> Dict[str, Any]:
        """
        Get storage backend information
        
        Returns:
            Storage information dictionary
        """
        try:
            # Get filesystem statistics
            stat = os.statvfs(self.storage_root)
            
            total_space = stat.f_frsize * stat.f_blocks
            free_space = stat.f_frsize * stat.f_available
            used_space = total_space - free_space
            
            # Count stored files
            file_count = len(self.list_files())
            
            return {
                "backend": self.backend_name,
                "storage_root": str(self.storage_root),
                "total_space_bytes": total_space,
                "used_space_bytes": used_space,
                "free_space_bytes": free_space,
                "usage_percent": (used_space / total_space * 100) if total_space > 0 else 0,
                "file_count": file_count
            }
            
        except Exception as e:
            return {
                "backend": self.backend_name,
                "storage_root": str(self.storage_root),
                "error": str(e)
            }
