import magic
import hashlib
from abc import ABC, abstractmethod
from typing import BinaryIO, Optional, Dict, Any
from pathlib import Path

class AbstractFile(ABC):
    """Abstract base class for file handling with validation and MIME checking"""
    
    def __init__(self, file_stream: BinaryIO, filename: str):
        self.file_stream = file_stream
        self.filename = filename
        self.size = 0
        self.mime_type = ""
        self.file_hash = ""
        self._validated = False
    
    def validate(self) -> bool:
        """Validate file format, MIME type, and calculate hash"""
        try:
            # Reset stream position
            self.file_stream.seek(0)
            
            # Read file content for validation
            content = self.file_stream.read()
            self.size = len(content)
            
            # Detect MIME type using python-magic
            self.mime_type = magic.from_buffer(content, mime=True)
            
            # Calculate SHA3-512 hash
            hasher = hashlib.sha3_512()
            hasher.update(content)
            self.file_hash = hasher.hexdigest()
            
            # Reset stream position
            self.file_stream.seek(0)
            
            # Perform specific validation
            self._validated = self._validate_content(content)
            return self._validated
            
        except Exception as e:
            print(f"File validation error: {e}")
            return False
    
    @abstractmethod
    def _validate_content(self, content: bytes) -> bool:
        """Implement specific content validation logic"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get file metadata"""
        return {
            "filename": self.filename,
            "size": self.size,
            "mime_type": self.mime_type,
            "file_hash": self.file_hash,
            "validated": self._validated
        }
    
    def is_safe_mime_type(self, allowed_types: list = None) -> bool:
        """Check if MIME type is in allowed list"""
        if allowed_types is None:
            # Default safe MIME types
            allowed_types = [
                'application/pdf',
                'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'text/plain',
                'text/csv',
                'image/jpeg',
                'image/png',
                'image/gif',
                'image/svg+xml',
                'application/json',
                'application/xml'
            ]
        
        return self.mime_type in allowed_types

class GenericFile(AbstractFile):
    """Generic file handler for common file types"""
    
    def _validate_content(self, content: bytes) -> bool:
        """Basic validation for generic files"""
        # Check for minimum file size
        if len(content) == 0:
            return False
        
        # Check if it's a safe MIME type
        if not self.is_safe_mime_type():
            print(f"Unsafe MIME type detected: {self.mime_type}")
            return False
        
        # Additional security checks for executable files
        dangerous_signatures = [
            b'\x4d\x5a',  # PE executable
            b'\x7f\x45\x4c\x46',  # ELF executable
            b'\xca\xfe\xba\xbe',  # Mach-O binary
            b'\xfe\xed\xfa\xce',  # Mach-O binary
        ]
        
        for sig in dangerous_signatures:
            if content.startswith(sig):
                print("Potentially dangerous executable file detected")
                return False
        
        return True

class PDFFile(AbstractFile):
    """Specialized handler for PDF files"""
    
    def _validate_content(self, content: bytes) -> bool:
        """PDF-specific validation"""
        # Check PDF signature
        if not content.startswith(b'%PDF-'):
            return False
        
        # Check for PDF trailer
        if b'%%EOF' not in content[-1024:]:
            return False
        
        # Basic structure validation
        if b'obj' not in content or b'endobj' not in content:
            return False
        
        return True

class ImageFile(AbstractFile):
    """Specialized handler for image files"""
    
    def _validate_content(self, content: bytes) -> bool:
        """Image-specific validation"""
        # Check common image signatures
        image_signatures = {
            b'\xff\xd8\xff': 'image/jpeg',
            b'\x89\x50\x4e\x47': 'image/png',
            b'\x47\x49\x46\x38': 'image/gif',
            b'\x42\x4d': 'image/bmp',
        }
        
        for sig, expected_mime in image_signatures.items():
            if content.startswith(sig):
                return self.mime_type.startswith('image/')
        
        # SVG validation
        if self.mime_type == 'image/svg+xml':
            try:
                content_str = content.decode('utf-8', errors='ignore')
                return '<svg' in content_str and '</svg>' in content_str
            except:
                return False
        
        return False

def create_file_handler(file_stream: BinaryIO, filename: str) -> AbstractFile:
    """Factory function to create appropriate file handler"""
    # Get file extension
    ext = Path(filename).suffix.lower()
    
    # Return specialized handler based on extension
    if ext == '.pdf':
        return PDFFile(file_stream, filename)
    elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg']:
        return ImageFile(file_stream, filename)
    else:
        return GenericFile(file_stream, filename)
