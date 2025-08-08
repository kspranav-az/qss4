import subprocess
import tempfile
import os
import magic
from pathlib import Path
from typing import BinaryIO, Dict, Any, Optional
from flask import current_app

class SecuritySandbox:
    """MIME-based sandbox validation with subprocess isolation"""
    
    def __init__(self):
        self.allowed_mime_types = {
            # Documents
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'text/csv',
            'application/json',
            'application/xml',
            
            # Images
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/svg+xml',
            'image/bmp',
            'image/webp',
            
            # Medical (DICOM)
            'application/dicom',
            
            # Archives (with caution)
            'application/zip',
            'application/x-tar',
            'application/gzip'
        }
        
        self.dangerous_signatures = [
            b'\x4d\x5a',  # PE executable (Windows)
            b'\x7f\x45\x4c\x46',  # ELF executable (Linux)
            b'\xca\xfe\xba\xbe',  # Mach-O binary (macOS)
            b'\xfe\xed\xfa\xce',  # Mach-O binary (macOS)
            b'\xce\xfa\xed\xfe',  # Mach-O binary (macOS)
            b'\xcf\xfa\xed\xfe',  # Mach-O binary (macOS)
            b'\x50\x4b\x03\x04',  # ZIP (potentially dangerous)
        ]
    
    def validate_file_security(self, file_stream: BinaryIO, filename: str) -> Dict[str, Any]:
        """
        Comprehensive security validation of uploaded file
        
        Args:
            file_stream: Binary stream of file data
            filename: Original filename
        
        Returns:
            Dictionary with validation results
        """
        result = {
            "safe": False,
            "mime_type": "",
            "detected_type": "",
            "filename": filename,
            "size": 0,
            "warnings": [],
            "errors": []
        }
        
        try:
            # Reset stream position
            file_stream.seek(0)
            content = file_stream.read()
            result["size"] = len(content)
            
            # Reset stream for further use
            file_stream.seek(0)
            
            # Basic size check
            max_size = 100 * 1024 * 1024  # 100MB
            if len(content) > max_size:
                result["errors"].append(f"File too large: {len(content)} bytes")
                return result
            
            # Empty file check
            if len(content) == 0:
                result["errors"].append("Empty file")
                return result
            
            # MIME type detection
            mime_type = magic.from_buffer(content, mime=True)
            result["mime_type"] = mime_type
            result["detected_type"] = magic.from_buffer(content)
            
            # Check against allowed MIME types
            if mime_type not in self.allowed_mime_types:
                result["errors"].append(f"MIME type not allowed: {mime_type}")
                return result
            
            # Check for dangerous file signatures
            for signature in self.dangerous_signatures:
                if content.startswith(signature):
                    result["errors"].append("Potentially dangerous executable file detected")
                    return result
            
            # Filename extension check
            file_ext = Path(filename).suffix.lower()
            dangerous_extensions = {
                '.exe', '.bat', '.cmd', '.scr', '.pif', '.com',
                '.vbs', '.js', '.jar', '.app', '.deb', '.rpm',
                '.msi', '.pkg', '.dmg', '.run', '.bin'
            }
            
            if file_ext in dangerous_extensions:
                result["errors"].append(f"Dangerous file extension: {file_ext}")
                return result
            
            # Additional MIME-specific validation
            if mime_type == 'application/pdf':
                if not self._validate_pdf(content):
                    result["errors"].append("Invalid or corrupted PDF file")
                    return result
            elif mime_type.startswith('image/'):
                if not self._validate_image(content, mime_type):
                    result["warnings"].append("Image validation warnings")
            elif mime_type == 'application/zip':
                result["warnings"].append("ZIP archive detected - contents not validated")
            
            # Subprocess isolation test (optional)
            if self._should_run_subprocess_check(mime_type):
                subprocess_result = self._run_subprocess_validation(content, mime_type)
                if not subprocess_result["safe"]:
                    result["errors"].extend(subprocess_result["errors"])
                    return result
                result["warnings"].extend(subprocess_result.get("warnings", []))
            
            result["safe"] = True
            current_app.logger.info(f"File validation passed: {filename} ({mime_type})")
            
        except Exception as e:
            result["errors"].append(f"Validation error: {str(e)}")
            current_app.logger.error(f"File validation failed: {e}")
        
        return result
    
    def _validate_pdf(self, content: bytes) -> bool:
        """Validate PDF file structure"""
        try:
            # Check PDF header
            if not content.startswith(b'%PDF-'):
                return False
            
            # Check for EOF marker
            if b'%%EOF' not in content[-1024:]:
                return False
            
            # Basic structure checks
            if b'obj' not in content or b'endobj' not in content:
                return False
            
            # Check for suspicious JavaScript or embedded files
            suspicious_patterns = [b'/JavaScript', b'/JS', b'/EmbeddedFile']
            for pattern in suspicious_patterns:
                if pattern in content:
                    current_app.logger.warning(f"Suspicious PDF pattern found: {pattern}")
            
            return True
            
        except Exception:
            return False
    
    def _validate_image(self, content: bytes, mime_type: str) -> bool:
        """Validate image file structure"""
        try:
            image_signatures = {
                'image/jpeg': [b'\xff\xd8\xff'],
                'image/png': [b'\x89\x50\x4e\x47'],
                'image/gif': [b'\x47\x49\x46\x38'],
                'image/bmp': [b'\x42\x4d'],
                'image/webp': [b'\x52\x49\x46\x46']
            }
            
            signatures = image_signatures.get(mime_type, [])
            for sig in signatures:
                if content.startswith(sig):
                    return True
            
            # SVG special case
            if mime_type == 'image/svg+xml':
                try:
                    content_str = content.decode('utf-8', errors='ignore')
                    return '<svg' in content_str and '</svg>' in content_str
                except:
                    return False
            
            return len(signatures) == 0  # Unknown image type, allow by default
            
        except Exception:
            return False
    
    def _should_run_subprocess_check(self, mime_type: str) -> bool:
        """Determine if subprocess validation should be run"""
        # Only run subprocess checks for potentially risky file types
        risky_types = {
            'application/zip',
            'application/x-tar',
            'application/pdf'
        }
        return mime_type in risky_types
    
    def _run_subprocess_validation(self, content: bytes, mime_type: str) -> Dict[str, Any]:
        """
        Run file validation in isolated subprocess
        
        Args:
            content: File content
            mime_type: Detected MIME type
        
        Returns:
            Validation results from subprocess
        """
        result = {"safe": True, "errors": [], "warnings": []}
        
        try:
            # Create temporary file for subprocess validation
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(content)
                temp_path = temp_file.name
            
            try:
                # Run validation based on file type
                if mime_type == 'application/pdf':
                    result = self._validate_pdf_subprocess(temp_path)
                elif mime_type == 'application/zip':
                    result = self._validate_zip_subprocess(temp_path)
                else:
                    # Generic file validation
                    result = self._validate_generic_subprocess(temp_path)
                
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_path)
                except:
                    pass
            
        except Exception as e:
            result["errors"].append(f"Subprocess validation failed: {str(e)}")
            result["safe"] = False
        
        return result
    
    def _validate_pdf_subprocess(self, file_path: str) -> Dict[str, Any]:
        """Validate PDF using subprocess (if pdfinfo is available)"""
        result = {"safe": True, "errors": [], "warnings": []}
        
        try:
            # Try to use pdfinfo for validation
            cmd_result = subprocess.run(
                ['file', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if cmd_result.returncode == 0:
                output = cmd_result.stdout.lower()
                if 'pdf' not in output:
                    result["errors"].append("File does not appear to be a valid PDF")
                    result["safe"] = False
            else:
                result["warnings"].append("Could not validate PDF with external tools")
                
        except subprocess.TimeoutExpired:
            result["errors"].append("PDF validation timeout")
            result["safe"] = False
        except FileNotFoundError:
            result["warnings"].append("PDF validation tools not available")
        except Exception as e:
            result["warnings"].append(f"PDF validation error: {str(e)}")
        
        return result
    
    def _validate_zip_subprocess(self, file_path: str) -> Dict[str, Any]:
        """Validate ZIP using subprocess"""
        result = {"safe": True, "errors": [], "warnings": []}
        
        try:
            # Use unzip to test archive integrity
            cmd_result = subprocess.run(
                ['unzip', '-t', file_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if cmd_result.returncode != 0:
                result["errors"].append("ZIP archive appears to be corrupted")
                result["safe"] = False
            else:
                result["warnings"].append("ZIP archive validated but contents not scanned")
                
        except subprocess.TimeoutExpired:
            result["errors"].append("ZIP validation timeout")
            result["safe"] = False
        except FileNotFoundError:
            result["warnings"].append("ZIP validation tools not available")
        except Exception as e:
            result["warnings"].append(f"ZIP validation error: {str(e)}")
        
        return result
    
    def _validate_generic_subprocess(self, file_path: str) -> Dict[str, Any]:
        """Generic file validation using subprocess"""
        result = {"safe": True, "errors": [], "warnings": []}
        
        try:
            # Use file command for basic validation
            cmd_result = subprocess.run(
                ['file', '-b', file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if cmd_result.returncode == 0:
                file_type = cmd_result.stdout.strip().lower()
                
                # Check for suspicious content
                suspicious_keywords = ['executable', 'script', 'binary']
                for keyword in suspicious_keywords:
                    if keyword in file_type:
                        result["warnings"].append(f"File may contain {keyword} content")
            
        except subprocess.TimeoutExpired:
            result["warnings"].append("File validation timeout")
        except FileNotFoundError:
            result["warnings"].append("File validation tools not available")
        except Exception as e:
            result["warnings"].append(f"File validation error: {str(e)}")
        
        return result

# Global sandbox instance
security_sandbox = SecuritySandbox()
