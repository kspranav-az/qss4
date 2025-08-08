import io
import hashlib
from typing import BinaryIO, Dict, Any, Optional
from flask import current_app
from models import FileRecord, AuditLog
from app import db
from mineral.files.base_file import create_file_handler
from mineral.compression.zstd_compressor import ZstdCompressor
from mineral.encryption.hybrid_encryptor import KyberAESHybridEncryptor
from mineral.storage.local_fs import LocalFileSystemStorage
from mineral.blockchain.polygon_logger import PolygonBlockchainLogger
from mineral.blockchain.base import MockBlockchainLogger
from mineral.encryption.key_manager import key_manager
from core.config import settings

class FileService:
    """Main orchestrator for file operations: validate → compress → encrypt → store → log"""
    
    def __init__(self):
        # Initialize components
        self.compressor = ZstdCompressor(level=settings.compression_level)
        self.encryptor = KyberAESHybridEncryptor()
        
        # Initialize storage
        storage_config = {
            "storage_path": settings.storage_path
        }
        self.storage = LocalFileSystemStorage(storage_config)
        
        # Initialize blockchain logger
        if settings.polygon_private_key:
            blockchain_config = {
                "rpc_url": settings.polygon_rpc_url,
                "private_key": settings.polygon_private_key,
                "contract_address": settings.audit_contract_address
            }
            self.blockchain_logger = PolygonBlockchainLogger(blockchain_config)
        else:
            self.blockchain_logger = MockBlockchainLogger()
    
    def upload_file(self, file_stream: BinaryIO, filename: str, user_id: str, 
                   metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Complete file upload pipeline: validate → compress → encrypt → store → log
        
        Args:
            file_stream: Binary stream of file data
            filename: Original filename
            user_id: ID of user uploading the file
            metadata: Optional file metadata
        
        Returns:
            Dictionary with file information and upload results
        """
        try:
            current_app.logger.info(f"Starting file upload: {filename} for user {user_id}")
            
            # Step 1: Validate file
            file_handler = create_file_handler(file_stream, filename)
            if not file_handler.validate():
                raise ValueError("File validation failed")
            
            file_metadata = file_handler.get_metadata()
            current_app.logger.info(f"File validated: {file_metadata}")
            
            # Step 2: Compress file
            file_stream.seek(0)
            compressed_stream = self.compressor.compress_stream(file_stream)
            
            # Calculate hash of compressed data
            compressed_stream.seek(0)
            compressed_data = compressed_stream.read()
            file_hash = hashlib.sha3_512(compressed_data).hexdigest()
            
            # Reset stream
            compressed_stream = io.BytesIO(compressed_data)
            current_app.logger.info(f"File compressed: {len(compressed_data)} bytes")
            
            # Step 3: Encrypt file
            public_key = key_manager.get_public_key()
            encrypted_stream, kem_ciphertext, aes_nonce = self.encryptor.encrypt_with_public_key(
                compressed_stream, public_key
            )
            
            # Combine AES nonce with encrypted data for storage
            encrypted_stream.seek(0)
            encrypted_data = encrypted_stream.read()
            
            # Prepend nonce to encrypted data
            storage_data = aes_nonce + encrypted_data
            storage_stream = io.BytesIO(storage_data)
            
            current_app.logger.info(f"File encrypted: {len(storage_data)} bytes")
            
            # Step 4: Store encrypted file
            storage_id = self.storage.store(storage_stream, f"{user_id}_{filename}")
            current_app.logger.info(f"File stored: {storage_id}")
            
            # Step 5: Create database record
            file_record = FileRecord(
                user_id=user_id,
                storage_path=storage_id,
                original_filename=filename,
                size=file_metadata["size"],
                mime_type=file_metadata["mime_type"],
                compression_algo=self.compressor.algorithm_name,
                encryption_algo=self.encryptor.algorithm_name,
                kem_ciphertext=kem_ciphertext,
                file_hash=file_hash,
                file_metadata=metadata or {}
            )
            
            db.session.add(file_record)
            db.session.commit()
            
            current_app.logger.info(f"Database record created: {file_record.id}")
            
            # Step 6: Log to blockchain
            blockchain_data = {
                "user_id": user_id,
                "file_id": file_record.id,
                "filename": filename,
                "size": file_metadata["size"],
                "mime_type": file_metadata["mime_type"],
                "file_hash": file_hash
            }
            
            txn_id = self.blockchain_logger.log_event("file_upload", blockchain_data)
            
            if txn_id:
                file_record.blockchain_txn_id = txn_id
                db.session.commit()
                current_app.logger.info(f"Blockchain logged: {txn_id}")
            
            # Step 7: Create audit log
            audit_log = AuditLog(
                event_type="file_upload",
                table_name="files",
                row_id=file_record.id,
                user_id=user_id,
                txn_id=txn_id,
                details=blockchain_data
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            # Return upload results
            return {
                "file_id": file_record.id,
                "filename": filename,
                "size": file_metadata["size"],
                "mime_type": file_metadata["mime_type"],
                "compression_algo": self.compressor.algorithm_name,
                "encryption_algo": self.encryptor.algorithm_name,
                "file_hash": file_hash,
                "storage_id": storage_id,
                "blockchain_txn_id": txn_id,
                "upload_successful": True
            }
            
        except Exception as e:
            current_app.logger.error(f"File upload failed: {e}")
            
            # Rollback database changes
            db.session.rollback()
            
            # Clean up storage if file was stored
            if 'storage_id' in locals():
                try:
                    self.storage.delete(storage_id)
                except:
                    pass
            
            raise RuntimeError(f"File upload failed: {e}")
    
    def download_file(self, file_id: str, user_id: str) -> BinaryIO:
        """
        Download and decrypt file
        
        Args:
            file_id: ID of file to download
            user_id: ID of user requesting download
        
        Returns:
            Decrypted file stream
        """
        try:
            # Get file record
            file_record = FileRecord.query.filter_by(
                id=file_id, 
                deleted=False
            ).first()
            
            if not file_record:
                raise ValueError("File not found")
            
            # Check permissions (user owns file or is admin)
            if file_record.user_id != user_id:
                from models import User
                user = User.query.get(user_id)
                if not user or user.role != "admin":
                    raise PermissionError("Access denied")
            
            current_app.logger.info(f"Starting file download: {file_id} for user {user_id}")
            
            # Retrieve encrypted file from storage
            encrypted_stream = self.storage.retrieve(file_record.storage_path)
            
            # Extract nonce and encrypted data
            encrypted_stream.seek(0)
            storage_data = encrypted_stream.read()
            
            aes_nonce = storage_data[:12]  # First 12 bytes are nonce
            encrypted_data = storage_data[12:]  # Rest is encrypted data
            
            encrypted_stream = io.BytesIO(encrypted_data)
            
            # Decrypt file
            private_key = key_manager.get_private_key()
            compressed_stream = self.encryptor.decrypt_with_private_key(
                encrypted_stream, private_key, file_record.kem_ciphertext, aes_nonce
            )
            
            # Decompress file
            decrypted_stream = self.compressor.decompress_stream(compressed_stream)
            
            # Log download event
            audit_data = {
                "user_id": user_id,
                "file_id": file_id,
                "filename": file_record.original_filename
            }
            
            txn_id = self.blockchain_logger.log_event("file_download", audit_data)
            
            # Create audit log
            audit_log = AuditLog(
                event_type="file_download",
                table_name="files",
                row_id=file_id,
                user_id=user_id,
                txn_id=txn_id,
                details=audit_data
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            current_app.logger.info(f"File download completed: {file_id}")
            
            return decrypted_stream
            
        except Exception as e:
            current_app.logger.error(f"File download failed: {e}")
            raise RuntimeError(f"File download failed: {e}")
    
    def delete_file(self, file_id: str, user_id: str) -> bool:
        """
        Soft delete file
        
        Args:
            file_id: ID of file to delete
            user_id: ID of user requesting deletion
        
        Returns:
            True if successful
        """
        try:
            # Get file record
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
                if not user or user.role != "admin":
                    raise PermissionError("Access denied")
            
            # Soft delete
            file_record.deleted = True
            db.session.commit()
            
            # Log deletion event
            audit_data = {
                "user_id": user_id,
                "file_id": file_id,
                "filename": file_record.original_filename
            }
            
            txn_id = self.blockchain_logger.log_event("file_delete", audit_data)
            
            # Create audit log
            audit_log = AuditLog(
                event_type="file_delete",
                table_name="files",
                row_id=file_id,
                user_id=user_id,
                txn_id=txn_id,
                details=audit_data
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            current_app.logger.info(f"File deleted: {file_id}")
            return True
            
        except Exception as e:
            current_app.logger.error(f"File deletion failed: {e}")
            db.session.rollback()
            return False
    
    def get_file_info(self, file_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get file information
        
        Args:
            file_id: ID of file
            user_id: ID of user requesting info
        
        Returns:
            File information dictionary or None
        """
        try:
            file_record = FileRecord.query.filter_by(
                id=file_id,
                deleted=False
            ).first()
            
            if not file_record:
                return None
            
            # Check permissions
            if file_record.user_id != user_id:
                from models import User
                user = User.query.get(user_id)
                if not user or user.role != "admin":
                    return None
            
            return {
                "file_id": file_record.id,
                "filename": file_record.original_filename,
                "size": file_record.size,
                "mime_type": file_record.mime_type,
                "compression_algo": file_record.compression_algo,
                "encryption_algo": file_record.encryption_algo,
                "file_hash": file_record.file_hash,
                "blockchain_txn_id": file_record.blockchain_txn_id,
                "created_at": file_record.created_at.isoformat(),
                "metadata": file_record.metadata
            }
            
        except Exception as e:
            current_app.logger.error(f"Get file info failed: {e}")
            return None

# Global file service instance
file_service = FileService()
