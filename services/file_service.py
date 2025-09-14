import io
import logging
import hashlib
from typing import BinaryIO, Dict, Any, Optional
from flask import current_app
from models import FileRecord, AuditLog

# Configure logger
logger = logging.getLogger(__name__)
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
        """
        try:
            current_app.logger.info(f"[UPLOAD] Starting file upload: {filename} for user {user_id}")
            current_app.logger.debug(f"[UPLOAD] File stream info - closed: {getattr(file_stream, 'closed', 'N/A')}, position: {getattr(file_stream, 'tell', lambda: 'N/A')()}")

            # Step 0: Read file into memory
            try:
                file_content = file_stream.read()
                current_app.logger.debug(f"[UPLOAD] Read {len(file_content)} bytes from file stream")
            except Exception as e:
                current_app.logger.error(f"[UPLOAD] Error reading file stream: {e}")
                raise

            # Step 1: Validate
            try:
                validation_stream = io.BytesIO(file_content)
                file_handler = create_file_handler(validation_stream, filename)
                if not file_handler.validate():
                    raise ValueError("File validation failed")
                file_metadata = file_handler.get_metadata()
                current_app.logger.info(f"[UPLOAD] File validated: {file_metadata}")
            except Exception as e:
                current_app.logger.error(f"[UPLOAD] Validation failed: {e}")
                raise

            # Step 2: Compress
            input_stream = None
            compressed_stream = None
            
            try:
                # Create a new stream for compression
                input_stream = io.BytesIO(file_content)
                current_app.logger.debug("[UPLOAD] Created input stream for compression")

                # Compress the data using streaming
                compressed_stream = self.compressor.compress_stream(input_stream)
                current_app.logger.debug("[UPLOAD] Compression completed")
                
                # Get the compressed data
                compressed_data = compressed_stream.read()
                current_app.logger.info(f"[UPLOAD] File compressed: {len(compressed_data)} bytes")
                
                # Create a new stream for the next step
                compressed_stream = io.BytesIO(compressed_data)
                
            except Exception as e:
                current_app.logger.error(f"[UPLOAD] Compression failed: {e}", exc_info=True)
                raise
                
            finally:
                # Clean up resources
                if input_stream and not input_stream.closed:
                    input_stream.close()
                # Only close compressed_stream if it's the original stream from compressor
                # and not the new BytesIO we created after reading the data
                if (compressed_stream and not compressed_stream.closed and 
                    'compressed_data' not in locals()):
                    compressed_stream.close()

            # Step 3: Hash
            try:
                file_hash = hashlib.sha3_512(compressed_data).hexdigest()
                current_app.logger.debug(f"[UPLOAD] Generated file hash: {file_hash[:8]}...")
            except Exception as e:
                current_app.logger.error(f"[UPLOAD] Error hashing compressed data: {e}")
                raise

            # Step 4: Encrypt
            try:
                logger.debug("[UPLOAD] Starting file encryption")
                public_key = key_manager.get_public_key()
                encrypted_stream, kem_ciphertext, aes_nonce = self.encryptor.encrypt_with_public_key(
                    io.BytesIO(compressed_data), public_key
                )
                encrypted_data = encrypted_stream.read()
                storage_data = aes_nonce + encrypted_data
                storage_stream = io.BytesIO(storage_data)
                logger.info(f"[UPLOAD] File encrypted: {len(storage_data)} bytes")
            except Exception as e:
                logger.error(f"[UPLOAD] Encryption failed: {e}")
                raise

            # Step 5: Store
            try:
                storage_id = self.storage.store(storage_stream, f"{user_id}_{filename}")
                logger.info(f"[UPLOAD] File stored: {storage_id}")
            except Exception as e:
                logger.error(f"[UPLOAD] Storage failed: {e}")
                raise

            # Step 6: Database record
            try:
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
                logger.info(f"[UPLOAD] Database record created: {file_record.id}")
            except Exception as e:
                logger.error(f"[UPLOAD] Database insert failed: {e}")
                db.session.rollback()
                raise

            # Step 7: Blockchain log
            txn_id = None
            try:
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
                    logger.info(f"[UPLOAD] Blockchain logged: {txn_id}")
            except Exception as e:
                logger.error(f"[UPLOAD] Blockchain log failed: {e}")
                db.session.rollback()

            # Step 8: Audit log
            try:
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
            except Exception as e:
                logger.error(f"[UPLOAD] Audit log failed: {e}")
                db.session.rollback()

            # Final response
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
            logger.error(f"[UPLOAD] File upload failed: {e}")
            db.session.rollback()
            if 'storage_id' in locals():
                try:
                    self.storage.delete(storage_id)
                except Exception:
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

            # Physically delete the file from storage
            self.storage_backend.delete(file_record.storage_id)

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
