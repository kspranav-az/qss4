import uuid
import datetime
from app import db
from flask_login import UserMixin
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Integer, DateTime, JSON, LargeBinary, Boolean, Text

class User(UserMixin, db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="user")  # user, admin, manager
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class FileRecord(db.Model):
    __tablename__ = "files"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    storage_path = db.Column(db.String(500), nullable=False)  # local path or storage key
    original_filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    compression_algo = db.Column(db.String(50), nullable=False)
    encryption_algo = db.Column(db.String(50), nullable=False)
    kem_ciphertext = db.Column(db.LargeBinary, nullable=False)  # Kyber encapsulated key
    file_hash = db.Column(db.String(128), nullable=False)  # SHA3-512 hash
    blockchain_txn_id = db.Column(db.String(100), nullable=True)
    file_metadata = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    deleted = db.Column(db.Boolean, default=False)
    
    # Relationship
    user = db.relationship('User', backref='files')

class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = db.Column(db.String(50), nullable=False)  # upload, download, delete, etc.
    table_name = db.Column(db.String(50))
    row_id = db.Column(db.String(36))
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    prev_hash = db.Column(db.String(128))  # hash-chain for integrity
    record_hash = db.Column(db.String(128))  # SHA3-512 of this record
    signature = db.Column(db.LargeBinary)  # optional digital signature
    txn_id = db.Column(db.String(100), nullable=True)  # blockchain transaction ID
    details = db.Column(db.JSON)  # additional event details
    
    # Relationship
    user = db.relationship('User', backref='audit_logs')

class DownloadToken(db.Model):
    __tablename__ = "download_tokens"
    
    token = db.Column(db.String(64), primary_key=True)
    file_id = db.Column(db.String(36), db.ForeignKey('files.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ttl_seconds = db.Column(db.Integer, default=60)
    used = db.Column(db.Boolean, default=False)
    
    # Relationships
    file = db.relationship('FileRecord', backref='download_tokens')
    user = db.relationship('User', backref='download_tokens')
