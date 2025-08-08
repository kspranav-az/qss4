# Overview

QSS4 Quantum Safe Stone is a Flask-based backend service that provides enterprise-grade secure file storage with post-quantum cryptography capabilities. The system combines Kyber-1024 key encapsulation with AES-256-GCM encryption, blockchain audit trails via Polygon network, and smart compression using Zstandard. It features role-based access control, rate limiting, secure file sharing with one-time tokens, and a cross-platform CLI client. The application is designed for production deployment with comprehensive security controls including MIME type validation, subprocess isolation, and Redis-backed caching.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Architecture
- **Flask Application Factory Pattern**: Modular design with blueprints for authentication, file management, user management, and health checks
- **SQLAlchemy ORM**: Database abstraction layer with support for PostgreSQL and SQLite
- **JWT Authentication**: Token-based authentication with refresh token support and role-based access control (admin, manager, user)
- **Rate Limiting**: Redis-backed sliding window rate limiting to prevent abuse
- **Proxy Fix Middleware**: Production-ready deployment support for reverse proxy setups

## Security Framework
- **Post-Quantum Cryptography**: Hybrid encryption using Kyber-1024 KEM for quantum-resistant key encapsulation combined with AES-256-GCM
- **Password Security**: Argon2 password hashing with strength validation
- **File Validation**: MIME type detection using python-magic library with security sandbox for malware detection
- **Subprocess Isolation**: Secure file handling to prevent code execution attacks
- **Role-Based Access Control**: Three-tier permission system with decorators for endpoint protection

## File Processing Pipeline
- **Validation Layer**: MIME type checking, file size limits, and security scanning
- **Compression Layer**: Zstandard compression with configurable levels for optimal storage efficiency
- **Encryption Layer**: Kyber-1024 key encapsulation followed by AES-256-GCM symmetric encryption
- **Storage Layer**: Pluggable storage backend (currently local filesystem with secure path handling)
- **Audit Layer**: Blockchain logging to Polygon network for tamper-proof audit trails

## Data Storage
- **Primary Database**: User accounts, file metadata, audit logs, and download tokens
- **File Storage**: Encrypted files stored on local filesystem with hash-based organization
- **Caching Layer**: Redis for session management, rate limiting, and one-time download tokens
- **Key Management**: Secure storage of Kyber keypairs with optional Fernet encryption

## API Design
- **RESTful Endpoints**: Organized into versioned blueprints (v1) for authentication, files, users, and health checks
- **Streaming Support**: Large file uploads and downloads using chunked processing
- **Token-Based Downloads**: One-time use tokens with TTL expiration for secure file sharing
- **Pagination**: Efficient data retrieval with filtering and sorting capabilities

## Client Interface
- **Rich CLI Client**: Cross-platform command-line interface with progress bars and secure credential storage
- **Web Interface**: Bootstrap-based responsive frontend with drag-and-drop file uploads
- **Keyring Integration**: Secure credential storage using OS-native keyring services

# External Dependencies

## Databases
- **PostgreSQL/SQLite**: Primary data storage for user accounts, file metadata, and audit logs
- **Redis**: Caching layer for sessions, rate limiting, and temporary token storage

## Cryptographic Libraries
- **kyber-py**: Post-quantum Kyber-1024 key encapsulation mechanism
- **cryptography**: AES-256-GCM encryption and Fernet key protection
- **python-magic**: MIME type detection for file validation

## Blockchain Integration
- **Polygon Network**: Ethereum-compatible blockchain for immutable audit trails
- **Web3.py**: Ethereum blockchain interaction library
- **eth-account**: Ethereum account management and transaction signing

## Compression and Storage
- **zstandard**: High-performance compression algorithm
- **Flask-SQLAlchemy**: Database ORM integration
- **Flask-JWT-Extended**: JWT token management with refresh support

## Security and Validation
- **Werkzeug**: Secure filename handling and password hashing
- **python-magic**: File type detection and validation
- **keyring**: Secure credential storage for CLI client

## Development and Deployment
- **Click**: Command-line interface framework for scripts and CLI client
- **Rich**: Terminal UI library for enhanced CLI experience
- **Flask-Login**: Session management for web interface
- **ProxyFix**: Production deployment middleware for reverse proxy support