# QSS4 - Quantum-Safe Secure Storage

![QSS4 Logo](https://via.placeholder.com/200x80/2563eb/ffffff?text=QSS4)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![Security](https://img.shields.io/badge/Security-Post--Quantum-red.svg)](https://csrc.nist.gov/projects/post-quantum-cryptography)

A production-ready Flask backend for secure file storage featuring post-quantum cryptography, blockchain audit trails, and enterprise-grade security controls.

## 🚀 Features

### 🔐 Post-Quantum Cryptography
- **Kyber-1024 KEM** for quantum-resistant key encapsulation
- **AES-256-GCM** symmetric encryption for data protection
- **Hybrid encryption** combining PQ and classical cryptography
- **SHA3-512** cryptographic hashing

### 🛡️ Enterprise Security
- **JWT-based authentication** with role-based access control
- **Argon2** password hashing
- **Rate limiting** and brute force protection
- **MIME type validation** and security scanning
- **Secure file handling** with subprocess isolation

### 📊 Blockchain Audit Trail
- **Polygon blockchain** integration for tamper-proof logs
- **Immutable audit records** of all file operations
- **Cryptographic verification** of file integrity
- **Transaction anchoring** for compliance

### 🗜️ Smart Compression
- **Zstandard compression** for optimal storage efficiency
- **Streaming compression** for large files
- **Configurable compression levels**
- **Transparent decompression** during downloads

### 🔄 Secure File Sharing
- **One-time download tokens** with TTL expiration
- **Atomic token validation** using Redis Lua scripts
- **Secure URL generation** for controlled access
- **Token revocation** and management

### 🖥️ Cross-Platform CLI
- **Rich terminal interface** with progress bars
- **Secure credential storage** using OS keyring
- **Batch operations** and automation support
- **Configuration management**

## 📋 Requirements

- **Python 3.8+**
- **Redis 6.0+**
- **PostgreSQL 13+** (SQLite for development)
- **Node.js 16+** (for CLI dependencies)

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/your-org/qss4-backend.git
cd qss4-backend
