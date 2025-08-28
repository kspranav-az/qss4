import os
import json
from pathlib import Path
from typing import Optional, Tuple
from cryptography.fernet import Fernet
from core.config import settings
from .hybrid_encryptor import KyberKEM

class KeyManager:
    """Secure key management for Kyber keypairs and configuration"""
    
    def __init__(self):
        self.kem = KyberKEM()
        self.fernet_key = self._get_fernet_key()
        self.cipher_suite = Fernet(self.fernet_key) if self.fernet_key else None
        
        # Ensure key directory exists
        self.key_dir = Path("keys")
        self.key_dir.mkdir(exist_ok=True)
    
    def _get_fernet_key(self) -> bytes:
        """Get Fernet key for config encryption"""
        # Hardcoded Fernet key for encryption
        key = "g414Y6DmuaxaDjcB7XBqY7SYPFZFOYP5YlYod5Likio="
        return key.encode() if isinstance(key, str) else key
    
    def generate_kyber_keypair(self) -> Tuple[bytes, bytes]:
        """Generate new Kyber keypair"""
        try:
            public_key, private_key = self.kem.generate_keypair()
            return public_key, private_key
        except Exception as e:
            raise RuntimeError(f"Failed to generate Kyber keypair: {e}")
    
    def save_keypair(self, public_key: bytes, private_key: bytes, 
                    encrypt: bool = True) -> dict:
        """
        Save Kyber keypair to files
        
        Args:
            public_key: Kyber public key
            private_key: Kyber private key
            encrypt: Whether to encrypt the private key with Fernet
        
        Returns:
            dict with file paths and metadata
        """
        try:
            # Save public key (not encrypted)
            public_key_path = self.key_dir / "kyber_public.key"
            with open(public_key_path, "wb") as f:
                f.write(public_key)
            
            # Save private key (optionally encrypted)
            private_key_path = self.key_dir / "kyber_private.key"
            if encrypt and self.cipher_suite:
                encrypted_private_key = self.cipher_suite.encrypt(private_key)
                with open(private_key_path, "wb") as f:
                    f.write(encrypted_private_key)
            else:
                with open(private_key_path, "wb") as f:
                    f.write(private_key)
            
            # Save metadata
            metadata = {
                "algorithm": self.kem.algorithm_name,
                "public_key_size": len(public_key),
                "private_key_size": len(private_key),
                "encrypted": encrypt,
                "public_key_path": str(public_key_path),
                "private_key_path": str(private_key_path)
            }
            
            metadata_path = self.key_dir / "kyber_metadata.json"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            
            # Set secure file permissions
            os.chmod(private_key_path, 0o600)  # Owner read/write only
            os.chmod(public_key_path, 0o644)   # Owner read/write, others read
            os.chmod(metadata_path, 0o644)
            
            return metadata
            
        except Exception as e:
            raise RuntimeError(f"Failed to save keypair: {e}")
    
    def load_keypair(self) -> Tuple[bytes, bytes]:
        """
        Load Kyber keypair from files
        
        Returns:
            Tuple of (public_key, private_key)
        """
        try:
            # Load metadata
            metadata_path = self.key_dir / "kyber_metadata.json"
            if not metadata_path.exists():
                raise FileNotFoundError("Kyber metadata file not found")
            
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            
            # Load public key
            public_key_path = Path(metadata["public_key_path"])
            if not public_key_path.exists():
                raise FileNotFoundError(f"Public key file not found: {public_key_path}")
            
            with open(public_key_path, "rb") as f:
                public_key = f.read()
            
            # Load private key
            private_key_path = Path(metadata["private_key_path"])
            if not private_key_path.exists():
                raise FileNotFoundError(f"Private key file not found: {private_key_path}")
            
            with open(private_key_path, "rb") as f:
                private_key_data = f.read()
            
            # Decrypt private key if encrypted
            if metadata.get("encrypted", False):
                if not self.cipher_suite:
                    raise RuntimeError("Fernet key not available for decryption")
                private_key = self.cipher_suite.decrypt(private_key_data)
            else:
                private_key = private_key_data
            
            return public_key, private_key
            
        except Exception as e:
            raise RuntimeError(f"Failed to load keypair: {e}")
    
    def get_public_key(self) -> bytes:
        """Get public key only"""
        public_key, _ = self.load_keypair()
        return public_key
    
    def get_private_key(self) -> bytes:
        """Get private key only"""
        _, private_key = self.load_keypair()
        return private_key
    
    def keypair_exists(self) -> bool:
        """Check if keypair files exist"""
        metadata_path = self.key_dir / "kyber_metadata.json"
        return metadata_path.exists()
    
    def rotate_keypair(self) -> dict:
        """
        Generate new keypair and backup old one
        
        Returns:
            dict with new keypair metadata
        """
        try:
            # Backup existing keypair if it exists
            if self.keypair_exists():
                backup_dir = self.key_dir / "backup"
                backup_dir.mkdir(exist_ok=True)
                
                import shutil
                import datetime
                
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                
                # Copy files to backup directory
                for file_name in ["kyber_public.key", "kyber_private.key", "kyber_metadata.json"]:
                    src_path = self.key_dir / file_name
                    if src_path.exists():
                        dst_path = backup_dir / f"{timestamp}_{file_name}"
                        shutil.copy2(src_path, dst_path)
            
            # Generate and save new keypair
            public_key, private_key = self.generate_kyber_keypair()
            metadata = self.save_keypair(public_key, private_key, encrypt=True)
            
            print(f"Keypair rotated successfully. Backup created with timestamp: {timestamp}")
            return metadata
            
        except Exception as e:
            raise RuntimeError(f"Failed to rotate keypair: {e}")
    
    def secure_delete_key_material(self, data: bytes) -> None:
        """Securely overwrite key material in memory"""
        if isinstance(data, bytes):
            # Overwrite memory with zeros (basic secure deletion)
            for i in range(len(data)):
                data = data[:i] + b'\x00' + data[i+1:]

# Global key manager instance
key_manager = KeyManager()
