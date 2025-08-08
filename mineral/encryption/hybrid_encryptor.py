import os
import io
from typing import BinaryIO, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .base import BaseEncryptor, BaseKEM, HybridEncryptor

# Kyber implementation (using kyber-py)
try:
    from kyber_py.ml_kem import ML_KEM_1024
    KYBER_AVAILABLE = True
except ImportError:
    print("Warning: kyber-py not available, using mock implementation")
    KYBER_AVAILABLE = False

class MockKyber:
    """Mock Kyber implementation for development when kyber-py is not available"""
    
    @staticmethod
    def keygen():
        # Generate mock keys (DO NOT USE IN PRODUCTION)
        public_key = os.urandom(1568)  # ML-KEM-1024 public key size
        private_key = os.urandom(3168)  # ML-KEM-1024 private key size
        return public_key, private_key
    
    @staticmethod
    def encaps(public_key):
        # Mock encapsulation
        shared_secret = os.urandom(32)  # 256-bit shared secret
        ciphertext = os.urandom(1568)  # ML-KEM-1024 ciphertext size
        return shared_secret, ciphertext
    
    @staticmethod
    def decaps(private_key, ciphertext):
        # Mock decapsulation (returns random secret - FOR DEVELOPMENT ONLY)
        return os.urandom(32)

class KyberKEM(BaseKEM):
    """Kyber Key Encapsulation Mechanism implementation"""
    
    def __init__(self):
        super().__init__()
        self.algorithm_name = "kyber-1024"
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Kyber keypair"""
        if KYBER_AVAILABLE:
            return ML_KEM_1024.keygen()
        else:
            return MockKyber.keygen()
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate shared secret with Kyber public key"""
        if KYBER_AVAILABLE:
            return ML_KEM_1024.encaps(public_key)
        else:
            return MockKyber.encaps(public_key)
    
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate shared secret with Kyber private key"""
        if KYBER_AVAILABLE:
            return ML_KEM_1024.decaps(private_key, ciphertext)
        else:
            return MockKyber.decaps(private_key, ciphertext)
    
    def get_public_key_size(self) -> int:
        return 1568  # ML-KEM-1024 public key size
    
    def get_private_key_size(self) -> int:
        return 3168  # ML-KEM-1024 private key size
    
    def get_ciphertext_size(self) -> int:
        return 1568  # ML-KEM-1024 ciphertext size

class AESGCMEncryptor(BaseEncryptor):
    """AES-GCM symmetric encryption implementation"""
    
    def __init__(self):
        super().__init__()
        self.algorithm_name = "aes-256-gcm"
    
    def encrypt_stream(self, input_stream: BinaryIO, key: bytes) -> Tuple[BinaryIO, bytes]:
        """Encrypt stream using AES-GCM"""
        try:
            # Generate nonce
            nonce = os.urandom(12)  # 96-bit nonce for GCM
            
            # Create cipher
            aesgcm = AESGCM(key)
            
            # Read all data (for simplicity, can be optimized for streaming)
            input_stream.seek(0)
            plaintext = input_stream.read()
            
            # Encrypt
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)
            
            # Create output stream
            output_stream = io.BytesIO(ciphertext)
            output_stream.seek(0)
            
            return output_stream, nonce
            
        except Exception as e:
            raise RuntimeError(f"AES-GCM encryption failed: {e}")
    
    def decrypt_stream(self, encrypted_stream: BinaryIO, key: bytes, nonce: bytes) -> BinaryIO:
        """Decrypt stream using AES-GCM"""
        try:
            # Create cipher
            aesgcm = AESGCM(key)
            
            # Read encrypted data
            encrypted_stream.seek(0)
            ciphertext = encrypted_stream.read()
            
            # Decrypt
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Create output stream
            output_stream = io.BytesIO(plaintext)
            output_stream.seek(0)
            
            return output_stream
            
        except Exception as e:
            raise RuntimeError(f"AES-GCM decryption failed: {e}")
    
    def generate_key(self) -> bytes:
        """Generate 256-bit AES key"""
        return os.urandom(32)
    
    def get_key_size(self) -> int:
        """Return key size in bytes"""
        return 32  # 256 bits

class KyberAESHybridEncryptor(HybridEncryptor):
    """Hybrid encryptor using Kyber KEM + AES-GCM"""
    
    def __init__(self):
        kem = KyberKEM()
        encryptor = AESGCMEncryptor()
        super().__init__(kem, encryptor)
    
    def encrypt_with_public_key(self, input_stream: BinaryIO, public_key: bytes) -> Tuple[BinaryIO, bytes, bytes]:
        """
        Encrypt using Kyber + AES-GCM hybrid scheme
        Returns (encrypted_stream, kem_ciphertext, aes_nonce)
        """
        try:
            # Step 1: Use Kyber to encapsulate a shared secret
            shared_secret, kem_ciphertext = self.kem.encapsulate(public_key)
            
            # Step 2: Derive AES key from shared secret using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES
                salt=None,
                info=b'qss4-hybrid-encryption'
            )
            aes_key = hkdf.derive(shared_secret)
            
            # Step 3: Encrypt data with AES-GCM
            encrypted_stream, nonce = self.encryptor.encrypt_stream(input_stream, aes_key)
            
            # Clear sensitive data
            shared_secret = b'\x00' * len(shared_secret)
            aes_key = b'\x00' * len(aes_key)
            
            return encrypted_stream, kem_ciphertext, nonce
            
        except Exception as e:
            raise RuntimeError(f"Hybrid encryption failed: {e}")
    
    def decrypt_with_private_key(self, encrypted_stream: BinaryIO, private_key: bytes, 
                               kem_ciphertext: bytes, nonce: bytes) -> BinaryIO:
        """
        Decrypt using Kyber + AES-GCM hybrid scheme
        Returns decrypted_stream
        """
        try:
            # Step 1: Use Kyber to decapsulate the shared secret
            shared_secret = self.kem.decapsulate(private_key, kem_ciphertext)
            
            # Step 2: Derive AES key from shared secret using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key for AES
                salt=None,
                info=b'qss4-hybrid-encryption'
            )
            aes_key = hkdf.derive(shared_secret)
            
            # Step 3: Decrypt data with AES-GCM
            decrypted_stream = self.encryptor.decrypt_stream(encrypted_stream, aes_key, nonce)
            
            # Clear sensitive data
            shared_secret = b'\x00' * len(shared_secret)
            aes_key = b'\x00' * len(aes_key)
            
            return decrypted_stream
            
        except Exception as e:
            raise RuntimeError(f"Hybrid decryption failed: {e}")
