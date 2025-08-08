from abc import ABC, abstractmethod
from typing import BinaryIO, Tuple, Dict, Any
import io

class BaseEncryptor(ABC):
    """Abstract base class for encryption algorithms"""
    
    def __init__(self):
        self.algorithm_name = ""
    
    @abstractmethod
    def encrypt_stream(self, input_stream: BinaryIO, key: bytes) -> Tuple[BinaryIO, bytes]:
        """
        Encrypt data from input stream
        Returns (encrypted_stream, metadata)
        """
        pass
    
    @abstractmethod
    def decrypt_stream(self, encrypted_stream: BinaryIO, key: bytes, metadata: bytes) -> BinaryIO:
        """
        Decrypt data from encrypted stream using key and metadata
        Returns decrypted stream
        """
        pass
    
    @abstractmethod
    def generate_key(self) -> bytes:
        """Generate a new encryption key"""
        pass
    
    @abstractmethod
    def get_key_size(self) -> int:
        """Get the required key size in bytes"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get encryptor metadata"""
        return {
            "algorithm": self.algorithm_name,
            "key_size": self.get_key_size()
        }

class BaseKEM(ABC):
    """Abstract base class for Key Encapsulation Mechanisms"""
    
    def __init__(self):
        self.algorithm_name = ""
    
    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new keypair
        Returns (public_key, private_key)
        """
        pass
    
    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using public key
        Returns (shared_secret, ciphertext)
        """
        pass
    
    @abstractmethod
    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate shared secret using private key and ciphertext
        Returns shared_secret
        """
        pass
    
    @abstractmethod
    def get_public_key_size(self) -> int:
        """Get public key size in bytes"""
        pass
    
    @abstractmethod
    def get_private_key_size(self) -> int:
        """Get private key size in bytes"""
        pass
    
    @abstractmethod
    def get_ciphertext_size(self) -> int:
        """Get ciphertext size in bytes"""
        pass

class HybridEncryptor(ABC):
    """Abstract base class for hybrid encryption (KEM + AEAD)"""
    
    def __init__(self, kem: BaseKEM, encryptor: BaseEncryptor):
        self.kem = kem
        self.encryptor = encryptor
        self.algorithm_name = f"{kem.algorithm_name}+{encryptor.algorithm_name}"
    
    @abstractmethod
    def encrypt_with_public_key(self, input_stream: BinaryIO, public_key: bytes) -> Tuple[BinaryIO, bytes]:
        """
        Encrypt using hybrid scheme with public key
        Returns (encrypted_stream, kem_ciphertext)
        """
        pass
    
    @abstractmethod
    def decrypt_with_private_key(self, encrypted_stream: BinaryIO, private_key: bytes, kem_ciphertext: bytes) -> BinaryIO:
        """
        Decrypt using hybrid scheme with private key
        Returns decrypted_stream
        """
        pass
