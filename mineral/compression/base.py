from abc import ABC, abstractmethod
from typing import BinaryIO, Dict, Any
import io

class BaseCompressor(ABC):
    """Abstract base class for compression algorithms"""
    
    def __init__(self, level: int = 3):
        self.level = level
        self.algorithm_name = ""
    
    @abstractmethod
    def compress_stream(self, input_stream: BinaryIO) -> BinaryIO:
        """Compress data from input stream and return compressed stream"""
        pass
    
    @abstractmethod
    def decompress_stream(self, compressed_stream: BinaryIO) -> BinaryIO:
        """Decompress data from compressed stream and return decompressed stream"""
        pass
    
    @abstractmethod
    def compress_bytes(self, data: bytes) -> bytes:
        """Compress bytes directly"""
        pass
    
    @abstractmethod
    def decompress_bytes(self, compressed_data: bytes) -> bytes:
        """Decompress bytes directly"""
        pass
    
    def get_metadata(self) -> Dict[str, Any]:
        """Get compressor metadata"""
        return {
            "algorithm": self.algorithm_name,
            "level": self.level
        }
    
    def estimate_compression_ratio(self, original_size: int, compressed_size: int) -> float:
        """Calculate compression ratio"""
        if original_size == 0:
            return 0.0
        return compressed_size / original_size

class NullCompressor(BaseCompressor):
    """No-op compressor that passes data through unchanged"""
    
    def __init__(self):
        super().__init__(level=0)
        self.algorithm_name = "none"
    
    def compress_stream(self, input_stream: BinaryIO) -> BinaryIO:
        """Return input stream unchanged"""
        return input_stream
    
    def decompress_stream(self, compressed_stream: BinaryIO) -> BinaryIO:
        """Return compressed stream unchanged"""
        return compressed_stream
    
    def compress_bytes(self, data: bytes) -> bytes:
        """Return data unchanged"""
        return data
    
    def decompress_bytes(self, compressed_data: bytes) -> bytes:
        """Return data unchanged"""
        return compressed_data
