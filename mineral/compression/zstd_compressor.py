import zstandard as zstd
import io
from typing import BinaryIO
from .base import BaseCompressor

class ZstdCompressor(BaseCompressor):
    """Zstandard compression implementation with streaming support"""
    
    def __init__(self, level: int = 3):
        super().__init__(level)
        self.algorithm_name = "zstd"
        self.compressor = zstd.ZstdCompressor(level=level)
        self.decompressor = zstd.ZstdDecompressor()
    
# In zstd_compressor.py

    def compress_stream(self, input_stream: BinaryIO) -> BinaryIO:
        """
        Compress data from input stream using streaming.
        
        Args:
            input_stream: BinaryIO stream to compress
            
        Returns:
            BinaryIO: Compressed data as a file-like object
            
        Raises:
            RuntimeError: If compression fails
        """
        try:
            # Reset input stream position if seekable
            if hasattr(input_stream, 'seekable') and input_stream.seekable() and input_stream.tell() > 0:
                input_stream.seek(0)
            
            # Read all data from input stream
            input_data = input_stream.read()
            
            # Compress the data directly
            compressor = zstd.ZstdCompressor(level=self.level)
            compressed_bytes = compressor.compress(input_data)
            
            # Create a new BytesIO object with compressed data
            compressed_data = io.BytesIO(compressed_bytes)
            
            return compressed_data
            
        except Exception as e:
            raise RuntimeError(f"Zstd compression failed: {e}")

    def decompress_stream(self, compressed_stream: BinaryIO) -> BinaryIO:
        """Decompress data from compressed stream using streaming"""
        try:
            # Create output buffer
            output_buffer = io.BytesIO()
            
            # Reset compressed stream position
            compressed_stream.seek(0)
            
            # Use streaming decompressor
            with self.decompressor.stream_reader(compressed_stream) as reader:
                while True:
                    chunk = reader.read(8192)  # 8KB chunks
                    if not chunk:
                        break
                    output_buffer.write(chunk)
            
            # Reset output buffer position
            output_buffer.seek(0)
            return output_buffer
            
        except Exception as e:
            raise RuntimeError(f"Zstd decompression failed: {e}")
    
    def compress_bytes(self, data: bytes) -> bytes:
        """Compress bytes directly"""
        try:
            return self.compressor.compress(data)
        except Exception as e:
            raise RuntimeError(f"Zstd byte compression failed: {e}")
    
    def decompress_bytes(self, compressed_data: bytes) -> bytes:
        """Decompress bytes directly"""
        try:
            return self.decompressor.decompress(compressed_data)
        except Exception as e:
            raise RuntimeError(f"Zstd byte decompression failed: {e}")
    
    def get_compression_stats(self, original_data: bytes) -> dict:
        """Get detailed compression statistics"""
        compressed_data = self.compress_bytes(original_data)
        
        return {
            "original_size": len(original_data),
            "compressed_size": len(compressed_data),
            "compression_ratio": self.estimate_compression_ratio(
                len(original_data), len(compressed_data)
            ),
            "space_saved_percent": (
                (len(original_data) - len(compressed_data)) / len(original_data) * 100
                if len(original_data) > 0 else 0
            ),
            "algorithm": self.algorithm_name,
            "level": self.level
        }