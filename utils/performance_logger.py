import csv
import os
import time
import psutil
from datetime import datetime
from typing import Dict, Any, Optional

class PerformanceLogger:
    def __init__(self, log_file_path: str = "performance_log.csv"):
        self.log_file_path = log_file_path
        self.start_time = None
        self.start_timestamp = None
        self._initialize_log_file()

    def _initialize_log_file(self):
        """Initializes the CSV log file with headers if it doesn't exist."""
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'w', newline='') as csvfile:
                self.csv_writer = csv.writer(csvfile)
                self.csv_writer.writerow([
                    'start_timestamp', 'end_timestamp', 'step', 'execution_time_ms', 
                    'cpu_percent', 'memory_usage_mb', 'file_size_kb', 
                    'original_file_size_bytes', 'compressed_file_size_bytes', 
                    'encrypted_file_size_bytes', 'encryption_overhead_bytes', 'compression_ratio', 'function_name'
                ])

    def start_timer(self):
        """Starts the timer for measuring execution time and records the start timestamp."""
        self.start_time = time.perf_counter()
        self.start_timestamp = datetime.now().isoformat()

    def stop_timer_and_log(self, step: str, file_size_bytes: Optional[int] = None, 
                           original_file_size_bytes: Optional[int] = None, 
                           compressed_file_size_bytes: Optional[int] = None, 
                           encrypted_file_size_bytes: Optional[int] = None,
                           function_name: Optional[str] = None,
                           encryption_overhead_bytes: Optional[int] = None,
                           extra_info: Optional[Dict[str, Any]] = None):
        """
        Stops the timer, collects performance metrics, and logs them to the CSV file.
        Args:
            step_name: Identifier for the current step (e.g., "validation", "compression").
            file_size_bytes: Size of the file after the current step, in bytes.
            original_file_size_bytes: Original size of the file before any transformations, in bytes.
            compressed_file_size_bytes: Size of the file after compression, in bytes.
            encrypted_file_size_bytes: Size of the file after encryption, in bytes.
            extra_info: Additional information to log.
        """
        if self.start_time is None or self.start_timestamp is None:
            raise RuntimeError("Timer was not started. Call start_timer() before stop_timer_and_log().")

        end_time = time.perf_counter()
        end_timestamp = datetime.now().isoformat()
        execution_time_ms = (end_time - self.start_time) * 1000

        cpu_percent = psutil.cpu_percent(interval=None)
        memory_info = psutil.virtual_memory()
        memory_usage_mb = memory_info.used / (1024 * 1024)

        file_size_kb = file_size_bytes / 1024 if file_size_bytes is not None else None
        
        compression_ratio = None
        if original_file_size_bytes is not None and compressed_file_size_bytes is not None and original_file_size_bytes > 0:
            compression_ratio = original_file_size_bytes / compressed_file_size_bytes

        log_entry = {
            "start_timestamp": self.start_timestamp,
            "end_timestamp": end_timestamp,
            "function_name": function_name,
            "step": step,
            "execution_time_ms": execution_time_ms,
            "cpu_percent": cpu_percent,
            "memory_usage_mb": memory_usage_mb,
            "file_size_kb": f"{file_size_kb:.2f}" if file_size_kb is not None else "",
            "original_file_size_bytes": original_file_size_bytes if original_file_size_bytes is not None else "",
            "compressed_file_size_bytes": compressed_file_size_bytes if compressed_file_size_bytes is not None else "",
            "encrypted_file_size_bytes": encrypted_file_size_bytes if encrypted_file_size_bytes is not None else "",
            "encryption_overhead_bytes": encryption_overhead_bytes if encryption_overhead_bytes is not None else "",
            "compression_ratio": f"{compression_ratio:.2f}" if compression_ratio is not None else ""
        }
        if extra_info:
            log_entry.update(extra_info)

        with open(self.log_file_path, 'a', newline='') as csvfile:
            fieldnames = log_entry.keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            # Only write header if the file is empty (newly created or truncated)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow(log_entry)

        self.start_time = None # Reset timer
        self.start_timestamp = None # Reset timestamp