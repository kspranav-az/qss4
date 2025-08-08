from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import hashlib
import json
from datetime import datetime

class BaseBlockchainLogger(ABC):
    """Abstract base class for blockchain audit logging"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.network_name = ""
        self.enabled = True
    
    @abstractmethod
    def log_event(self, event_type: str, data: Dict[str, Any]) -> Optional[str]:
        """
        Log an event to the blockchain
        
        Args:
            event_type: Type of event (upload, download, delete, etc.)
            data: Event data to log
        
        Returns:
            Transaction ID if successful, None otherwise
        """
        pass
    
    @abstractmethod
    def verify_event(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """
        Verify an event exists on the blockchain
        
        Args:
            transaction_id: Transaction ID to verify
        
        Returns:
            Event data if found, None otherwise
        """
        pass
    
    @abstractmethod
    def get_network_status(self) -> Dict[str, Any]:
        """
        Get blockchain network status
        
        Returns:
            Network status information
        """
        pass
    
    def create_audit_hash(self, data: Dict[str, Any]) -> str:
        """
        Create a deterministic hash for audit data
        
        Args:
            data: Data to hash
        
        Returns:
            SHA3-512 hash of the data
        """
        # Sort data for deterministic hashing
        sorted_data = json.dumps(data, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_512(sorted_data.encode()).hexdigest()
    
    def prepare_audit_data(self, event_type: str, user_id: str, 
                          file_id: str, additional_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Prepare standardized audit data
        
        Args:
            event_type: Type of event
            user_id: User ID associated with event
            file_id: File ID associated with event
            additional_data: Additional event-specific data
        
        Returns:
            Standardized audit data dictionary
        """
        audit_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "file_id": file_id,
            "network": self.network_name
        }
        
        if additional_data:
            audit_data.update(additional_data)
        
        # Add hash of the data
        audit_data["data_hash"] = self.create_audit_hash(audit_data)
        
        return audit_data
    
    def is_enabled(self) -> bool:
        """Check if blockchain logging is enabled"""
        return self.enabled

class MockBlockchainLogger(BaseBlockchainLogger):
    """Mock blockchain logger for development and testing"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.network_name = "mock"
        self.events = {}  # In-memory storage for mock events
    
    def log_event(self, event_type: str, data: Dict[str, Any]) -> Optional[str]:
        """Mock event logging"""
        try:
            # Generate mock transaction ID
            import uuid
            tx_id = f"mock_tx_{uuid.uuid4().hex[:16]}"
            
            # Store event data
            self.events[tx_id] = {
                "event_type": event_type,
                "data": data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            print(f"Mock blockchain log: {event_type} -> {tx_id}")
            return tx_id
            
        except Exception as e:
            print(f"Mock blockchain logging failed: {e}")
            return None
    
    def verify_event(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """Mock event verification"""
        return self.events.get(transaction_id)
    
    def get_network_status(self) -> Dict[str, Any]:
        """Mock network status"""
        return {
            "network": self.network_name,
            "status": "connected",
            "block_height": 12345,
            "events_logged": len(self.events)
        }
