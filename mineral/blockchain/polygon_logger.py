import os
import json
from typing import Dict, Any, Optional
from web3 import Web3
from eth_account import Account
from .base import BaseBlockchainLogger
import time

class PolygonBlockchainLogger(BaseBlockchainLogger):
    """Polygon blockchain logger for tamper-proof audit trails"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.network_name = "polygon"
        
        # Configuration
        self.rpc_url = self.config.get("rpc_url", "https://polygon-rpc.com")
        self.private_key = self.config.get("private_key")
        self.contract_address = self.config.get("contract_address")
        
        # Initialize Web3
        self.w3 = None
        self.account = None
        self.contract = None
        
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Web3 connection and contract"""
        try:
            if not self.private_key:
                print("Warning: No Polygon private key configured. Blockchain logging disabled.")
                self.enabled = False
                return
            
            # Initialize Web3
            self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
            
            if not self.w3.is_connected():
                print("Warning: Cannot connect to Polygon network. Blockchain logging disabled.")
                self.enabled = False
                return
            
            # Initialize account
            self.account = Account.from_key(self.private_key)
            
            # Initialize contract if address is provided
            if self.contract_address:
                self._initialize_contract()
            
            print(f"Polygon blockchain logger initialized. Address: {self.account.address}")
            
        except Exception as e:
            print(f"Failed to initialize Polygon connection: {e}")
            self.enabled = False
    
    def _initialize_contract(self):
        """Initialize smart contract for structured logging"""
        try:
            # Simple audit contract ABI
            audit_contract_abi = [
                {
                    "inputs": [
                        {"name": "_eventType", "type": "string"},
                        {"name": "_dataHash", "type": "string"},
                        {"name": "_metadata", "type": "string"}
                    ],
                    "name": "logEvent",
                    "outputs": [],
                    "stateMutability": "nonpayable",
                    "type": "function"
                },
                {
                    "inputs": [{"name": "", "type": "uint256"}],
                    "name": "events",
                    "outputs": [
                        {"name": "eventType", "type": "string"},
                        {"name": "dataHash", "type": "string"},
                        {"name": "metadata", "type": "string"},
                        {"name": "timestamp", "type": "uint256"},
                        {"name": "sender", "type": "address"}
                    ],
                    "stateMutability": "view",
                    "type": "function"
                }
            ]
            
            self.contract = self.w3.eth.contract(
                address=self.contract_address,
                abi=audit_contract_abi
            )
            
        except Exception as e:
            print(f"Failed to initialize contract: {e}")
            self.contract = None
    
    def log_event(self, event_type: str, data: Dict[str, Any]) -> Optional[str]:
        """
        Log event to Polygon blockchain
        
        Args:
            event_type: Type of event
            data: Event data to log
        
        Returns:
            Transaction hash if successful, None otherwise
        """
        if not self.enabled or not self.w3 or not self.account:
            print("Polygon logging not available")
            return None
        
        try:
            # Prepare audit data
            audit_data = self.prepare_audit_data(
                event_type=event_type,
                user_id=data.get("user_id", ""),
                file_id=data.get("file_id", ""),
                additional_data=data
            )
            
            data_hash = audit_data["data_hash"]
            metadata = json.dumps(audit_data, separators=(',', ':'))
            
            if self.contract:
                # Use smart contract
                return self._log_to_contract(event_type, data_hash, metadata)
            else:
                # Use simple transaction with data
                return self._log_to_transaction(metadata)
                
        except Exception as e:
            print(f"Polygon event logging failed: {e}")
            return None
    
    def _log_to_contract(self, event_type: str, data_hash: str, metadata: str) -> Optional[str]:
        """Log event using smart contract"""
        try:
            # Build transaction
            function = self.contract.functions.logEvent(event_type, data_hash, metadata)
            
            # Estimate gas
            gas_estimate = function.estimate_gas({'from': self.account.address})
            
            # Build transaction
            transaction = function.build_transaction({
                'from': self.account.address,
                'gas': gas_estimate + 10000,  # Add buffer
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address)
            })
            
            # Sign and send transaction
            signed_txn = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            # Wait for confirmation (optional, for immediate feedback)
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            
            return receipt.transactionHash.hex()
            
        except Exception as e:
            print(f"Contract logging failed: {e}")
            return None
    
    def _log_to_transaction(self, metadata: str) -> Optional[str]:
        """Log event using simple transaction with data"""
        try:
            # Encode metadata as transaction data
            data = metadata.encode('utf-8').hex()
            
            # Build transaction
            transaction = {
                'to': self.account.address,  # Send to self
                'value': 0,  # No value transfer
                'gas': 21000 + len(data) * 16,  # Base gas + data gas
                'gasPrice': self.w3.eth.gas_price,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'data': '0x' + data
            }
            
            # Sign and send transaction
            signed_txn = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
            
            return tx_hash.hex()
            
        except Exception as e:
            print(f"Transaction logging failed: {e}")
            return None
    
    def verify_event(self, transaction_id: str) -> Optional[Dict[str, Any]]:
        """
        Verify event exists on Polygon blockchain
        
        Args:
            transaction_id: Transaction hash
        
        Returns:
            Event data if found, None otherwise
        """
        if not self.enabled or not self.w3:
            return None
        
        try:
            # Get transaction receipt
            receipt = self.w3.eth.get_transaction_receipt(transaction_id)
            if not receipt:
                return None
            
            # Get transaction details
            transaction = self.w3.eth.get_transaction(transaction_id)
            
            # Extract metadata from transaction data
            if transaction.input and len(transaction.input) > 2:
                try:
                    # Decode hex data
                    data_hex = transaction.input[2:]  # Remove '0x' prefix
                    data_bytes = bytes.fromhex(data_hex)
                    metadata_str = data_bytes.decode('utf-8')
                    metadata = json.loads(metadata_str)
                    
                    return {
                        "transaction_hash": transaction_id,
                        "block_number": receipt.blockNumber,
                        "block_hash": receipt.blockHash.hex(),
                        "status": receipt.status,
                        "gas_used": receipt.gasUsed,
                        "metadata": metadata,
                        "verified": True
                    }
                    
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            
            # Return basic transaction info if metadata cannot be decoded
            return {
                "transaction_hash": transaction_id,
                "block_number": receipt.blockNumber,
                "block_hash": receipt.blockHash.hex(),
                "status": receipt.status,
                "gas_used": receipt.gasUsed,
                "verified": True
            }
            
        except Exception as e:
            print(f"Event verification failed: {e}")
            return None
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get Polygon network status"""
        if not self.w3:
            return {
                "network": self.network_name,
                "status": "disconnected",
                "error": "Web3 not initialized"
            }
        
        try:
            latest_block = self.w3.eth.get_block('latest')
            balance = self.w3.eth.get_balance(self.account.address) if self.account else 0
            
            return {
                "network": self.network_name,
                "status": "connected",
                "chain_id": self.w3.eth.chain_id,
                "latest_block": latest_block.number,
                "gas_price": self.w3.eth.gas_price,
                "account_address": self.account.address if self.account else None,
                "account_balance_wei": balance,
                "account_balance_matic": self.w3.from_wei(balance, 'ether'),
                "contract_address": self.contract_address
            }
            
        except Exception as e:
            return {
                "network": self.network_name,
                "status": "error",
                "error": str(e)
            }
    
    def get_gas_estimate(self, event_type: str, data_size: int) -> Dict[str, Any]:
        """
        Estimate gas cost for logging an event
        
        Args:
            event_type: Type of event
            data_size: Size of data in bytes
        
        Returns:
            Gas estimate information
        """
        if not self.w3:
            return {"error": "Web3 not initialized"}
        
        try:
            base_gas = 21000
            data_gas = data_size * 16  # Approximate gas cost per byte
            total_gas = base_gas + data_gas
            
            gas_price = self.w3.eth.gas_price
            cost_wei = total_gas * gas_price
            cost_matic = self.w3.from_wei(cost_wei, 'ether')
            
            return {
                "estimated_gas": total_gas,
                "gas_price_wei": gas_price,
                "estimated_cost_wei": cost_wei,
                "estimated_cost_matic": float(cost_matic),
                "data_size_bytes": data_size
            }
            
        except Exception as e:
            return {"error": str(e)}
