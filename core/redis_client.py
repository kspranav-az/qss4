import redis
import json
import os
from typing import Optional, Any, Union
from core.config import settings

class RedisClient:
    """Singleton Redis client for caching and token management"""
    
    _instance = None
    _client = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            self._client = redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
    
    @property
    def client(self):
        return self._client
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a key-value pair with optional TTL"""
        try:
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            
            if ttl:
                return self._client.setex(key, ttl, value)
            else:
                return self._client.set(key, value)
        except Exception as e:
            print(f"Redis SET error: {e}")
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """Get value by key"""
        try:
            value = self._client.get(key)
            if value is None:
                return None
            
            # Try to parse as JSON
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return value
        except Exception as e:
            print(f"Redis GET error: {e}")
            return None
    
    def delete(self, key: str) -> bool:
        """Delete a key"""
        try:
            return bool(self._client.delete(key))
        except Exception as e:
            print(f"Redis DELETE error: {e}")
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists"""
        try:
            return bool(self._client.exists(key))
        except Exception as e:
            print(f"Redis EXISTS error: {e}")
            return False
    
    def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment a key's value"""
        try:
            return self._client.incr(key, amount)
        except Exception as e:
            print(f"Redis INCR error: {e}")
            return None
    
    def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key"""
        try:
            return bool(self._client.expire(key, ttl))
        except Exception as e:
            print(f"Redis EXPIRE error: {e}")
            return False
    
    def ping(self) -> bool:
        """Check Redis connection"""
        try:
            return self._client.ping()
        except Exception as e:
            print(f"Redis PING error: {e}")
            return False
    
    def flushdb(self) -> bool:
        """Flush current database (use with caution)"""
        try:
            return self._client.flushdb()
        except Exception as e:
            print(f"Redis FLUSHDB error: {e}")
            return False

# Global Redis client instance
redis_client = RedisClient()
