import time
from typing import Optional
from flask import request, jsonify, current_app
from functools import wraps
from core.redis_client import redis_client
from core.config import settings

class RateLimiter:
    """Rate limiting using Redis sliding window"""
    
    def __init__(self, redis_client):
        self.redis = redis_client
        self.enabled = settings.rate_limit_enabled
    
    def is_allowed(self, key: str, limit: int, window: int = 60) -> tuple[bool, dict]:
        """
        Check if request is allowed based on rate limit
        Returns (allowed, info_dict)
        """
        if not self.enabled:
            return True, {"remaining": limit, "reset_at": 0}
        
        try:
            current_time = int(time.time())
            window_start = current_time - window
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis.client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, window_start)
            
            # Count current entries
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time): current_time})
            
            # Set expiry
            pipe.expire(key, window)
            
            results = pipe.execute()
            current_count = results[1]  # Count after cleanup
            
            remaining = max(0, limit - current_count - 1)
            reset_at = current_time + window
            
            if current_count >= limit:
                return False, {
                    "remaining": 0,
                    "reset_at": reset_at,
                    "retry_after": window
                }
            
            return True, {
                "remaining": remaining,
                "reset_at": reset_at
            }
            
        except Exception as e:
            current_app.logger.error(f"Rate limiting error: {e}")
            # Fail open - allow request if Redis is down
            return True, {"remaining": limit, "reset_at": 0}
    
    def get_client_key(self, prefix: str = "rate_limit") -> str:
        """Generate rate limit key for client"""
        # Use IP address as identifier
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR') or request.remote_addr
        return f"{prefix}:{client_ip}"

def rate_limit(limit: int = None, window: int = 60, per_user: bool = False):
    """
    Rate limiting decorator
    
    Args:
        limit: Number of requests allowed per window (default from settings)
        window: Time window in seconds (default 60)
        per_user: Use user ID instead of IP for rate limiting
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not settings.rate_limit_enabled:
                return f(*args, **kwargs)
            
            limiter = RateLimiter(redis_client)
            request_limit = limit or settings.rate_limit_per_minute
            
            if per_user:
                # Rate limit per authenticated user
                from flask_jwt_extended import get_jwt_identity
                try:
                    user_id = get_jwt_identity()
                    if user_id:
                        key = f"rate_limit:user:{user_id}"
                    else:
                        key = limiter.get_client_key()
                except:
                    key = limiter.get_client_key()
            else:
                # Rate limit per IP
                key = limiter.get_client_key()
            
            allowed, info = limiter.is_allowed(key, request_limit, window)
            
            if not allowed:
                response = jsonify({
                    "error": "Rate limit exceeded",
                    "retry_after": info.get("retry_after", window)
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(info.get("retry_after", window))
                return response
            
            # Add rate limit headers to response
            response = f(*args, **kwargs)
            if hasattr(response, 'headers'):
                response.headers["X-RateLimit-Limit"] = str(request_limit)
                response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", 0))
                response.headers["X-RateLimit-Reset"] = str(info.get("reset_at", 0))
            
            return response
        
        return decorated_function
    return decorator

# Global rate limiter instance
rate_limiter = RateLimiter(redis_client)
