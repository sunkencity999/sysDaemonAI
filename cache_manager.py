"""Cache management module for the system daemon AI."""

import json
import time
from typing import Any, Optional, Dict, Union
from functools import lru_cache
from collections import OrderedDict
import threading
import asyncio
from datetime import datetime, timedelta

class LRUCache:
    """Thread-safe LRU cache implementation."""
    
    def __init__(self, capacity: int = 1000):
        self.cache = OrderedDict()
        self.capacity = capacity
        self._lock = threading.Lock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        with self._lock:
            if key not in self.cache:
                return None
            value, expiry = self.cache.pop(key)
            if expiry and time.time() > expiry:
                del self.cache[key]
                return None
            self.cache[key] = (value, expiry)  # Move to end (most recently used)
            return value
            
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Put item in cache with optional TTL in seconds."""
        with self._lock:
            if key in self.cache:
                self.cache.pop(key)
            elif len(self.cache) >= self.capacity:
                self.cache.popitem(last=False)  # Remove least recently used
            expiry = time.time() + ttl if ttl else None
            self.cache[key] = (value, expiry)

class CacheManager:
    """Manages different caching strategies for the system."""
    
    def __init__(self):
        self.threat_cache = LRUCache(capacity=1000)  # Cache for threat detection results
        self.api_cache = LRUCache(capacity=500)      # Cache for API responses
        self.network_cache = LRUCache(capacity=200)  # Cache for network analysis results
        
    @lru_cache(maxsize=128)
    def get_cached_config(self, config_name: str) -> Optional[Dict]:
        """Get cached configuration using Python's built-in LRU cache."""
        return self.api_cache.get(f"config:{config_name}")
        
    def cache_threat_result(self, ip: str, result: Dict[str, Any], ttl: int = 3600) -> None:
        """Cache threat detection results for an IP."""
        self.threat_cache.put(ip, result, ttl)
        
    def get_threat_result(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached threat detection result for an IP."""
        return self.threat_cache.get(ip)
        
    def cache_api_response(self, endpoint: str, params: str, response: Any, ttl: int = 300) -> None:
        """Cache API response with a default TTL of 5 minutes."""
        cache_key = f"{endpoint}:{params}"
        self.api_cache.put(cache_key, response, ttl)
        
    def get_api_response(self, endpoint: str, params: str) -> Optional[Any]:
        """Get cached API response."""
        cache_key = f"{endpoint}:{params}"
        return self.api_cache.get(cache_key)
        
    def cache_network_analysis(self, analysis_key: str, result: Dict[str, Any], ttl: int = 1800) -> None:
        """Cache network analysis results with a default TTL of 30 minutes."""
        self.network_cache.put(analysis_key, result, ttl)
        
    def get_network_analysis(self, analysis_key: str) -> Optional[Dict[str, Any]]:
        """Get cached network analysis result."""
        return self.network_cache.get(analysis_key)

# Decorator for caching function results
def cached_result(cache: LRUCache, ttl: Optional[int] = None):
    """Decorator to cache function results."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Create a cache key from function name and arguments
            key = f"{func.__name__}:{str(args)}:{str(kwargs)}"
            result = cache.get(key)
            if result is None:
                result = func(*args, **kwargs)
                cache.put(key, result, ttl)
            return result
        return wrapper
    return decorator
