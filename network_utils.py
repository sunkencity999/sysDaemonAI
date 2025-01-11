#!/usr/bin/env python3
import requests
from requests.adapters import HTTPAdapter, Retry
from cachetools import TTLCache
import gzip
import json
import logging
from typing import Optional, Dict, Any, Union
from functools import wraps
import pickle
import hashlib
from datetime import datetime, timedelta

class NetworkManager:
    def __init__(self, pool_connections=100, pool_maxsize=100, max_retries=3, 
                 cache_ttl=300, cache_maxsize=1000, verify_ssl=True):
        self.logger = logging.getLogger(__name__)
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = self._create_session(pool_connections, pool_maxsize, max_retries)
        self.cache = TTLCache(maxsize=cache_maxsize, ttl=cache_ttl)
        
    def _create_session(self, pool_connections: int, pool_maxsize: int, 
                       max_retries: int) -> requests.Session:
        """Create a session with connection pooling and retry strategy."""
        session = requests.Session()
        session.verify = self.verify_ssl
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        
        # Configure connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _generate_cache_key(self, url: str, params: Optional[Dict] = None, 
                          data: Optional[Dict] = None) -> str:
        """Generate a unique cache key based on request parameters."""
        key_parts = [url]
        if params:
            key_parts.append(json.dumps(params, sort_keys=True))
        if data:
            key_parts.append(json.dumps(data, sort_keys=True))
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _compress_data(self, data: Union[str, bytes, Dict]) -> bytes:
        """Compress data using gzip."""
        if isinstance(data, dict):
            data = json.dumps(data)
        if isinstance(data, str):
            data = data.encode()
        return gzip.compress(data)
    
    def _decompress_data(self, data: bytes) -> Union[str, Dict]:
        """Decompress gzipped data."""
        decompressed = gzip.decompress(data)
        try:
            return json.loads(decompressed)
        except json.JSONDecodeError:
            return decompressed.decode()
    
    def request(self, method: str, url: str, params: Optional[Dict] = None, 
                data: Optional[Dict] = None, compress: bool = True, 
                use_cache: bool = True, **kwargs) -> requests.Response:
        """
        Make an HTTP request with caching and compression support.
        """
        cache_key = self._generate_cache_key(url, params, data)
        
        # Try to get from cache if caching is enabled
        if use_cache:
            cached_response = self.cache.get(cache_key)
            if cached_response is not None:
                self.logger.debug(f"Cache hit for {url}")
                return pickle.loads(cached_response)
        
        # Compress request data if enabled
        if compress and data:
            compressed_data = self._compress_data(data)
            kwargs['headers'] = kwargs.get('headers', {})
            kwargs['headers'].update({
                'Content-Encoding': 'gzip',
                'Accept-Encoding': 'gzip'
            })
            kwargs['data'] = compressed_data
        else:
            kwargs['json'] = data
        
        # Make the request
        response = self.session.request(method, url, params=params, **kwargs)
        
        # Cache the response if caching is enabled
        if use_cache:
            self.cache[cache_key] = pickle.dumps(response)
        
        return response

class OllamaCache:
    def __init__(self, ttl: int = 3600, maxsize: int = 1000):
        self.cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self.logger = logging.getLogger(__name__)
    
    def _generate_cache_key(self, model: str, prompt: str, 
                           system: Optional[str] = None) -> str:
        """Generate a unique cache key for Ollama requests."""
        key_parts = [model, prompt]
        if system:
            key_parts.append(system)
        key_string = '|'.join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get_cached_response(self, model: str, prompt: str, 
                          system: Optional[str] = None) -> Optional[str]:
        """Get a cached response if available."""
        cache_key = self._generate_cache_key(model, prompt, system)
        return self.cache.get(cache_key)
    
    def cache_response(self, model: str, prompt: str, response: str,
                      system: Optional[str] = None):
        """Cache an Ollama response."""
        cache_key = self._generate_cache_key(model, prompt, system)
        self.cache[cache_key] = response
        self.logger.debug(f"Cached Ollama response for key: {cache_key}")

def batch_processor(batch_size: int = 100, timeout: int = 60):
    """
    Decorator for batch processing network monitoring data.
    
    Args:
        batch_size: Maximum number of items to process in a batch
        timeout: Maximum time (in seconds) to wait before processing an incomplete batch
    """
    def decorator(func):
        batch = []
        last_process_time = datetime.now()
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            nonlocal batch, last_process_time
            
            # Add item to batch
            item = kwargs.get('data') or args[-1]
            batch.append(item)
            
            # Process batch if it's full or timeout has been reached
            if (len(batch) >= batch_size or 
                datetime.now() - last_process_time > timedelta(seconds=timeout)):
                result = func(*args, batch=batch, **kwargs)
                batch = []
                last_process_time = datetime.now()
                return result
            return None
            
        return wrapper
    return decorator
