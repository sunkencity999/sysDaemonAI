#!/usr/bin/env python3
import json
import os
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

class APICache:
    def __init__(self, cache_dir: str = None):
        if cache_dir is None:
            cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'cache')
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize cache files
        self.ip_cache_file = os.path.join(cache_dir, 'ip_threat_cache.json')
        self._load_cache()

    def _load_cache(self):
        """Load cache from disk"""
        try:
            if os.path.exists(self.ip_cache_file):
                with open(self.ip_cache_file, 'r') as f:
                    self.ip_cache = json.load(f)
            else:
                self.ip_cache = {}
        except (json.JSONDecodeError, IOError):
            self.ip_cache = {}

    def _save_cache(self):
        """Save cache to disk"""
        try:
            with open(self.ip_cache_file, 'w') as f:
                json.dump(self.ip_cache, f, indent=4)
        except IOError as e:
            print(f"Error saving cache: {e}")

    def get_ip_data(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get IP data from cache if available and not expired"""
        if ip in self.ip_cache:
            cache_entry = self.ip_cache[ip]
            # Check if cache entry is still valid (24 hours)
            if datetime.fromisoformat(cache_entry['timestamp']) > datetime.now() - timedelta(hours=24):
                return cache_entry['data']
        return None

    def cache_ip_data(self, ip: str, data: Dict[str, Any]):
        """Cache IP data with timestamp"""
        self.ip_cache[ip] = {
            'timestamp': datetime.now().isoformat(),
            'data': data
        }
        self._save_cache()

    def get_cached_ips(self) -> Dict[str, Any]:
        """Get all cached IP data that is still valid"""
        valid_cache = {}
        current_time = datetime.now()
        for ip, entry in self.ip_cache.items():
            if datetime.fromisoformat(entry['timestamp']) > current_time - timedelta(hours=24):
                valid_cache[ip] = entry['data']
        return valid_cache

    def cleanup_expired(self):
        """Remove expired entries from cache"""
        current_time = datetime.now()
        self.ip_cache = {
            ip: entry for ip, entry in self.ip_cache.items()
            if datetime.fromisoformat(entry['timestamp']) > current_time - timedelta(hours=24)
        }
        self._save_cache()
