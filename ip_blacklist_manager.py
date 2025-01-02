#!/usr/bin/env python3
import json
import os
import time
from datetime import datetime, timedelta
import logging
from typing import Set, Optional
import requests
from pathlib import Path

logger = logging.getLogger(__name__)

class IPBlacklistManager:
    def __init__(self, cache_dir: str = None):
        """Initialize the IP Blacklist Manager.
        
        Args:
            cache_dir: Directory to store the cache file. Defaults to ~/.cache/sysdaemon/
        """
        if cache_dir is None:
            cache_dir = os.path.expanduser("~/.cache/sysdaemon")
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.cache_file = self.cache_dir / "ip_blacklist_cache.json"
        self.blacklist: Set[str] = set()
        self.last_update: Optional[float] = None
        
        # API endpoints for malicious IP data
        self.api_endpoints = [
            "https://reputation.alienvault.com/reputation.generic",
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/malicious.txt"
        ]

    def _load_cache(self) -> None:
        """Load IP blacklist from cache file."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.blacklist = set(cache_data['ips'])
                    self.last_update = cache_data['last_update']
                    logger.info(f"Loaded {len(self.blacklist)} IPs from cache")
            else:
                logger.info("No cache file found")
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            self.blacklist = set()
            self.last_update = None

    def _save_cache(self) -> None:
        """Save current IP blacklist to cache file."""
        try:
            cache_data = {
                'ips': list(self.blacklist),
                'last_update': self.last_update
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
            logger.info(f"Saved {len(self.blacklist)} IPs to cache")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    def _fetch_malicious_ips(self) -> Set[str]:
        """Fetch malicious IPs from various sources."""
        all_ips = set()
        
        for endpoint in self.api_endpoints:
            try:
                response = requests.get(endpoint, timeout=10)
                if response.status_code == 200:
                    # Parse IPs from the response text
                    # This is a simple implementation; you might need to adjust
                    # the parsing logic based on the specific format of each source
                    ips = set(
                        ip.strip() 
                        for line in response.text.splitlines() 
                        if line.strip() and not line.startswith('#')
                        for ip in line.split()[0].split(',')
                        if self._is_valid_ip(ip.strip())
                    )
                    all_ips.update(ips)
                    logger.info(f"Fetched {len(ips)} IPs from {endpoint}")
            except Exception as e:
                logger.error(f"Error fetching from {endpoint}: {e}")
        
        return all_ips

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except (ValueError, TypeError):
            return False

    def needs_update(self) -> bool:
        """Check if the blacklist needs to be updated."""
        if self.last_update is None:
            return True
        
        last_update_time = datetime.fromtimestamp(self.last_update)
        next_update_time = last_update_time + timedelta(days=1)
        return datetime.now() >= next_update_time

    def update_if_needed(self) -> None:
        """Update the IP blacklist if necessary."""
        self._load_cache()
        
        if self.needs_update():
            logger.info("Updating IP blacklist...")
            new_ips = self._fetch_malicious_ips()
            
            if new_ips:
                self.blacklist = new_ips
                self.last_update = time.time()
                self._save_cache()
                logger.info(f"Updated blacklist with {len(new_ips)} IPs")
            else:
                logger.warning("No IPs fetched, keeping existing blacklist")

    def is_malicious(self, ip: str) -> bool:
        """Check if an IP is in the blacklist."""
        return ip in self.blacklist

    def get_blacklist(self) -> Set[str]:
        """Get the current set of blacklisted IPs."""
        return self.blacklist.copy()

    def add_custom_ip(self, ip: str) -> None:
        """Add a custom IP to the blacklist."""
        if self._is_valid_ip(ip):
            self.blacklist.add(ip)
            self._save_cache()
            logger.info(f"Added custom IP to blacklist: {ip}")
        else:
            raise ValueError(f"Invalid IP address format: {ip}")

    def remove_custom_ip(self, ip: str) -> None:
        """Remove a custom IP from the blacklist."""
        if ip in self.blacklist:
            self.blacklist.remove(ip)
            self._save_cache()
            logger.info(f"Removed IP from blacklist: {ip}")
