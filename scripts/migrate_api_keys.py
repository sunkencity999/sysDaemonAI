#!/usr/bin/env python3
"""
Migration script to move API keys from config.py to secure storage.
This script should be run once to migrate existing API keys to the new secure storage system.
"""

import os
import sys
import re
from pathlib import Path

# Add parent directory to path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

from api_key_manager import APIKeyManager

def extract_api_key_from_config():
    """Extract the API key from the old config file."""
    config_path = Path(__file__).parent.parent / 'config.py'
    if not config_path.exists():
        print("Config file not found!")
        return None
    
    with open(config_path, 'r') as f:
        content = f.read()
    
    # Look for the API key in the ABUSEIPDB_CONFIG
    match = re.search(r"'api_key':\s*'([^']+)'", content)
    if match:
        return match.group(1)
    return None

def main():
    print("Starting API key migration...")
    
    # Initialize API key manager
    key_manager = APIKeyManager()
    
    # Try to get key from environment variable first
    env_key = os.environ.get('SYSDAEMON_ABUSEIPDB_API_KEY')
    if env_key:
        print("Found API key in environment variable, storing in secure storage...")
        key_manager.store_key('ABUSEIPDB_API_KEY', env_key)
        print("Migration completed successfully!")
        return
    
    # Try to extract key from config file
    config_key = extract_api_key_from_config()
    if config_key:
        print("Found API key in config.py, storing in secure storage...")
        key_manager.store_key('ABUSEIPDB_API_KEY', config_key)
        print("Migration completed successfully!")
        print("\nIMPORTANT: The API key has been moved to secure storage.")
        print("You should now remove the hardcoded API key from config.py")
        print("The config.py file has already been updated to use the secure storage.")
        return
    
    print("No API key found to migrate!")
    print("Please set your API key using one of these methods:")
    print("1. Set environment variable: SYSDAEMON_ABUSEIPDB_API_KEY")
    print("2. Run: python3 -c 'from api_key_manager import APIKeyManager; APIKeyManager().store_key(\"ABUSEIPDB_API_KEY\", \"your-api-key-here\")'")

if __name__ == "__main__":
    main()
