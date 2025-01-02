"""Configuration settings for the system daemon AI."""

import os

# API Configuration
OLLAMA_CONFIG = {
    'base_url': 'http://localhost:11434',
    'generate_endpoint': '/api/generate',
    'health_endpoint': '/api/version',
    'model': 'llama3.2:latest',  # Using llama3.2 for superior performance and analysis
    'timeout': 40,  # Reduced timeout since smaller model is faster
    'retries': 5,
    'retry_delay': 3,  # Reduced delay since model is faster
    'backoff_factor': 2,
    'cache_ttl': 300,  # 5 minutes
    'cache_maxsize': 1000,
    'temperature': 0.7,
    'max_tokens': 4000,  # Reduced token limit since we don't need vision model's capacity
}

# AbuseIPDB Configuration
ABUSEIPDB_CONFIG = {
    'api_key': 'd823ef94bd0ab629c2ebbd7ba44dc7a8ad7774a040fd7e3239ef9d03f97fc3a2f00fd3434022b58e',
    'base_url': 'https://api.abuseipdb.com/api/v2',
    'confidence_score': 90,
    'timeout': 10,  # seconds
    'max_retries': 3,
    'retry_delay': 1,  # seconds
}

# Performance Monitoring
PERFORMANCE_CONFIG = {
    'monitored_hosts': ['8.8.8.8', '1.1.1.1'],
    'check_interval': 60,  # seconds
    'connection_history_size': 1000,
}

# Logging Configuration
LOG_CONFIG = {
    'log_dir': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs'),
    'max_log_size': 10 * 1024 * 1024,  # 10MB
    'backup_count': 5,
}

# Notification Configuration
NOTIFICATION_CONFIG = {
    'timeout': 10,
    'default_title': 'System Monitor Alert',
}

# Network utility configurations
NETWORK_CONFIG = {
    'pool_connections': 100,
    'pool_maxsize': 100,
    'max_retries': 3,
    'cache_ttl': 300,  # 5 minutes
    'cache_maxsize': 1000,
    'batch_size': 100,
    'batch_timeout': 60,  # 1 minute
    'compression_enabled': True
}

# Ollama cache configuration
OLLAMA_CACHE_CONFIG = {
    'ttl': 3600,  # 1 hour
    'maxsize': 1000
}

# Crawler Configuration
CRAWLER_CONFIG = {
    'seed_urls': [
        'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        'https://nvd.nist.gov/vuln/full-listing',
        'https://www.bleepingcomputer.com/security/',
        'https://www.darkreading.com/vulnerabilities-threats',
        'https://www.securityweek.com',  # Added more reliable security news source
        'https://www.zdnet.com/security'  # Added mainstream tech security source
    ],
    'max_pages': 50,  # Reduced to avoid overwhelming the sites
    'request_delay': 3,  # Increased delay between requests to be more polite
    'timeout': 15,  # Increased timeout for slower sites
    'max_retries': 3,  # Number of times to retry failed requests
    'retry_delay': 5,  # Seconds to wait between retries
    'user_agent': 'SecurityMonitor/1.0 (Research Bot)',
    'follow_robots_txt': True,  # Respect robots.txt
    'max_depth': 3,  # Maximum depth to crawl from seed URLs
    'verify_ssl': True  # Verify SSL certificates
}
