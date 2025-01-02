#!/usr/bin/env python3
import json
import os
from typing import Dict, Any

class AdvancedConfig:
    DEFAULT_CONFIG = {
        'monitoring': {
            'intervals': {
                'system_metrics': 5,  # seconds
                'network_connections': 2,
                'threat_detection': 10,
                'performance_check': 30
            },
            'thresholds': {
                'cpu_warning': 80,  # percentage
                'cpu_critical': 90,
                'memory_warning': 85,
                'memory_critical': 95,
                'disk_warning': 85,
                'disk_critical': 95,
                'network_spike_threshold': 1000000  # bytes/sec
            },
            'retention': {
                'metrics_days': 90,
                'connections_days': 30,
                'alerts_days': 180
            }
        },
        'logging': {
            'log_rotation': {
                'max_size_mb': 100,
                'backup_count': 5,
                'compression': True
            },
            'log_levels': {
                'console': 'INFO',
                'file': 'DEBUG',
                'database': 'INFO'
            }
        },
        'security': {
            'ip_blacklist_update_interval': 3600,  # seconds
            'threat_detection_sensitivity': 0.7,
            'auto_block_threshold': 0.9,
            'whitelist': [],
            'blacklist': []
        },
        'backup': {
            'enabled': True,
            'interval_hours': 24,
            'retention_count': 7,
            'compression': True,
            'backup_paths': [
                'logs/',
                'data/'
            ]
        },
        'visualization': {
            'default_timespan': '24h',
            'update_interval': 5,  # seconds
            'max_datapoints': 1000,
            'chart_themes': {
                'light': {
                    'background': '#ffffff',
                    'text': '#000000',
                    'grid': '#e0e0e0'
                },
                'dark': {
                    'background': '#2d2d2d',
                    'text': '#ffffff',
                    'grid': '#404040'
                }
            }
        },
        'api_keys': {
            'abuseipdb': 'd823ef94bd0ab629c2ebbd7ba44dc7a8ad7774a040fd7e3239ef9d03f97fc3a2f00fd3434022b58e'
        }
    }

    def __init__(self):
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'advanced_config.json')
        self.config = self.load_config()

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create with defaults if not exists"""
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults to ensure all keys exist
                    return self._deep_merge(self.DEFAULT_CONFIG.copy(), user_config)
            except json.JSONDecodeError:
                return self.DEFAULT_CONFIG.copy()
        else:
            # Create default config file
            self.save_config(self.DEFAULT_CONFIG)
            return self.DEFAULT_CONFIG.copy()

    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file"""
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=4)
        self.config = config

    def get(self, *keys: str) -> Any:
        """Get a configuration value using dot notation"""
        value = self.config
        for key in keys:
            value = value.get(key)
            if value is None:
                return None
        return value

    def set(self, value: Any, *keys: str) -> None:
        """Set a configuration value using dot notation"""
        config = self.config
        for key in keys[:-1]:
            config = config.setdefault(key, {})
        config[keys[-1]] = value
        self.save_config(self.config)

    def reset_to_defaults(self) -> None:
        """Reset configuration to default values"""
        self.save_config(self.DEFAULT_CONFIG.copy())

    @staticmethod
    def _deep_merge(base: Dict[str, Any], update: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries"""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = AdvancedConfig._deep_merge(base[key], value)
            else:
                base[key] = value
        return base
