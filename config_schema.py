#!/usr/bin/env python3
from typing import Dict, Any
from pydantic import BaseModel, Field, validator
from enum import Enum
import os

class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class LoggingConfig(BaseModel):
    log_rotation: Dict[str, Any] = Field(
        default={
            'max_size_mb': 100,
            'backup_count': 5,
            'compression': True
        }
    )
    log_levels: Dict[str, LogLevel] = Field(
        default={
            'console': LogLevel.INFO,
            'file': LogLevel.DEBUG,
            'database': LogLevel.INFO
        }
    )

class MonitoringConfig(BaseModel):
    intervals: Dict[str, int] = Field(...)
    thresholds: Dict[str, float] = Field(...)
    retention: Dict[str, int] = Field(...)

    @validator('intervals')
    def validate_intervals(cls, v):
        required_keys = {'system_metrics', 'network_connections', 'threat_detection', 'performance_check'}
        if not all(key in v for key in required_keys):
            raise ValueError(f"Missing required interval configurations: {required_keys - v.keys()}")
        return v

class SecurityConfig(BaseModel):
    ip_blacklist_update_interval: int = Field(default=3600)
    threat_detection_sensitivity: float = Field(ge=0.0, le=1.0)
    auto_block_threshold: float = Field(ge=0.0, le=1.0)
    whitelist: list[str] = Field(default_factory=list)
    blacklist: list[str] = Field(default_factory=list)

class BackupConfig(BaseModel):
    enabled: bool = Field(default=True)
    interval_hours: int = Field(default=24)
    retention_days: int = Field(default=30)
    storage_path: str = Field(default="./backups")

class SystemConfig(BaseModel):
    environment: str = Field(default="development")
    debug_mode: bool = Field(default=False)
    api_version: str = Field(default="v1")
    service_name: str = Field(default="sysDaemon")

class EnterpriseConfig(BaseModel):
    monitoring: MonitoringConfig
    logging: LoggingConfig
    security: SecurityConfig
    backup: BackupConfig
    system: SystemConfig

    class Config:
        validate_assignment = True
        extra = "forbid"

def load_environment_config() -> Dict[str, Any]:
    """Load configuration from environment variables with prefixes."""
    config = {}
    for key, value in os.environ.items():
        if key.startswith("SYSDAEMON_"):
            parts = key.lower().split("_")[1:]
            current = config
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            current[parts[-1]] = value
    return config
