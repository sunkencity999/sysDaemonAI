import os
import logging
import logging.handlers
from datetime import datetime
import json
from typing import Dict, Any

class StructuredFormatter(logging.Formatter):
    """Custom formatter that outputs logs in JSON format with correlation IDs"""
    
    def format(self, record: logging.LogRecord) -> str:
        # Basic log structure
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add correlation ID if available
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
            
        # Add extra fields if available
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)
            
        # Add exception info if available
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
            
        return json.dumps(log_data)

def setup_logging(app_name: str = 'sysdaemon', log_dir: str = 'logs') -> None:
    """Setup structured logging with file rotation and console output"""
    
    # Ensure log directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # Create formatters
    structured_formatter = StructuredFormatter()
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup file handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        os.path.join(log_dir, f'{app_name}.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setFormatter(structured_formatter)
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Setup application logger
    app_logger = logging.getLogger(app_name)
    app_logger.setLevel(logging.INFO)
    
    # Log startup message
    app_logger.info(
        "Logging system initialized",
        extra={'extra_fields': {'app_name': app_name}}
    )

class ContextLogger:
    """Logger that maintains context between related operations"""
    
    def __init__(self, logger_name: str):
        self.logger = logging.getLogger(logger_name)
        self.context: Dict[str, Any] = {}
        
    def set_context(self, **kwargs) -> None:
        """Set context values that will be included in all subsequent log messages"""
        self.context.update(kwargs)
        
    def clear_context(self) -> None:
        """Clear all context values"""
        self.context.clear()
        
    def _log(self, level: int, msg: str, *args, **kwargs) -> None:
        """Internal logging method that adds context to all messages"""
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        if 'extra_fields' not in kwargs['extra']:
            kwargs['extra']['extra_fields'] = {}
            
        kwargs['extra']['extra_fields'].update(self.context)
        self.logger.log(level, msg, *args, **kwargs)
        
    def debug(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.DEBUG, msg, *args, **kwargs)
        
    def info(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.INFO, msg, *args, **kwargs)
        
    def warning(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.WARNING, msg, *args, **kwargs)
        
    def error(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.ERROR, msg, *args, **kwargs)
        
    def critical(self, msg: str, *args, **kwargs) -> None:
        self._log(logging.CRITICAL, msg, *args, **kwargs)
