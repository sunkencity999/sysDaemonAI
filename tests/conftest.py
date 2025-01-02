"""Test configuration and fixtures for SysDaemon AI tests."""

import os
import sys
import pytest
from unittest.mock import MagicMock
from PyQt6.QtWidgets import QApplication
import threading

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def pytest_configure(config):
    """Configure pytest before running tests."""
    # Set asyncio mode to auto
    config.option.asyncio_mode = "auto"

@pytest.fixture(scope="session", autouse=True)
def stop_running_threads():
    """Fixture to stop running threads after all tests."""
    yield
    for thread in threading.enumerate():
        if thread != threading.current_thread():
            try:
                thread._stop()
            except:
                pass

@pytest.fixture(scope="session")
def qapp():
    """Create a Qt application instance for the test session."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app
    app.quit()

@pytest.fixture
def mock_network_monitor():
    """Create a mock network monitor instance."""
    mock = MagicMock()
    # Add common mock returns that many tests will need
    mock.get_active_connections.return_value = []
    mock.get_interface_stats.return_value = {'bytes_sent': 0, 'bytes_recv': 0}
    mock.llm_analyzer = MagicMock()
    return mock

@pytest.fixture
def mock_database():
    """Create a mock database instance."""
    mock = MagicMock()
    mock.session.query.return_value.all.return_value = []
    return mock

@pytest.fixture
def temp_config_dir(tmp_path):
    """Create a temporary configuration directory."""
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    return config_dir

@pytest.fixture
def temp_log_dir(tmp_path):
    """Create a temporary log directory."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir

@pytest.fixture(autouse=True)
def cleanup_after_test():
    """Clean up after each test."""
    yield
    # Clean up any remaining threads
    for thread in threading.enumerate():
        if thread != threading.current_thread() and thread.name != "MainThread":
            try:
                thread._stop()
            except:
                pass
