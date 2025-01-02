"""Tests for the network monitoring functionality."""

import pytest
from unittest.mock import patch, MagicMock
import psutil
from prometheus_client import REGISTRY
import sys

# Mock the crewai and ai_agents imports
sys.modules['crewai'] = MagicMock()
sys.modules['ai_agents'] = MagicMock()
sys.modules['ai_agents.log_monitor_agent'] = MagicMock()
sys.modules['ai_agents.base_agent'] = MagicMock()
sys.modules['ai_agents.threat_intel_agent'] = MagicMock()
sys.modules['ai_agents.network_security_agent'] = MagicMock()
sys.modules['ai_agents.defense_agent'] = MagicMock()
sys.modules['ai_agents.incident_response_agent'] = MagicMock()
sys.modules['ai_agents.crawler_agent'] = MagicMock()
sys.modules['ai_agents.analysis_agent'] = MagicMock()

from network_monitor import NetworkMonitor
import asyncio
from network_monitor.task_manager import TaskPriority

@pytest.fixture(autouse=True)
def clean_prometheus_registry():
    """Clean up the Prometheus registry before and after each test."""
    # Store existing collectors
    collectors = list(REGISTRY._collector_to_names.keys())
    
    # Remove all collectors
    for collector in collectors:
        REGISTRY.unregister(collector)
    
    yield
    
    # Clean up after test
    collectors = list(REGISTRY._collector_to_names.keys())
    for collector in collectors:
        REGISTRY.unregister(collector)

@pytest.fixture
def mock_performance_monitor():
    """Mock the performance monitor to avoid Prometheus conflicts."""
    with patch('network_monitor.network_monitor.PerformanceMonitor') as mock:
        # Configure the mock to return the expected values
        mock_stats = {
            'bytes_sent': 1000,
            'bytes_recv': 2000,
            'packets_sent': 10,
            'packets_recv': 20
        }
        mock.return_value.get_network_stats.return_value = mock_stats
        yield mock

def test_network_monitor_initialization(mock_performance_monitor):
    """Test NetworkMonitor initializes correctly."""
    monitor = NetworkMonitor()
    assert monitor is not None
    assert hasattr(monitor, 'get_current_connections')

@pytest.mark.parametrize("connection_data,expected_count", [
    ([], 0),
    ([
        MagicMock(
            laddr=MagicMock(ip='127.0.0.1', port=80),
            raddr=MagicMock(ip='192.168.1.1', port=443),
            status='ESTABLISHED',
            pid=1234
        )
    ], 1)
])
def test_get_current_connections(mock_performance_monitor, connection_data, expected_count):
    """Test getting current network connections."""
    with patch('psutil.net_connections', return_value=connection_data), \
         patch('psutil.Process') as mock_process:
        
        mock_process.return_value.name.return_value = 'python'
        monitor = NetworkMonitor()
        connections = monitor.get_current_connections()
        assert len(connections) == expected_count
        if expected_count > 0:
            assert 'local_address' in connections[0]
            assert 'remote_address' in connections[0]
            assert 'status' in connections[0]

def test_get_performance_stats(mock_performance_monitor):
    """Test getting performance statistics."""
    mock_stats = {
        'bytes_sent': 1000,
        'bytes_recv': 2000,
        'packets_sent': 10,
        'packets_recv': 20
    }
    
    with patch('psutil.net_io_counters', return_value=MagicMock(**mock_stats)):
        monitor = NetworkMonitor()
        stats = monitor.performance_monitor.get_network_stats()
        assert stats['bytes_sent'] == 1000
        assert stats['bytes_recv'] == 2000

@pytest.mark.asyncio
async def test_process_connection(mock_performance_monitor):
    """Test connection processing."""
    monitor = NetworkMonitor()
    
    # Test a new connection
    connection = {
        'local_address': '127.0.0.1:80',
        'remote_address': '192.168.1.1:443',
        'status': 'ESTABLISHED',
        'pid': 1234,
        'process_name': 'python'
    }
    
    # Process the connection
    await monitor.process_connection(connection)
    
    # Verify it was added to history
    assert len(monitor.connection_history) == 1
    assert monitor.connection_history[0]['local_address'] == '127.0.0.1:80'

@pytest.mark.asyncio
async def test_error_handling(mock_performance_monitor):
    """Test error handling in network monitoring."""
    with patch('psutil.net_connections', side_effect=psutil.AccessDenied):
        monitor = NetworkMonitor()
        connections = monitor.get_current_connections()
        assert connections == []  # Should return empty list on error

@pytest.mark.asyncio
async def test_async_monitoring(mock_performance_monitor):
    """Test asynchronous network monitoring."""
    monitor = NetworkMonitor()
    
    # Mock network activity
    mock_connections = [
        MagicMock(
            laddr=MagicMock(ip='127.0.0.1', port=80),
            raddr=MagicMock(ip='192.168.1.1', port=443),
            status='ESTABLISHED',
            pid=1234
        )
    ]
    
    with patch('psutil.net_connections', return_value=mock_connections), \
         patch('psutil.Process') as mock_process:
        
        mock_process.return_value.name.return_value = 'python'
        
        # Test async monitoring for one update
        connection = {
            'source_ip': '127.0.0.1',
            'destination_ip': '192.168.1.1',
            'source_port': 80,
            'destination_port': 443,
            'protocol': 'TCP',
            'bytes_sent': 1000,
            'bytes_received': 2000,
            'status': 'ESTABLISHED'
        }
        
        # Process the connection
        await monitor.process_connection(connection)
        
        # Verify monitoring is working
        assert len(monitor.connection_history) > 0
        assert monitor.connection_history[0]['source_ip'] == '127.0.0.1'
