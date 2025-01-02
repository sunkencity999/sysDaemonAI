"""Tests for the network monitoring GUI."""

import pytest
from unittest.mock import patch, MagicMock
from PyQt6.QtCore import Qt
from network_gui import NetworkMonitorGUI

def test_gui_initialization(qapp, mock_network_monitor):
    """Test GUI initializes correctly."""
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor):
        gui = NetworkMonitorGUI()
        assert gui is not None
        assert hasattr(gui, 'network_monitor')

def test_connection_table_update(qapp, mock_network_monitor):
    """Test connection table updates correctly."""
    mock_connections = [{
        'local_address': '127.0.0.1:80',
        'remote_address': '192.168.1.1:443',
        'status': 'ESTABLISHED',
        'pid': 1234,
        'process': 'python'
    }]
    mock_network_monitor.get_active_connections.return_value = mock_connections
    
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor):
        gui = NetworkMonitorGUI()
        gui.update_connections()
        
        # Check if the connection appears in the table
        table = gui.connections_table
        assert table.rowCount() == 1
        assert table.item(0, 0).text() == '127.0.0.1:80'
        assert table.item(0, 1).text() == '192.168.1.1:443'

def test_startup_checkbox(qapp, mock_network_monitor):
    """Test startup checkbox functionality."""
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor):
        gui = NetworkMonitorGUI()
        
        # Mock the launch agent functions
        with patch('os.path.exists', return_value=False), \
             patch('subprocess.run') as mock_run, \
             patch('shutil.copy2') as mock_copy:
            
            # Test enabling startup
            gui.startup_checkbox.setChecked(True)
            assert mock_copy.called
            mock_run.assert_called_with(['launchctl', 'load', '-w', pytest.any()], check=True)
            
            # Test disabling startup
            gui.startup_checkbox.setChecked(False)
            mock_run.assert_called_with(['launchctl', 'unload', '-w', pytest.any()], check=True)

def test_export_functionality(qapp, mock_network_monitor, tmp_path):
    """Test data export functionality."""
    mock_connections = [{
        'local_address': '127.0.0.1:80',
        'remote_address': '192.168.1.1:443',
        'status': 'ESTABLISHED',
        'pid': 1234,
        'process': 'python'
    }]
    mock_network_monitor.get_active_connections.return_value = mock_connections
    
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor), \
         patch('PyQt6.QtWidgets.QFileDialog.getSaveFileName', 
               return_value=(str(tmp_path / "export.xlsx"), "*.xlsx")):
        
        gui = NetworkMonitorGUI()
        gui.export_data()
        
        # Verify export file was created
        assert (tmp_path / "export.xlsx").exists()

@pytest.mark.parametrize("test_data,expected_severity", [
    ({'threat_level': 0.2}, 'Low'),
    ({'threat_level': 0.6}, 'Medium'),
    ({'threat_level': 0.8}, 'High')
])
def test_threat_level_display(qapp, mock_network_monitor, test_data, expected_severity):
    """Test threat level display functionality."""
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor):
        gui = NetworkMonitorGUI()
        severity = gui._get_threat_severity(test_data)
        assert severity == expected_severity

def test_error_handling(qapp, mock_network_monitor):
    """Test GUI error handling."""
    mock_network_monitor.get_active_connections.side_effect = Exception("Test error")
    
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor), \
         patch('PyQt6.QtWidgets.QMessageBox.warning') as mock_warning:
        
        gui = NetworkMonitorGUI()
        gui.update_connections()
        
        # Verify error dialog was shown
        assert mock_warning.called

def test_system_tray(qapp, mock_network_monitor):
    """Test system tray functionality."""
    with patch('network_gui.NetworkMonitor', return_value=mock_network_monitor):
        gui = NetworkMonitorGUI()
        
        # Verify system tray icon exists
        assert gui.tray_icon is not None
        assert gui.tray_icon.isVisible()
        
        # Test minimize to tray
        gui.close()
        assert not gui.isVisible()
        assert gui.tray_icon.isVisible()
