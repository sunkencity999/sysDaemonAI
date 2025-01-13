#!/usr/bin/env python3

import logging
from datetime import datetime, timedelta
from PyQt6.QtCore import QThread, pyqtSignal

class NetworkMonitorThread(QThread):
    """Thread for monitoring network connections and updating statistics."""
    
    connection_update = pyqtSignal(list)
    analysis_update = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    stats_update = pyqtSignal(dict)
    
    def __init__(self, network_monitor):
        """Initialize the network monitor thread.
        
        Args:
            network_monitor: Instance of NetworkMonitor class to get connection data
        """
        super().__init__()
        self.network_monitor = network_monitor
        self.running = True
        self.connection_history = []
        self.last_update = datetime.now()
        self.logger = logging.getLogger(__name__)
        
    def run(self):
        """Main thread loop for monitoring network connections."""
        self.logger.info("Starting network monitor thread")
        while self.running:
            try:
                connections = self.network_monitor.get_active_connections()
                if connections:
                    # Update connection history with timestamp
                    for conn in connections:
                        conn['timestamp'] = datetime.now().isoformat()
                    
                    # Keep last hour of connections for timeline
                    current_time = datetime.now()
                    one_hour_ago = current_time - timedelta(hours=1)
                    self.connection_history = [
                        conn for conn in self.connection_history 
                        if datetime.fromisoformat(conn['timestamp']) > one_hour_ago
                    ]
                    self.connection_history.extend(connections)
                    
                    # Emit updates
                    self.connection_update.emit(connections)
                    
                    # Calculate and emit statistics every minute
                    if (datetime.now() - self.last_update).seconds >= 60:
                        stats = self.calculate_stats()
                        self.stats_update.emit(stats)
                        self.last_update = datetime.now()
                        
            except Exception as e:
                error_msg = f"Error monitoring connections: {str(e)}"
                self.logger.error(error_msg)
                self.error_signal.emit(error_msg)
            
            # Sleep for 1 second before next update
            self.msleep(1000)
    
    def calculate_stats(self):
        """Calculate statistics from connection history.
        
        Returns:
            dict: Statistics including total connections, unique IPs, states,
                 top processes, and potential threats
        """
        stats = {
            'total_connections': len(self.connection_history),
            'unique_ips': len(set(conn['remote_address'].split(':')[0] 
                               for conn in self.connection_history 
                               if 'remote_address' in conn)),
            'connection_states': {},
            'top_processes': {},
            'potential_threats': 0
        }
        
        # Count connection states and processes
        for conn in self.connection_history:
            # Count states
            state = conn.get('status', 'unknown')
            stats['connection_states'][state] = stats['connection_states'].get(state, 0) + 1
            
            # Count processes
            process = conn.get('process', 'unknown')
            stats['top_processes'][process] = stats['top_processes'].get(process, 0) + 1
            
            # Count potential threats
            if conn.get('threat_level', 0) > 0.7:
                stats['potential_threats'] += 1
        
        return stats
    
    def stop(self):
        """Stop the network monitor thread."""
        self.logger.info("Stopping network monitor thread")
        self.running = False
