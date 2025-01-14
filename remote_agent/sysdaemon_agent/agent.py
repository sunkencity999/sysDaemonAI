#!/usr/bin/env python3

import os
import sys
import json
import time
import logging
import platform
import requests
import threading
import subprocess
from datetime import datetime
from pathlib import Path
import psutil
import getpass
import socket
from PyQt6.QtWidgets import (QApplication, QSystemTrayIcon, QMenu, 
                          QInputDialog, QLineEdit, QMessageBox)
from PyQt6.QtGui import QIcon
from PyQt6.QtCore import QTimer, QObject, pyqtSignal

class RemoteAgent(QObject):
    alert_signal = pyqtSignal(str, str)  # title, message
    
    def __init__(self):
        super().__init__()
        self.setup_logging()
        self.load_config()
        self.setup_directories()
        self.hostname = platform.node()
        self.alerts = []
        self.last_security_analysis = None
        self.running = True
        self.server_info = None
        self.sock = None
        
        # Start server discovery
        self.discovery_thread = threading.Thread(target=self.discover_server, daemon=True)
        self.discovery_thread.start()
        
    def discover_server(self):
        """Listen for server broadcasts and connect"""
        discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        discovery_sock.bind(('', 5776))  # Use 5776 for discovery (5775 + 1)
        
        while self.running and not self.server_info:
            try:
                data, addr = discovery_sock.recvfrom(1024)
                server_info = json.loads(data.decode())
                
                if server_info.get('type') == 'sysdaemon_server':
                    self.server_info = server_info
                    self.logger.info(f"Found server at {server_info['ip']}:{server_info['port']}")
                    self.connect_to_server()
                    
            except Exception as e:
                self.logger.error(f"Error in server discovery: {e}")
                time.sleep(5)  # Wait before retrying
                
    def connect_to_server(self):
        """Connect to the main application server"""
        if not self.server_info:
            self.logger.error("No server info available")
            return
            
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.server_info['ip'], self.server_info['port']))
            
            # Send initial handshake with agent info
            agent_info = {
                'hostname': self.hostname,
                'platform': platform.system(),
                'version': '1.0',
                'username': getpass.getuser(),
                'start_time': datetime.now().isoformat()
            }
            self.sock.send(json.dumps(agent_info).encode())
            
            # Start sending metrics
            self.metrics_thread = threading.Thread(target=self.send_metrics_loop, daemon=True)
            self.metrics_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to connect to server: {e}")
            self.server_info = None  # Reset server info to trigger rediscovery
            
    def send_metrics_loop(self):
        """Continuously send metrics to the server"""
        while self.running and self.sock:
            try:
                metrics = self.collect_metrics()
                self.sock.send(json.dumps(metrics).encode())
                time.sleep(60)  # Send metrics every minute
            except Exception as e:
                self.logger.error(f"Error sending metrics: {e}")
                self.sock.close()
                self.sock = None
                self.server_info = None  # Reset server info to trigger rediscovery
                break
                
    def collect_metrics(self):
        """Collect system metrics"""
        try:
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': dict(psutil.virtual_memory()._asdict()),
                'disk': {disk.mountpoint: dict(psutil.disk_usage(disk.mountpoint)._asdict())
                        for disk in psutil.disk_partitions()},
                'network': dict(psutil.net_io_counters()._asdict()),
                'boot_time': psutil.boot_time(),
                'processes': len(psutil.pids())
            }
            
            # Try to get network connections (may require root)
            try:
                connections = psutil.net_connections()
                metrics['connections'] = [
                    {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    for conn in connections if conn.status == 'ESTABLISHED'
                ]
            except Exception:
                metrics['connections'] = []
                
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            return {}
            
    def stop(self):
        """Stop the agent"""
        self.running = False
        if self.sock:
            self.sock.close()
            
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = os.path.expanduser('~/.sysdaemon/logs')
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger('SysDaemonAgent')
        self.logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler(os.path.join(log_dir, 'agent.log'))
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        self.logger.addHandler(handler)

    def setup_directories(self):
        """Create necessary directories"""
        self.base_dir = os.path.expanduser('~/.sysdaemon')
        self.config_dir = os.path.join(self.base_dir, 'config')
        self.data_dir = os.path.join(self.base_dir, 'data')
        
        for directory in [self.base_dir, self.config_dir, self.data_dir]:
            os.makedirs(directory, exist_ok=True)

    def load_config(self):
        """Load configuration from file or create default"""
        config_file = os.path.expanduser('~/.sysdaemon/config/agent_config.json')
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        else:
            self.config = {
                'master_url': 'http://localhost:5000',  # Default master URL
                'check_interval': 300,  # 5 minutes
                'daily_report_time': '00:00',  # Midnight
                'last_report_date': None
            }
            self.save_config()

    def save_config(self):
        """Save current configuration to file"""
        config_file = os.path.expanduser('~/.sysdaemon/config/agent_config.json')
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=4)

    def collect_system_info(self):
        """Collect system information"""
        info = {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': {disk.mountpoint: psutil.disk_usage(disk.mountpoint).percent 
                          for disk in psutil.disk_partitions() if os.path.exists(disk.mountpoint)},
            'timestamp': datetime.now().isoformat()
        }
        return info

    def collect_network_info(self):
        """Collect network information (may require elevated privileges)"""
        try:
            # Try to get network connections (may require root)
            connections = psutil.net_connections()
            network_info = {
                'connections': [
                    {
                        'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    for conn in connections if conn.status == 'ESTABLISHED'
                ]
            }
        except (psutil.AccessDenied, PermissionError):
            network_info = {'error': 'Insufficient permissions for network data'}
            self.request_elevated_privileges()
        
        return network_info

    def request_elevated_privileges(self):
        """Request elevated privileges if needed"""
        if sys.platform == 'darwin':  # macOS
            try:
                password, ok = QInputDialog.getText(
                    None, 'Elevated Privileges Required',
                    'Enter administrator password:',
                    QLineEdit.EchoMode.Password
                )
                if ok and password:
                    # Use sudo with the provided password
                    subprocess.run(['sudo', '-S', 'echo', 'Testing privileges'],
                                input=password.encode(),
                                capture_output=True)
            except Exception as e:
                self.logger.error(f"Error requesting privileges: {e}")

    def add_alert(self, title, message):
        """Add a new alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'title': title,
            'message': message
        }
        self.alerts.append(alert)
        self.alert_signal.emit(title, message)

    def send_daily_report(self):
        """Send daily report to master server"""
        try:
            report = {
                'agent_id': self.hostname,
                'timestamp': datetime.now().isoformat(),
                'system_info': self.collect_system_info(),
                'network_info': self.collect_network_info(),
                'alerts': self.alerts,
                'security_analysis': self.last_security_analysis
            }

            response = requests.post(
                f"{self.config['master_url']}/api/report",
                json=report,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                self.alerts = []  # Clear alerts after successful send
                self.config['last_report_date'] = datetime.now().date().isoformat()
                self.save_config()
                self.logger.info("Daily report sent successfully")
            else:
                self.logger.error(f"Failed to send report: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error sending daily report: {e}")

    def check_daily_report_time(self):
        """Check if it's time to send the daily report"""
        now = datetime.now()
        report_time = datetime.strptime(self.config['daily_report_time'], '%H:%M').time()
        
        if (now.time().hour == report_time.hour and 
            now.time().minute == report_time.minute and
            (self.config['last_report_date'] != now.date().isoformat())):
            self.send_daily_report()

    def start(self):
        """Start the agent monitoring"""
        self.logger.info("Starting SysDaemon AI Remote Agent")
        
        # Start periodic checks
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_daily_report_time)
        self.timer.start(60000)  # Check every minute
        
        self.logger.info("Agent started successfully")

def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    
    # Set application metadata
    app.setApplicationName("SysDaemon AI Agent")
    app.setApplicationDisplayName("SysDaemon AI Agent")
    app.setOrganizationName("Sysdaemon AI")
    app.setOrganizationDomain("Sysdaemon AI")
    
    # Create and set up system tray icon
    icon_path = os.path.join(os.path.dirname(__file__), 'icons', 'app_icon.png')
    if not os.path.exists(icon_path):
        icon_dir = os.path.dirname(icon_path)
        os.makedirs(icon_dir, exist_ok=True)
        # Copy icon from main application if available
        main_icon = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                               'network_monitor', 'icons', 'app_icon.png')
        if os.path.exists(main_icon):
            import shutil
            shutil.copy2(main_icon, icon_path)
    
    tray = QSystemTrayIcon()
    if os.path.exists(icon_path):
        tray.setIcon(QIcon(icon_path))
    
    # Create tray menu
    menu = QMenu()
    status_action = menu.addAction("Status: Running")
    status_action.setEnabled(False)
    menu.addSeparator()
    quit_action = menu.addAction("Quit")
    quit_action.triggered.connect(app.quit)
    
    tray.setContextMenu(menu)
    tray.show()
    
    # Create and start agent
    agent = RemoteAgent()
    agent.alert_signal.connect(
        lambda title, msg: tray.showMessage(title, msg, QSystemTrayIcon.MessageIcon.Information)
    )
    agent.start()
    
    return app.exec()

if __name__ == '__main__':
    sys.exit(main())
