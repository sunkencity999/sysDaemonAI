#!/usr/bin/env python3

import os
import json
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                          QPushButton, QTextEdit, QTabWidget, QLineEdit, 
                          QComboBox, QMessageBox, QDialog)

class AdminPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.agents = []
        self.setup_ui()
        self.load_remote_agents()
        
    def setup_ui(self):
        """Set up the admin panel UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Remote Agents Administration")
        title.setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;")
        layout.addWidget(title)
        
        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search agents...")
        self.search_input.textChanged.connect(self.filter_agents)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Agents list
        self.agents_list = QComboBox()
        self.agents_list.currentIndexChanged.connect(self.show_agent_details)
        layout.addWidget(self.agents_list)
        
        # Refresh button
        refresh_btn = QPushButton("Refresh Agents")
        refresh_btn.clicked.connect(self.load_remote_agents)
        layout.addWidget(refresh_btn)
        
        # Status label
        self.status_label = QLabel("No agents connected")
        layout.addWidget(self.status_label)
        
        self.setLayout(layout)
    
    def load_remote_agents(self):
        """Load list of remote agents from the database"""
        try:
            # Create data directory if it doesn't exist
            data_dir = os.path.join(os.path.dirname(__file__), 'data')
            os.makedirs(data_dir, exist_ok=True)
            
            # Load agents from file
            agents_file = os.path.join(data_dir, 'remote_agents.json')
            if os.path.exists(agents_file):
                with open(agents_file, 'r') as f:
                    self.agents = json.load(f)
            else:
                self.agents = []
            
            self.update_agents_list()
            self.update_status_label()
            
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load remote agents: {e}")
    
    def update_status_label(self):
        """Update the status label with current agent count"""
        count = len(self.agents)
        self.status_label.setText(f"Connected Agents: {count}")
    
    def filter_agents(self, text):
        """Filter agents list based on search text"""
        self.agents_list.clear()
        for agent in self.agents:
            if text.lower() in agent['hostname'].lower():
                self.agents_list.addItem(agent['hostname'])
    
    def update_agents_list(self):
        """Update the agents dropdown list"""
        self.agents_list.clear()
        for agent in sorted(self.agents, key=lambda x: x['hostname']):
            self.agents_list.addItem(agent['hostname'])
    
    def show_agent_details(self, index):
        """Show details for the selected agent"""
        if index < 0:
            return
            
        hostname = self.agents_list.currentText()
        agent = next((a for a in self.agents if a['hostname'] == hostname), None)
        if not agent:
            return
        
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Agent Details - {hostname}")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Create tabs
        tabs = QTabWidget()
        
        # System Info tab
        system_tab = QWidget()
        system_layout = QVBoxLayout()
        system_text = QTextEdit()
        system_text.setReadOnly(True)
        system_text.setText(json.dumps(agent.get('system_info', {}), indent=2))
        system_layout.addWidget(system_text)
        system_tab.setLayout(system_layout)
        tabs.addTab(system_tab, "System Info")
        
        # Alerts tab
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout()
        alerts_text = QTextEdit()
        alerts_text.setReadOnly(True)
        alerts = agent.get('alerts', [])
        alerts_text.setText("\n\n".join([
            f"[{alert['timestamp']}] {alert['title']}\n{alert['message']}"
            for alert in alerts
        ]))
        alerts_layout.addWidget(alerts_text)
        alerts_tab.setLayout(alerts_layout)
        tabs.addTab(alerts_tab, f"Alerts ({len(alerts)})")
        
        # Security Analysis tab
        security_tab = QWidget()
        security_layout = QVBoxLayout()
        security_text = QTextEdit()
        security_text.setReadOnly(True)
        security_text.setText(agent.get('security_analysis', 'No security analysis available'))
        security_layout.addWidget(security_text)
        security_tab.setLayout(security_layout)
        tabs.addTab(security_tab, "Security Analysis")
        
        # Network Info tab
        network_tab = QWidget()
        network_layout = QVBoxLayout()
        network_text = QTextEdit()
        network_text.setReadOnly(True)
        network_text.setText(json.dumps(agent.get('network_info', {}), indent=2))
        network_layout.addWidget(network_text)
        network_tab.setLayout(network_layout)
        tabs.addTab(network_tab, "Network Info")
        
        layout.addWidget(tabs)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.setLayout(layout)
        dialog.exec()
