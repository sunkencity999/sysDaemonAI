"""UI components for AI agents."""

import sys
import os
import json
import threading
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QTextEdit, QPushButton, QLineEdit, QTabWidget, 
                           QGroupBox, QComboBox, QSpinBox, QCheckBox,
                           QFileDialog, QMessageBox, QDialog)
from PyQt6.QtCore import Qt, pyqtSignal, QObject, QTimer
from PyQt6.QtGui import QTextCursor
import logging
import logging.handlers
import queue
from queue import Queue
from datetime import datetime, timedelta
from typing import Dict, Any
from config import LOG_CONFIG, OLLAMA_CONFIG
from virus_scanner import VirusScanner
from virus_scanner_ui import ScanProgressDialog, ScanResultsDialog, ScanOptionsDialog
import subprocess

# Suppress Qt warnings about layer-backed views
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.qpa.*=false'

# Ensure log directory exists
os.makedirs(LOG_CONFIG['log_dir'], exist_ok=True)

# Configure logging
def setup_logging():
    """Set up logging configuration."""
    log_file = os.path.join(LOG_CONFIG['log_dir'], 'monitor.log')
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create rotating file handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=LOG_CONFIG['max_log_size'],
        backupCount=LOG_CONFIG['backup_count']
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return root_logger

# Initialize logging
logger = setup_logging()

class AgentTabs(QWidget):
    def __init__(self, main_window, agent_configs):
        super().__init__()
        self.main = main_window
        self.agent_configs = agent_configs
        self.crawler_text = None
        self.logger = logging.getLogger(__name__)
        self.load_model_config()  # Load the model configuration on startup
        
        # Create layout
        self.layout = QVBoxLayout(self)
        
        # Create top button bar
        top_button_layout = QHBoxLayout()
        
        # Add virus scan button
        self.virus_scan_button = QPushButton("Virus Scan")
        self.virus_scan_button.clicked.connect(self.start_virus_scan)
        top_button_layout.addWidget(self.virus_scan_button)
        
        # Add model selection dropdown
        self.model_selection_dropdown = QComboBox(self)
        models = self.fetch_installed_models()
        self.model_selection_dropdown.addItems(models)
        # Set the current model based on OLLAMA_CONFIG
        current_model = OLLAMA_CONFIG.get('model', models[0] if models else '')
        if current_model in models:
            self.model_selection_dropdown.setCurrentText(current_model)
        self.model_selection_dropdown.currentIndexChanged.connect(self.update_selected_model)
        top_button_layout.addWidget(self.model_selection_dropdown)
        
        # Add label to display the currently selected model
        self.model_selection_label = QLabel(f"Current Model: {current_model}", self)
        top_button_layout.addWidget(self.model_selection_label)
        
        # Add stretch to push buttons to the right
        top_button_layout.addStretch()
        
        # Add the button layout to main layout
        self.layout.addLayout(top_button_layout)
        
        # Add tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        
        # Setup tabs
        self.setup_agent_tabs()
        
        # Connect signals from log monitor agent
        if hasattr(self.main, 'log_monitor'):
            self.main.log_monitor.finding_signal.connect(self.handle_log_finding)
            self.main.log_monitor.status_signal.connect(self.handle_log_status)
            self.main.log_monitor.error_signal.connect(self.handle_log_error)
        
        # Setup auto-refresh timer with longer interval
        self.log_refresh_timer = QTimer(self)
        self.log_refresh_timer.timeout.connect(self.refresh_logs)
        self.log_refresh_timer.start(300000)  # Refresh every 5 minutes instead of every minute
    
    def load_model_config(self):
        """Load the model configuration from a file."""
        try:
            with open('model_config.json', 'r') as f:
                config = json.load(f)
                OLLAMA_CONFIG['model'] = config.get('model', 'default_model')  # Set to a default model if not found
        except FileNotFoundError:
            self.logger.warning("Model configuration file not found. Using default model.")
            with open('model_config.json', 'w') as f:
                json.dump({'model': 'default_model'}, f)

    def setup_agent_tabs(self):
        """Create tabs for each AI agent."""
        self.create_log_monitor_tab()
        self.create_threat_intel_tab()
        self.create_defense_tab()
        self.create_crawler_tab()
    
    def create_log_monitor_tab(self):
        """Create the Log Monitor tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Add settings section
        settings_group = QGroupBox("Log Monitor Settings")
        settings_layout = QHBoxLayout()
        
        # Time window setting
        settings_layout.addWidget(QLabel("Time Window:"))
        self.time_window_combo = QComboBox()
        self.time_window_combo.addItems(["Last Hour", "Last 4 Hours", "Last 24 Hours", "Last Week"])
        settings_layout.addWidget(self.time_window_combo)
        
        # Add auto-refresh checkbox
        self.auto_refresh_check = QCheckBox("Auto Refresh")
        self.auto_refresh_check.setChecked(True)
        settings_layout.addWidget(self.auto_refresh_check)
        
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        # Add summary section
        summary_group = QGroupBox("Log Analysis Summary")
        summary_layout = QVBoxLayout()
        self.log_summary_text = QTextEdit()
        self.log_summary_text.setReadOnly(True)
        self.log_summary_text.setMaximumHeight(100)
        summary_layout.addWidget(self.log_summary_text)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Add findings section
        findings_group = QGroupBox("Log Findings")
        findings_layout = QVBoxLayout()
        
        # Add severity filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Severity:"))
        self.log_severity_combo = QComboBox()
        self.log_severity_combo.addItems(["All", "HIGH", "MEDIUM", "LOW"])
        self.log_severity_combo.currentTextChanged.connect(self.filter_log_findings)
        filter_layout.addWidget(self.log_severity_combo)
        findings_layout.addLayout(filter_layout)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        findings_layout.addWidget(self.log_text)
        findings_group.setLayout(findings_layout)
        layout.addWidget(findings_group)
        
        # Add controls
        controls_layout = QHBoxLayout()
        
        refresh_button = QPushButton("Refresh Logs")
        refresh_button.clicked.connect(self.refresh_logs)
        controls_layout.addWidget(refresh_button)
        
        export_button = QPushButton("Export Findings")
        export_button.clicked.connect(self.export_log_findings)
        controls_layout.addWidget(export_button)
        
        layout.addLayout(controls_layout)
        
        # Add status bar
        self.log_status_label = QLabel("")
        layout.addWidget(self.log_status_label)
        
        self.tabs.addTab(tab, "Log Monitor")
        
        # Store widget references
        self.log_findings = []
    
    def create_threat_intel_tab(self):
        """Create the Threat Intelligence tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        threat_text = QTextEdit()
        threat_text.setReadOnly(True)
        layout.addWidget(QLabel("<h3>Threat Intelligence</h3>"))
        layout.addWidget(threat_text)
        
        # Add IP check field
        ip_layout = QHBoxLayout()
        ip_input = QLineEdit()
        ip_input.setPlaceholderText("Enter IP to check...")
        check_ip = QPushButton("Check IP")
        check_ip.clicked.connect(lambda: self.check_ip_threat(ip_input.text(), threat_text))
        ip_layout.addWidget(ip_input)
        ip_layout.addWidget(check_ip)
        layout.addLayout(ip_layout)
        
        self.tabs.addTab(tab, "Threat Intel")
    
    def create_defense_tab(self):
        """Create the Defense tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        defense_text = QTextEdit()
        defense_text.setReadOnly(True)
        layout.addWidget(QLabel("<h3>Active Defenses</h3>"))
        layout.addWidget(defense_text)
        
        # Add defense controls
        control_layout = QHBoxLayout()
        rule_input = QLineEdit()
        rule_input.setPlaceholderText("Enter IP to block...")
        block_button = QPushButton("Block IP")
        block_button.clicked.connect(lambda: self.implement_defense(rule_input.text(), defense_text))
        control_layout.addWidget(rule_input)
        control_layout.addWidget(block_button)
        layout.addLayout(control_layout)
        
        self.tabs.addTab(tab, "Defense")
    
    def create_crawler_tab(self):
        """Create the crawler tab."""
        crawler_tab = QWidget()
        layout = QVBoxLayout(crawler_tab)
        
        # Controls section
        controls_group = QGroupBox("Controls")
        controls_layout = QHBoxLayout()
        controls_group.setLayout(controls_layout)
        
        self.crawler_url_input = QLineEdit()
        self.crawler_url_input.setPlaceholderText("Enter URL to crawl")
        controls_layout.addWidget(self.crawler_url_input)
        
        self.crawler_depth_input = QSpinBox()
        self.crawler_depth_input.setRange(1, 100)  # Increased range
        self.crawler_depth_input.setValue(10)  # Default value
        self.crawler_depth_input.setToolTip("Maximum number of pages to crawl")
        controls_layout.addWidget(self.crawler_depth_input)
        
        self.start_crawler_button = QPushButton("Start Crawl")
        self.start_crawler_button.clicked.connect(self.start_crawling)
        controls_layout.addWidget(self.start_crawler_button)
        
        self.export_crawler_button = QPushButton("Export Findings")
        self.export_crawler_button.clicked.connect(self.export_crawler_findings)
        controls_layout.addWidget(self.export_crawler_button)
        
        layout.addWidget(controls_group)
        
        # Add findings section
        findings_group = QGroupBox("Security Findings")
        findings_layout = QVBoxLayout()
        findings_group.setLayout(findings_layout)
        
        self.crawler_text = QTextEdit()
        self.crawler_text.setReadOnly(True)
        findings_layout.addWidget(self.crawler_text)
        
        layout.addWidget(findings_group)
        
        # Status label
        self.status_label = QLabel("Ready to crawl")
        layout.addWidget(self.status_label)
        
        self.tabs.addTab(crawler_tab, "Intelligence")
        
        # Connect crawler agent signals if available
        if hasattr(self.main, 'crawler_agent'):
            self.main.crawler_agent.finding_signal.connect(self.update_security_finding)
            self.main.crawler_agent.status_signal.connect(self.status_label.setText)
            self.main.crawler_agent.error_signal.connect(lambda msg: self.status_label.setText(f"Error: {msg}"))
        
        # Setup status update timer
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.update_crawler_status)
        self.status_timer.start(1000)  # Update every second
    
    def update_log_findings(self, text_widget):
        """Update log findings display."""
        findings = self.main.log_monitor.get_recent_findings()
        text_widget.clear()
        for finding in findings:
            text_widget.append(f"[{finding['timestamp']}] {finding['severity']}: {finding['finding']}")
    
    def check_ip_threat(self, ip, text_widget):
        """Check IP against threat intelligence."""
        try:
            import requests
            
            if not ip:
                text_widget.append("Please enter an IP address")
                return
                
            # Use AbuseIPDB API if configured
            if 'abuseipdb' in self.agent_configs and self.agent_configs['abuseipdb']:
                api_key = self.agent_configs['abuseipdb']
                url = 'https://api.abuseipdb.com/api/v2/check'
                headers = {
                    'Accept': 'application/json',
                    'Key': api_key
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': '90'
                }
                
                response = requests.get(url, headers=headers, params=params)
                if response.status_code == 200:
                    data = response.json()['data']
                    text_widget.append(f"\nResults for IP: {ip}")
                    text_widget.append(f"Abuse Confidence Score: {data['abuseConfidenceScore']}%")
                    text_widget.append(f"Total Reports: {data['totalReports']}")
                    text_widget.append(f"Country: {data['countryCode']}")
                    if data['lastReportedAt']:
                        text_widget.append(f"Last Reported: {data['lastReportedAt']}")
                    text_widget.append(f"Domain: {data['domain'] or 'N/A'}")
                    text_widget.append(f"ISP: {data['isp'] or 'N/A'}")
                    text_widget.append("\nUsage Type: " + (data['usageType'] or 'N/A'))
                else:
                    text_widget.append(f"Error checking IP: {response.status_code}")
            else:
                text_widget.append("AbuseIPDB API key not configured")
                
        except Exception as e:
            text_widget.append(f"Error checking IP: {str(e)}")
    
    def implement_defense(self, ip, text_widget):
        """Implement defense measure."""
        rule = {'action': 'block', 'ip': ip}
        if self.main.defense_agent.implement_firewall_rule(rule):
            text_widget.append(f"Successfully blocked IP: {ip}")
        else:
            text_widget.append(f"Failed to block IP: {ip}")
        
        # Update active defenses
        defenses = self.main.defense_agent.get_active_defenses()
        text_widget.clear()
        for defense in defenses:
            text_widget.append(f"[{defense['timestamp']}] {defense['finding']}")
    
    def start_crawling(self):
        """Start or stop the crawler based on current state."""
        if not hasattr(self.main, 'crawler_agent'):
            self.status_label.setText("Crawler agent not initialized")
            return
            
        if self.start_crawler_button.text() == "Stop Crawl":
            # Stop the crawler
            try:
                self.main.crawler_agent.stop_crawling()
                self.start_crawler_button.setText("Start Crawl")
                self.crawler_url_input.setEnabled(True)
                self.crawler_depth_input.setEnabled(True)
                self.status_label.setText("Crawler stopped")
            except Exception as e:
                self.status_label.setText(f"Error stopping crawler: {str(e)}")
                self.logger.error(f"Error stopping crawler: {str(e)}")
        else:
            # Start the crawler
            url = self.crawler_url_input.text().strip()
            if not url:
                self.status_label.setText("Please enter a URL to crawl")
                return
                
            # Add http:// if no protocol specified
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
                
            # Use depth as max_pages
            max_pages = self.crawler_depth_input.value()
            
            try:
                # Reset findings and UI before starting
                self.crawler_text.clear()
                self.main.crawler_agent.reset()
                
                # Start crawling in a new thread
                def crawl():
                    try:
                        self.main.crawler_agent.crawl(url=url, max_pages=max_pages)
                    except Exception as e:
                        self.status_label.setText(f"Error: {str(e)}")
                        self.logger.error(f"Crawler error: {str(e)}")
                        self.start_crawler_button.setText("Start Crawl")
                        self.crawler_url_input.setEnabled(True)
                        self.crawler_depth_input.setEnabled(True)
                
                threading.Thread(target=crawl, daemon=True).start()
                
                self.start_crawler_button.setText("Stop Crawl")
                self.crawler_url_input.setEnabled(False)
                self.crawler_depth_input.setEnabled(False)
                self.status_label.setText("Starting crawler...")
                
            except Exception as e:
                self.status_label.setText(f"Error starting crawler: {str(e)}")
                self.logger.error(f"Error starting crawler: {str(e)}")
    
    def update_security_finding(self, source, finding):
        """Update the findings display with new security finding."""
        if source != 'crawler':
            return
            
        severity = finding.get('severity', 'UNKNOWN')
        finding_type = finding.get('finding_type', 'UNKNOWN')
        url = finding.get('url', 'No URL')
        description = finding.get('description', 'No description')
        indicators = finding.get('indicators', [])
        recommendations = finding.get('recommendations', [])
        
        # Color scheme for severity levels
        color = {
            'HIGH': '#ff4444',    # Red
            'MEDIUM': '#ffbb33',  # Orange
            'LOW': '#33b5e5',     # Blue
            'UNKNOWN': '#999999'  # Gray
        }.get(severity, '#999999')
        
        # Build HTML content
        html_parts = []
        
        # Start finding container
        html_parts.append(f'''
            <div style='margin: 10px 0; padding: 15px; border: 1px solid {color}; border-radius: 5px; background-color: rgba({",".join(map(str, self._hex_to_rgb(color)))}, 0.1);'>
                <div style='margin-bottom: 10px;'>
                    <span style='color: {color}; font-weight: bold; font-size: 14px;'>[{severity}] {finding_type}</span>
                </div>
                <div style='margin: 5px 0;'>
                    <strong>URL:</strong> <a href='{url}' style='color: {color};'>{url}</a>
                </div>
                <div style='margin: 5px 0;'>
                    <strong>Finding:</strong> {description}
                </div>
        ''')
        
        # Add indicators if present
        if indicators:
            html_parts.append('<div style="margin: 10px 0;"><strong>Indicators:</strong>')
            html_parts.append('<ul style="margin: 5px 0; padding-left: 20px;">')
            for indicator in indicators:
                html_parts.append(f'<li>{indicator}</li></ul> ')
            html_parts.append('</div>')
        
        # Add recommendations if present
        if recommendations:
            html_parts.append('<div style="margin: 10px 0;"><strong>Recommendations:</strong>')
            html_parts.append('<ul style="margin: 5px 0; padding-left: 20px;">')
            for rec in recommendations:
                html_parts.append(f'<li>{rec}</li></ul>')
            html_parts.append('</div>')
        
        # Close finding container
        # html_parts.append('</div>')
        
        # Join all HTML parts and set as rich text
        self.crawler_text.setHtml(''.join(html_parts))
        
        # Scroll to the bottom to show newest findings
        scrollbar = self.crawler_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())
    
    def filter_findings(self, severity):
        """Filter findings by severity."""
        if hasattr(self.main, 'crawler_agent'):
            self.crawler_text.clear()
            if severity == "All":
                findings = self.main.crawler_agent.get_recent_discoveries()
            else:
                findings = self.main.crawler_agent.get_findings_by_severity(severity)
            
            for finding in findings:
                self.crawler_text.append(f"[{finding['timestamp']}] {finding['severity']}: {finding['finding']}")
    
    def toggle_crawling(self):
        """Toggle crawler between start and stop states."""
        if hasattr(self.main, 'crawler_agent'):
            if not self.main.crawler_agent.is_crawling:
                # Update max indicators from UI
                self.main.crawler_agent.max_indicators = self.max_indicators_input.value()
                
                # Start crawling
                self.crawler_button.setText("Stop Crawling")
                self.crawler_button.setStyleSheet("background-color: #ff4444;")
                self.status_label.setText("Crawler is running...")
                self.start_crawling()
            else:
                # Stop crawling
                self.main.crawler_agent.stop_crawling()
                self.crawler_button.setText("Start Crawling")
                self.crawler_button.setStyleSheet("")
                self.status_label.setText("Crawler stopped.")
    
    def update_crawler_status(self):
        """Update the crawler status display."""
        if not hasattr(self.main, 'crawler_agent'):
            return
            
        # Check if crawler is running
        is_crawling = self.main.crawler_agent.is_crawling
        
        # Update button text and UI state based on crawler status
        if is_crawling:
            self.start_crawler_button.setText("Stop Crawl")
            self.crawler_url_input.setEnabled(False)
            self.crawler_depth_input.setEnabled(False)
        else:
            self.start_crawler_button.setText("Start Crawl")
            self.crawler_url_input.setEnabled(True)
            self.crawler_depth_input.setEnabled(True)
            
        # Update findings display
        findings = getattr(self.main.crawler_agent, 'findings', [])
        if findings:
            self.crawler_text.clear()
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                title = finding.get('title', 'No title')
                url = finding.get('url', 'No URL')
                content = finding.get('content', 'No content')
                indicators = finding.get('indicators', [])
                recommendations = finding.get('recommendations', [])
                
                color = {
                    'HIGH': 'red',
                    'MEDIUM': 'orange',
                    'LOW': 'blue',
                }.get(severity, 'black')
                
                # Format the finding with more details
                self.crawler_text.append(
                    f"<div style='margin-bottom: 20px;'>"
                    f"<p><b style='color: {color};'>[{severity}] {title}</b></p>"
                    f"<p><b>URL:</b> <a href='{url}'>{url}</a></p>"
                    f"<p><b>Finding:</b> {content}</p>"
                )
                
                if indicators:
                    self.crawler_text.append("<p><b>Indicators:</b></p><ul>")
                    for indicator in indicators:
                        self.crawler_text.append(f"<li>{indicator}</li></ul>")
                    # self.crawler_text.append("</ul>")
                
                if recommendations:
                    self.crawler_text.append("<p><b>Recommendations:</b></p><ul>")
                    for rec in recommendations:
                        self.crawler_text.append(f"<li>{rec}</li></ul>")
                    # self.crawler_text.append("</ul>")
                
                #self.crawler_text.append("</div><hr>")
    
    def refresh_logs(self):
        """Refresh log findings."""
        if not hasattr(self.main, 'log_monitor'):
            return
            
        try:
            # Get time window from combo box
            window_text = self.time_window_combo.currentText()
            if window_text == "Last Hour":
                time_window = timedelta(hours=1)
            elif window_text == "Last 4 Hours":
                time_window = timedelta(hours=4)
            elif window_text == "Last 24 Hours":
                time_window = timedelta(hours=24)
            else:  # Last Week
                time_window = timedelta(days=7)
            
            # Clear existing findings if needed
            self.log_findings = []
            self.log_text.clear()
            self.log_summary_text.clear()
            
            # Analyze logs
            self.log_status_label.setText("Analyzing logs...")
            self.main.log_monitor.analyze_logs(time_window)
            
        except Exception as e:
            self.handle_log_error(str(e))
    
    def handle_log_finding(self, finding_html: str, metadata: dict):
        """Handle new log finding signal."""
        try:
            # Store finding
            self.log_findings.append(metadata)
            
            # Update display if severity matches filter
            current_filter = self.log_severity_combo.currentText()
            if current_filter == "All" or current_filter == metadata['severity']:
                cursor = self.log_text.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                cursor.insertHtml(finding_html)
                cursor.insertHtml("<hr>")
            
            # Update summary
            self._update_log_summary()
            
        except Exception as e:
            self.handle_log_error(f"Error handling log finding: {str(e)}")
    
    def handle_log_status(self, status: str):
        """Handle log monitor status update."""
        self.log_status_label.setText(status)
    
    def handle_log_error(self, error: str):
        """Handle log monitor error."""
        self.log_status_label.setText(f"Error: {error}")
        self.log_status_label.setStyleSheet("color: red;")
    
    def filter_log_findings(self, severity: str):
        """Filter log findings by severity."""
        try:
            self.log_text.clear()
            
            # Re-display findings that match the filter
            cursor = self.log_text.textCursor()
            for finding in self.log_findings:
                if severity == "All" or severity == finding['severity']:
                    cursor.movePosition(QTextCursor.MoveOperation.End)
                    cursor.insertHtml(self._format_finding_html(finding))
                    cursor.insertHtml("<hr>")
            
        except Exception as e:
            self.handle_log_error(f"Error filtering findings: {str(e)}")
    
    def export_crawler_findings(self):
        """Export crawler findings to a file."""
        try:
            if not hasattr(self.main, 'crawler_agent'):
                QMessageBox.warning(
                    self,
                    "Export Error",
                    "Crawler agent not initialized"
                )
                return
                
            findings = getattr(self.main.crawler_agent, 'findings', [])
            if not findings:
                QMessageBox.information(
                    self,
                    "Export Info",
                    "No findings to export"
                )
                return
            
            # Get current timestamp for filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawler_findings_{timestamp}.json"
            
            # Ask user for save location
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Crawler Findings",
                filename,
                "JSON Files (*.json);;All Files (*)"
            )
            
            if file_path:
                # Format findings for export
                export_data = {
                    'timestamp': datetime.now().isoformat(),
                    'findings': findings  # Findings are already in dictionary format
                }
                
                # Write to file with proper formatting
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                
                QMessageBox.information(
                    self,
                    "Export Successful",
                    f"Findings exported to {file_path}"
                )
        
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Error exporting findings: {str(e)}"
            )
    
    def export_log_findings(self):
        """Export log findings to a JSON file."""
        try:
            # Create an exports directory if it doesn't exist
            export_dir = os.path.join(os.getcwd(), 'exports')
            os.makedirs(export_dir, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"log_findings_{timestamp}.json"
            filepath = os.path.join(export_dir, filename)
            
            # Check if we have findings to export
            if not self.log_findings:
                self.log_status_label.setText("No findings to export")
                self.log_status_label.setStyleSheet("color: #ff4444;")
                return
                
            # Export findings
            with open(filepath, 'w') as f:
                json.dump({
                    'timestamp': timestamp,
                    'total_findings': len(self.log_findings),
                    'findings': self.log_findings,
                    'metadata': {
                        'time_window': self.time_window_combo.currentText(),
                        'severity_filter': self.log_severity_combo.currentText()
                    }
                }, f, indent=2)
                
            # Show success message with clickable link
            abs_path = os.path.abspath(filepath)
            self.log_status_label.setText(
                f'Findings exported to: <a href="file://{abs_path}">{filename}</a>'
            )
            self.log_status_label.setOpenExternalLinks(True)
            self.log_status_label.setStyleSheet("color: #44aa44;")
            
            # Also show a system notification
            self.main.show_notification(
                "Export Complete",
                f"Log findings exported to {filename}"
            )
            
        except Exception as e:
            self.handle_log_error(f"Error exporting findings: {str(e)}")
            self.log_status_label.setStyleSheet("color: #ff4444;")
    
    def _format_finding_html(self, finding: Dict[str, Any]) -> str:
        """Format a finding dictionary as HTML."""
        severity_colors = {
            'HIGH': '#ff4444',
            'MEDIUM': '#ffaa00',
            'LOW': '#44aa44'
        }
        
        return f"""
        <div style='margin-bottom: 10px; padding: 5px; border-left: 3px solid {severity_colors.get(finding['severity'], '#888888')};'>
            <p><strong>Time:</strong> {finding['timestamp']}</p>
            <p><strong>Category:</strong> {finding['category']} ({finding['severity']})</p>
            <p><strong>Source:</strong> {finding['source']}</p>
            <p><strong>Description:</strong> {finding['description']}</p>
            <p><strong>Log Entry:</strong> <pre>{finding['raw_log']}</pre></p>
            <p><strong>Recommendations:</strong></p>
            <ul>
                {''.join(f'<li>{rec}</li>' for rec in finding['recommendations'])}
            </ul>
        </div>
        """

    def _update_log_summary(self):
        """Update the log analysis summary."""
        try:
            severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            category_counts = {}
            
            for finding in self.log_findings:
                severity_counts[finding['severity']] = severity_counts.get(finding['severity'], 0) + 1
                category_counts[finding['category']] = category_counts.get(finding['category'], 0) + 1
            
            summary = f"""
            <h4>Summary of Findings</h4>
            <p><strong>Total Findings:</strong> {len(self.log_findings)}</p>
            <p><strong>By Severity:</strong> HIGH: {severity_counts['HIGH']}, MEDIUM: {severity_counts['MEDIUM']}, LOW: {severity_counts['LOW']}</p>
            <p><strong>By Category:</strong> {', '.join(f'{cat}: {count}' for cat, count in category_counts.items())}</p>
            """
            
            self.log_summary_text.setHtml(summary)
            
        except Exception as e:
            self.handle_log_error(f"Error updating summary: {str(e)}")

    def _hex_to_rgb(self, hex_color):
        """Convert hex color to RGB values."""
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def fetch_installed_models(self):
        """Fetch the list of installed models from Ollama."""
        try:
            result = subprocess.run(['ollama', 'list'], capture_output=True, text=True, check=True)
            models = result.stdout.splitlines()  # Split output into lines
            return models
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error fetching installed models: {e.stderr}")
            return []  # Return an empty list on error

    def update_selected_model(self):
        """Update the selected model based on the dropdown selection."""
        selected_model = self.model_selection_dropdown.currentText()
        OLLAMA_CONFIG['model'] = selected_model
        self.logger.info(f"Selected model updated to: {selected_model}")
        
        # Update the label to show the currently selected model
        self.model_selection_label.setText(f"Current Model: {selected_model}")
        
        # Save the selected model to a config file
        with open('model_config.json', 'w') as f:
            json.dump({'model': selected_model}, f)

    def start_virus_scan(self):
        """Start a virus scan of the system."""
        # Create scanner instance
        self.scanner = VirusScanner()
        
        # Connect scanner signals
        self.scanner.scan_complete.connect(lambda files: self.handle_scan_complete(files, None))
        self.scanner.scan_error.connect(lambda error: self.handle_scan_error(error, None))
        
        # Show scan options dialog
        options_dialog = ScanOptionsDialog(self)
        result = options_dialog.exec()
        
        if result == QDialog.DialogCode.Rejected:
            return
            
        # Show directory selection dialog
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Directory to Scan",
            os.path.expanduser("~"),
            QFileDialog.Option.ShowDirsOnly
        )
        
        if not directory:
            return
            
        # Create progress dialog
        self.progress_dialog = ScanProgressDialog(self)
        
        try:
            # Start the scan
            self.scanner.start_scan(
                directory,
                progress_callback=self.progress_dialog.update_progress,
                status_callback=self.progress_dialog.add_status_message
            )
            
            # Show the progress dialog
            result = self.progress_dialog.exec()
            
            # Handle cancellation
            if result == QDialog.DialogCode.Rejected:
                self.scanner.stop_scan()
                return
                
        except Exception as e:
            self.handle_scan_error(str(e), self.progress_dialog)
            
    def handle_scan_complete(self, suspicious_files, progress_dialog):
        """Handle completion of virus scan."""
        if progress_dialog and progress_dialog.isVisible():
            progress_dialog.accept()
            
        if not suspicious_files:
            QMessageBox.information(
                self,
                "Scan Complete",
                "No suspicious files were found."
            )
            return
            
        # Show results dialog
        results_dialog = ScanResultsDialog(suspicious_files, self)
        results_dialog.exec()
        
    def handle_scan_error(self, error, progress_dialog):
        """Handle virus scan error."""
        if progress_dialog and progress_dialog.isVisible():
            progress_dialog.accept()
            
        QMessageBox.critical(
            self,
            "Scan Error",
            f"An error occurred during the scan: {error}"
        )
