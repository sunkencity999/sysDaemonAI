"""UI components for virus scanning functionality."""

import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                           QPushButton, QProgressBar, QFileDialog, 
                           QTableWidget, QTableWidgetItem, QMessageBox,
                           QDialog, QTextEdit)
from PyQt6.QtCore import (Qt, pyqtSlot, QMetaObject, Q_ARG)
from virus_scanner import VirusScanner
import logging

class ScanProgressDialog(QDialog):
    """Dialog showing scan progress."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Virus Scan Progress")
        self.setModal(True)
        self.resize(500, 200)  

        # Create layout
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Current file label
        self.current_file_label = QLabel("Preparing scan...")
        self.current_file_label.setWordWrap(True)
        layout.addWidget(self.current_file_label)

        # Status text area
        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        self.status_text.setMaximumHeight(100)
        layout.addWidget(self.status_text)

        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

    @pyqtSlot(int, str)
    def update_progress(self, percentage: int, current_file: str):
        """Update progress bar and current file label."""
        if not self.isVisible():
            return
        # Direct update since this should be called from main thread
        self.progress_bar.setValue(percentage)
        self.current_file_label.setText(f"Scanning: {current_file}")

    @pyqtSlot(str)
    def add_status_message(self, message: str):
        """Add a status message to the text area."""
        if not self.isVisible():
            return
        # Direct update since this should be called from main thread
        self.status_text.append(message)
        # Scroll to the bottom
        scrollbar = self.status_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


class ScanOptionsDialog(QDialog):
    """Dialog for configuring scan options."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Options")
        self.setModal(True)
        self.resize(400, 200)

        # Create layout
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Add description
        description = QLabel(
            "This will scan files and directories that are accessible "
            "with your current user permissions."
        )
        description.setWordWrap(True)
        layout.addWidget(description)

        # Add scan button
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(lambda: self.done(1))
        layout.addWidget(self.scan_button)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)


class ScanResultsDialog(QDialog):
    """Dialog showing scan results."""
    
    def __init__(self, suspicious_files, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Results")
        self.setModal(True)
        self.resize(600, 400)
        self.scanner = VirusScanner()

        # Create layout
        layout = QVBoxLayout()
        self.setLayout(layout)

        # Add results table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["File Path", "Confidence", "Reasons", "Action"])
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table)

        # Populate table
        for filepath in suspicious_files:
            self.add_suspicious_file(filepath)

        # Add close button
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

    def add_suspicious_file(self, filepath: str):
        """Add a suspicious file to the results table."""
        try:
            # Get threat information
            threat_info = self.scanner.get_threat_info(filepath)
            
            # Skip files that aren't suspicious
            if not threat_info or not threat_info.is_suspicious:
                return
                
            row = self.table.rowCount()
            self.table.insertRow(row)
            
            # File path
            path_item = QTableWidgetItem(filepath)
            path_item.setToolTip(filepath)
            self.table.setItem(row, 0, path_item)
            
            # Threat level (confidence)
            confidence = f"{threat_info.confidence:.2%}"
            confidence_item = QTableWidgetItem(confidence)
            self.table.setItem(row, 1, confidence_item)
            
            # Threat reasons
            reasons = "\n".join(threat_info.reasons) if threat_info.reasons else "Unknown"
            reasons_item = QTableWidgetItem(reasons)
            reasons_item.setToolTip(reasons)
            self.table.setItem(row, 2, reasons_item)
            
            # Action buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(4, 4, 4, 4)
            
            # Quarantine button
            quarantine_button = QPushButton("Quarantine")
            quarantine_button.clicked.connect(lambda: self.quarantine_file(filepath))
            action_layout.addWidget(quarantine_button)
            
            # View details button
            details_button = QPushButton("Details")
            details_button.clicked.connect(lambda: self.show_file_details(filepath))
            action_layout.addWidget(details_button)
            
            self.table.setCellWidget(row, 3, action_widget)
            
        except Exception as e:
            logging.error(f"Error adding suspicious file to table: {e}")

    def show_file_details(self, filepath: str):
        """Show detailed information about a suspicious file."""
        try:
            threat_info = self.scanner.get_threat_info(filepath)
            if not threat_info:
                QMessageBox.warning(self, "Warning", "No threat information available for this file.")
                return
                
            details = f"""
File: {filepath}
Confidence: {threat_info.confidence:.2%}

Reasons:
{chr(10).join(f'- {reason}' for reason in threat_info.reasons)}

Threat Labels:
{chr(10).join(f'- {label}' for label in threat_info.threat_labels)}
"""
            
            msg = QMessageBox(self)
            msg.setWindowTitle("File Details")
            msg.setText(details)
            msg.setIcon(QMessageBox.Icon.Information)
            msg.exec()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to show file details: {e}")

    def quarantine_file(self, filepath: str):
        """Quarantine a suspicious file."""
        try:
            # Get current threat info
            threat_info = self.scanner.get_threat_info(filepath)
            if not threat_info:
                QMessageBox.warning(self, "Warning", "Could not evaluate file threat status")
                return
                
            success, message = self.scanner.quarantine_file(filepath, threat_info)
            if success:
                QMessageBox.information(self, "Success", message)
                # Remove the file from the results list
                for i in range(self.table.rowCount()):
                    item = self.table.item(i, 0)
                    if item and item.text() == filepath:
                        self.table.removeRow(i)
                        break
            else:
                QMessageBox.warning(self, "Warning", message)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to quarantine file: {e}")
