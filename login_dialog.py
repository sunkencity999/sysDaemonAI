#!/usr/bin/env python3
from PyQt6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                          QLineEdit, QPushButton, QMessageBox, QApplication)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QIcon
import logging
from auth_manager import AuthManager

class LoginDialog(QDialog):
    login_successful = pyqtSignal(str)  # Emits JWT token on successful login
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.auth_manager = AuthManager()
        self.logger = logging.getLogger(__name__)
        self.auth_token = None
        self.setup_ui()
        
    def setup_ui(self):
        self.setWindowTitle("SysDaemon AI - Login")
        self.setFixedSize(400, 300)  # Increased height to accommodate new elements
        
        # Main layout
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Title
        title = QLabel("SysDaemon AI")
        title.setStyleSheet("""
            QLabel {
                color: #4a9eff;
                font-size: 24px;
                font-weight: bold;
            }
        """)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Subtitle
        subtitle = QLabel("Enterprise Security Suite")
        subtitle.setStyleSheet("QLabel { color: #999999; }")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)
        
        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        username_label.setFixedWidth(80)
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username")
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        password_label.setFixedWidth(80)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Confirm Password (initially hidden)
        confirm_password_layout = QHBoxLayout()
        confirm_password_label = QLabel("Confirm:")
        confirm_password_label.setFixedWidth(80)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        confirm_password_layout.addWidget(confirm_password_label)
        confirm_password_layout.addWidget(self.confirm_password_input)
        layout.addLayout(confirm_password_layout)
        self.confirm_password_input.hide()
        confirm_password_label.hide()
        
        # Buttons layout
        buttons_layout = QHBoxLayout()
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.clicked.connect(self.try_login)
        self.login_button.setStyleSheet("""
            QPushButton {
                background-color: #4a9eff;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 4px;
                width: 100px;
            }
            QPushButton:hover {
                background-color: #3a8eef;
            }
            QPushButton:pressed {
                background-color: #2a7edf;
            }
        """)
        buttons_layout.addWidget(self.login_button)
        
        # Register button
        self.register_button = QPushButton("Register")
        self.register_button.clicked.connect(self.toggle_register_mode)
        self.register_button.setStyleSheet("""
            QPushButton {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #4a9eff;
                padding: 8px;
                border-radius: 4px;
                width: 100px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
            QPushButton:pressed {
                background-color: #1a1a1a;
            }
        """)
        buttons_layout.addWidget(self.register_button)
        
        layout.addLayout(buttons_layout)
        
        # Set dialog layout
        self.setLayout(layout)
        
        # Set window style for dark theme
        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
            }
            QLabel {
                color: #ffffff;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QLineEdit:focus {
                border: 1px solid #4a9eff;
            }
        """)
        
        # Track registration mode
        self.register_mode = False
        
    def toggle_register_mode(self):
        self.register_mode = not self.register_mode
        if self.register_mode:
            self.confirm_password_input.show()
            self.confirm_password_input.parentWidget().show()
            self.login_button.setText("Create Account")
            self.register_button.setText("Back to Login")
        else:
            self.confirm_password_input.hide()
            self.confirm_password_input.parentWidget().hide()
            self.login_button.setText("Login")
            self.register_button.setText("Register")
            
    def try_login(self):
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Error", "Please enter both username and password")
            return
            
        if self.register_mode:
            confirm_password = self.confirm_password_input.text()
            if password != confirm_password:
                QMessageBox.warning(self, "Error", "Passwords do not match")
                return
                
            try:
                if self.auth_manager.register(username, password):
                    QMessageBox.information(self, "Success", "Account created successfully!")
                    # Automatically authenticate after successful registration
                    token = self.auth_manager.authenticate(username, password)
                    if token:
                        self.auth_token = token
                        self.login_successful.emit(token)
                        self.accept()
                    else:
                        QMessageBox.critical(self, "Error", "Registration successful but automatic login failed")
                else:
                    QMessageBox.warning(self, "Error", "Username already exists")
            except Exception as e:
                self.logger.error(f"Registration error: {str(e)}")
                QMessageBox.critical(self, "Error", f"Registration failed: {str(e)}")
        else:
            try:
                token = self.auth_manager.authenticate(username, password)
                if token:
                    self.auth_token = token
                    self.login_successful.emit(token)
                    self.accept()
                else:
                    QMessageBox.warning(self, "Error", "Invalid username or password")
            except Exception as e:
                self.logger.error(f"Login error: {str(e)}")
                QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")

if __name__ == "__main__":
    app = QApplication([])
    dialog = LoginDialog()
    dialog.show()
    app.exec()
