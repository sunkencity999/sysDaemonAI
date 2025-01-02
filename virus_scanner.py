"""Virus scanning functionality for SysDaemon AI."""

import os
import hashlib
import threading
import queue
import json
import logging
import requests
import math
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from datetime import datetime
from collections import Counter
from PyQt6.QtCore import (QObject, pyqtSignal, pyqtSlot, QMetaObject, 
                         Qt, Q_ARG)
from PyQt6.QtWidgets import QApplication
import sys
import yara
import magic  # python-magic for file type detection
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import re
import shutil

@dataclass
class ThreatInfo:
    """Container for threat information."""
    is_suspicious: bool
    confidence: float
    reasons: List[str]
    threat_labels: List[str]

class ThreatIntelligence:
    """Handles threat intelligence operations."""
    
    def __init__(self):
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.otx_api_key = os.getenv('OTX_API_KEY')
        self.mb_api_key = os.getenv('MALWAREBAZAAR_API_KEY')
        
        # Initialize YARA rules
        self.yara_rules = None
        self.load_yara_rules()
        
        # Cache for hash lookups
        self.hash_cache = {}
        
        # Whitelist patterns for development files
        self.whitelist_patterns = [
            r'\.git/',
            r'node_modules/',
            r'venv/',
            r'\.venv/',
            r'__pycache__/',
            r'\.pytest_cache/',
            r'\.idea/',
            r'\.vscode/',
            r'\.npm/',
            r'\.yarn/',
            r'\.cargo/',
            r'target/debug/',
            r'target/release/',
            r'build/',
            r'dist/',
            r'\.pyc$',
            r'\.pyo$',
            r'\.pyd$',
            r'\.so$',
            r'\.dll$',
            r'\.dylib$',
            r'\.class$',
            r'\.jar$',
            r'package-lock\.json$',
            r'yarn\.lock$',
            r'Cargo\.lock$',
            r'poetry\.lock$',
        ]
        
        # Common source code file extensions
        self.source_code_extensions = {
            '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', 
            '.h', '.hpp', '.cs', '.rb', '.php', '.go', '.rs', '.swift',
            '.kt', '.kts', '.scala', '.clj', '.sql', '.sh', '.bash',
            '.zsh', '.fish', '.ps1', '.psm1', '.r', '.dart', '.lua'
        }
        
    def is_whitelisted(self, file_path: str) -> bool:
        """Check if a file path matches any whitelist pattern."""
        return any(re.search(pattern, file_path) for pattern in self.whitelist_patterns)
    
    def is_source_code(self, file_path: str) -> bool:
        """Check if a file is a source code file based on extension."""
        return os.path.splitext(file_path)[1].lower() in self.source_code_extensions

    def load_yara_rules(self):
        """Load YARA rules from the rules directory."""
        try:
            rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
            if os.path.exists(rules_dir):
                # Compile all .yar files in the rules directory
                rules_files = [os.path.join(rules_dir, f) for f in os.listdir(rules_dir) 
                             if f.endswith('.yar') or f.endswith('.yara')]
                if rules_files:
                    self.yara_rules = yara.compile(filepaths={
                        os.path.basename(f): f for f in rules_files
                    })
                    logging.info(f"Loaded YARA rules from: {', '.join(rules_files)}")
                else:
                    logging.warning("No .yar files found in rules directory")
                    self.yara_rules = None
        except Exception as e:
            logging.error(f"Failed to load YARA rules: {e}")
            self.yara_rules = None

    def _evaluate_threat(self, threat_info: ThreatInfo, is_source: bool = False) -> bool:
        """Evaluate if a file is suspicious based on its threat info."""
        if not threat_info:
            return False
        threshold = 0.7 if is_source else 0.5
        return threat_info.confidence >= threshold

    async def check_file_threat(self, file_path: str) -> ThreatInfo:
        """Check if a file is a threat using multiple sources."""
        threat_info = ThreatInfo(
            is_suspicious=False,
            confidence=0.0,
            reasons=[],
            threat_labels=[]
        )
        
        try:
            # Skip whitelisted paths
            if self.is_whitelisted(file_path):
                return threat_info
                
            # Get file metadata
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB for initial checks
                file_hash = hashlib.sha256(content).hexdigest()
            
            # Skip large files
            if file_size > 50 * 1024 * 1024:  # 50MB
                return threat_info
                
            # Check file type
            file_type = magic.from_buffer(content)
            is_source = self.is_source_code(file_path)
            
            # Adjust confidence for executables
            if any(ft in file_type.lower() for ft in ['executable', 'script', 'macro']):
                if not is_source:  # Don't flag source code files
                    threat_info.confidence += 0.2
                    threat_info.reasons.append(f"Suspicious file type: {file_type}")
            
            # Check YARA rules
            if self.yara_rules:
                matches = self.yara_rules.match(data=content)
                if matches:
                    # Reduce confidence for source code files
                    confidence_boost = 0.2 if is_source else 0.4
                    threat_info.confidence += confidence_boost
                    threat_info.reasons.extend([f"YARA rule match: {m.rule}" for m in matches])
                    threat_info.threat_labels.extend([m.rule for m in matches])
            
            # Check VirusTotal if API key is available
            if self.vt_api_key:
                vt_results = await self._check_virustotal(file_hash)
                if vt_results.get('positives', 0) > 0:
                    # Reduce confidence for source code files
                    max_confidence = 0.4 if is_source else 0.8
                    threat_info.confidence += min(vt_results['positives'] / vt_results['total'], max_confidence)
                    threat_info.reasons.append(f"VirusTotal detections: {vt_results['positives']}/{vt_results['total']}")
                    threat_info.threat_labels.extend(vt_results.get('threat_labels', []))
            
            # Check entropy for potential packing/encryption
            entropy = self._calculate_entropy(content)
            if entropy > 7.0:
                # Don't count high entropy against source code files
                if not is_source:
                    threat_info.confidence += 0.3
                    threat_info.reasons.append(f"High entropy ({entropy:.2f})")
            
            # Check for suspicious patterns
            if self._check_suspicious_patterns(content):
                # Reduce confidence for source code files
                confidence_boost = 0.2 if is_source else 0.4
                threat_info.confidence += confidence_boost
                threat_info.reasons.append("Contains suspicious patterns")
            
            # Set final suspicious status based on confidence threshold
            threat_info.is_suspicious = self._evaluate_threat(threat_info, is_source)
            
            # If confidence is 0%, clear the reasons list
            if threat_info.confidence == 0:
                threat_info.reasons = []
                threat_info.threat_labels = []
            
        except Exception as e:
            logging.error(f"Error checking file threat {file_path}: {e}")
            
        return threat_info

    async def _check_virustotal(self, file_hash: str) -> Dict:
        """Check a file hash against VirusTotal."""
        if not self.vt_api_key:
            return {}
            
        cache_key = f"vt_{file_hash}"
        if cache_key in self.hash_cache:
            return self.hash_cache[cache_key]
            
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.vt_api_key,
                'resource': file_hash
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.hash_cache[cache_key] = result
                        return result
        except Exception as e:
            logging.error(f"VirusTotal API error: {e}")
        return {}

    def _check_suspicious_patterns(self, content: bytes) -> bool:
        """Check for suspicious patterns in file content."""
        suspicious_patterns = [
            b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            b'CreateRemoteThread',
            b'VirtualAlloc',
            b'WriteProcessMemory',
            b'cmd.exe /c ',
            b'powershell -e',
            b'WScript.Shell',
            b'eval(',
            b'base64_decode',
            b'system(',
            b'exec(',
            b'shell_exec',
        ]
        return any(pattern in content for pattern in suspicious_patterns)

    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        byte_counts = Counter(data)
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        return entropy

    def get_threat_info(self, file_path: str) -> ThreatInfo:
        """Get threat information for a file."""
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            threat_info = loop.run_until_complete(self.check_file_threat(file_path))
            loop.close()
            
            # Ensure we use the same evaluation logic
            is_source = self.is_source_code(file_path)
            threat_info.is_suspicious = self._evaluate_threat(threat_info, is_source)
            
            return threat_info
        except Exception as e:
            logging.error(f"Failed to get threat info for {file_path}: {e}")
            return None

class VirusScanner(QObject):
    """Handles virus scanning operations."""
    
    # Signals for UI updates
    scan_progress = pyqtSignal(int, str)  # Progress percentage, current file
    scan_complete = pyqtSignal(list)  # List of suspicious files
    scan_error = pyqtSignal(str)  # Error message
    scan_permission_error = pyqtSignal(str)  # Permission error message

    def __init__(self):
        super().__init__()
        self.threat_intel = ThreatIntelligence()
        self.quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # Create quarantine metadata file
        self.quarantine_db = os.path.join(self.quarantine_dir, 'quarantine.json')
        if not os.path.exists(self.quarantine_db):
            with open(self.quarantine_db, 'w') as f:
                json.dump({}, f)

        self.scan_directory = None
        self.scan_thread = None
        self.is_scanning = False
        self.suspicious_files = []
        self._progress_callback = None
        self._status_callback = None
        # Move to main thread if Qt application exists
        app = QApplication.instance()
        if app is not None:
            self.moveToThread(app.thread())

    def start_scan(self, directory, progress_callback=None, status_callback=None):
        """Start a virus scan of the specified directory."""
        if self.is_scanning:
            if status_callback:
                status_callback("A scan is already in progress")
            self.scan_error.emit("A scan is already in progress")
            return

        self.scan_directory = directory
        self.is_scanning = True
        self.suspicious_files = []
        self._progress_callback = progress_callback
        self._status_callback = status_callback
        
        # Create and start the scan thread
        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(directory,)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def stop_scan(self):
        """Stop the current scan."""
        self.is_scanning = False
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=1.0)
            QMetaObject.invokeMethod(self, "_emit_scan_error",
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(str, "Scan stopped by user"))

    def _emit_scan_progress(self, progress: int, file_path: str):
        """Safely emit scan progress signal from any thread."""
        self.scan_progress.emit(progress, file_path)
        if hasattr(self, '_progress_callback') and self._progress_callback:
            QMetaObject.invokeMethod(self, "_do_progress_callback",
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(int, progress),
                                   Q_ARG(str, file_path))

    def _emit_scan_complete(self, suspicious_files: list):
        """Safely emit scan complete signal from any thread."""
        self.scan_complete.emit(suspicious_files)

    def _emit_scan_error(self, error: str):
        """Safely emit scan error signal from any thread."""
        self.scan_error.emit(error)
        if hasattr(self, '_status_callback') and self._status_callback:
            QMetaObject.invokeMethod(self, "_do_status_callback",
                                   Qt.ConnectionType.QueuedConnection,
                                   Q_ARG(str, error))

    @pyqtSlot(int, str)
    def _do_progress_callback(self, progress: int, file_path: str):
        """Execute progress callback in main thread."""
        if self._progress_callback:
            self._progress_callback(progress, file_path)

    @pyqtSlot(str)
    def _do_status_callback(self, message: str):
        """Execute status callback in main thread."""
        if self._status_callback:
            self._status_callback(message)

    def _scan_worker(self, directory: str):
        """Worker thread for scanning files."""
        try:
            total_files = 0
            scanned_files = 0

            # First pass: count total files
            for root, _, files in os.walk(directory):
                total_files += len(files)

            if self._status_callback:
                QMetaObject.invokeMethod(self, "_do_status_callback",
                                       Qt.ConnectionType.QueuedConnection,
                                       Q_ARG(str, f"Found {total_files} files to scan"))

            # Second pass: scan files
            for root, _, files in os.walk(directory):
                if not self.is_scanning:
                    return

                for file in files:
                    if not self.is_scanning:
                        return

                    file_path = os.path.join(root, file)
                    try:
                        # Update progress
                        scanned_files += 1
                        progress = int((scanned_files / total_files) * 100)
                        
                        # Emit progress updates
                        self._emit_scan_progress(progress, file_path)

                        # Check if file is suspicious
                        if self._is_file_suspicious(file_path):
                            self.suspicious_files.append(file_path)
                            if self._status_callback:
                                QMetaObject.invokeMethod(self, "_do_status_callback",
                                                       Qt.ConnectionType.QueuedConnection,
                                                       Q_ARG(str, f"Found suspicious file: {file_path}"))
                            
                    except (PermissionError, OSError) as e:
                        error_msg = f"Could not access file {file_path}: {e}"
                        logging.warning(error_msg)
                        if self._status_callback:
                            QMetaObject.invokeMethod(self, "_do_status_callback",
                                                   Qt.ConnectionType.QueuedConnection,
                                                   Q_ARG(str, error_msg))
                        continue

            if self.is_scanning:  # Only emit completion if we weren't stopped
                if self._status_callback:
                    QMetaObject.invokeMethod(self, "_do_status_callback",
                                           Qt.ConnectionType.QueuedConnection,
                                           Q_ARG(str, f"Scan complete. Found {len(self.suspicious_files)} suspicious files."))
                self._emit_scan_complete(self.suspicious_files)

        except Exception as e:
            error_msg = f"Error during scan: {str(e)}"
            logging.exception("Error during scan")
            self._emit_scan_error(error_msg)
        finally:
            self.is_scanning = False

    def _is_file_suspicious(self, file_path: str) -> bool:
        """
        Check if a file is suspicious.
        Returns True if the file exhibits suspicious characteristics.
        """
        try:
            # Skip files that are too large (> 50MB)
            if os.path.getsize(file_path) > 50 * 1024 * 1024:
                return False

            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()

            # Check for suspicious patterns
            suspicious_patterns = [
                b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',  # EICAR test file
                b'CreateRemoteThread',  # Potential process injection
                b'VirtualAlloc',  # Potential memory manipulation
                b'WriteProcessMemory',  # Potential process manipulation
                b'cmd.exe /c ',  # Command execution
                b'powershell -e',  # Encoded PowerShell
                b'WScript.Shell',  # Potential script execution
                b'eval(',  # Potential code execution
                b'base64_decode',  # Potential obfuscation
                b'system(',  # System command execution
                b'exec(',  # Code execution
                b'shell_exec',  # Shell command execution
            ]

            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if pattern in content:
                    return True

            # Check file entropy (high entropy might indicate encryption/packing)
            entropy = self._calculate_entropy(content)
            if entropy > 7.0:  # High entropy threshold
                return True

            # Check threat intelligence
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            threat_info = loop.run_until_complete(self.threat_intel.check_file_threat(file_path))
            if threat_info.is_suspicious:
                return True

            return False

        except (PermissionError, OSError) as e:
            logging.warning(f"Could not analyze file {file_path}: {e}")
            return False

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate the Shannon entropy of data."""
        if not data:
            return 0.0

        # Count byte occurrences
        byte_counts = Counter(data)
        file_size = len(data)
        
        # Calculate entropy
        entropy = 0
        for count in byte_counts.values():
            probability = count / file_size
            entropy -= probability * math.log2(probability)
            
        return entropy

    def get_threat_info(self, file_path: str) -> ThreatInfo:
        """Get threat information for a file."""
        try:
            import asyncio
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            threat_info = loop.run_until_complete(self.threat_intel.check_file_threat(file_path))
            loop.close()
            return threat_info
        except Exception as e:
            logging.error(f"Failed to get threat info for {file_path}: {e}")
            return None

    def quarantine_file(self, file_path: str, threat_info: ThreatInfo = None) -> tuple[bool, str]:
        """
        Quarantine a suspicious file by moving it to the quarantine directory
        and storing metadata about the threat.
        
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # If threat_info wasn't provided, check the file
            if threat_info is None:
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                threat_info = loop.run_until_complete(self.threat_intel.check_file_threat(file_path))
                loop.close()
            
            if not threat_info.is_suspicious:
                return False, "File is not suspicious"
            
            # Generate a unique quarantine filename
            file_hash = hashlib.sha256(open(file_path, 'rb').read()).hexdigest()
            quarantine_name = f"{file_hash}_{os.path.basename(file_path)}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Load existing quarantine metadata
            with open(self.quarantine_db, 'r') as f:
                quarantine_meta = json.load(f)
            
            # Add metadata about the quarantined file
            quarantine_meta[quarantine_name] = {
                'original_path': file_path,
                'quarantine_date': datetime.now().isoformat(),
                'threat_info': {
                    'confidence': threat_info.confidence,
                    'reasons': threat_info.reasons,
                    'threat_labels': threat_info.threat_labels
                },
                'file_hash': file_hash
            }
            
            # Move the file to quarantine
            shutil.move(file_path, quarantine_path)
            
            # Update quarantine metadata
            with open(self.quarantine_db, 'w') as f:
                json.dump(quarantine_meta, f, indent=2)
            
            msg = f"Successfully quarantined file {file_path}"
            logging.info(f"{msg} -> {quarantine_path}")
            return True, msg
            
        except Exception as e:
            msg = f"Failed to quarantine file {file_path}: {e}"
            logging.error(msg)
            return False, msg
            
    def restore_file(self, quarantine_name: str) -> bool:
        """
        Restore a file from quarantine to its original location.
        """
        try:
            # Load quarantine metadata
            with open(self.quarantine_db, 'r') as f:
                quarantine_meta = json.load(f)
            
            if quarantine_name not in quarantine_meta:
                logging.error(f"File {quarantine_name} not found in quarantine database")
                return False
            
            file_meta = quarantine_meta[quarantine_name]
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            original_path = file_meta['original_path']
            
            # Verify file hash hasn't changed
            current_hash = hashlib.sha256(open(quarantine_path, 'rb').read()).hexdigest()
            if current_hash != file_meta['file_hash']:
                logging.error(f"File hash mismatch for {quarantine_name}")
                return False
            
            # Create original directory if it doesn't exist
            os.makedirs(os.path.dirname(original_path), exist_ok=True)
            
            # Move file back to original location
            shutil.move(quarantine_path, original_path)
            
            # Remove from quarantine metadata
            del quarantine_meta[quarantine_name]
            with open(self.quarantine_db, 'w') as f:
                json.dump(quarantine_meta, f, indent=2)
            
            logging.info(f"Restored file {quarantine_name} -> {original_path}")
            return True
            
        except Exception as e:
            logging.error(f"Failed to restore file {quarantine_name}: {e}")
            return False

    def list_quarantined_files(self) -> dict:
        """
        Return a list of quarantined files and their metadata.
        """
        try:
            with open(self.quarantine_db, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Failed to list quarantined files: {e}")
            return {}

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner = VirusScanner()
    scanner.start_scan("/path/to/directory")
    sys.exit(app.exec())
