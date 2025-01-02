"""Elevated permission virus scanner without Qt dependencies."""

import os
import sys
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

class ElevatedScanner:
    """Simplified scanner for elevated permission scans."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.quarantine_dir = Path(os.path.expanduser("~/.sysdaemon/quarantine"))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Load virus signatures
        self.signatures = self._load_signatures()
        
    def _load_signatures(self) -> Dict[str, str]:
        """Load virus signatures from file."""
        signature_file = Path(__file__).parent / "data" / "virus_signatures.json"
        if signature_file.exists():
            try:
                with open(signature_file) as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading signatures: {e}", file=sys.stderr)
        return {}

    def _scan_file(self, filepath: Path) -> bool:
        """Scan a single file for potential threats."""
        try:
            # Skip files larger than 100MB for performance
            if filepath.stat().st_size > 100_000_000:
                return False

            # Calculate file hash
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()

            # Check against known signatures
            if file_hash in self.signatures:
                return True

            # Basic heuristic checks for text files
            if self._is_text_file(filepath):
                try:
                    with open(filepath, "rb") as f:
                        content = f.read(4096)
                        suspicious_patterns = [
                            b"CreateRemoteThread",
                            b"VirtualAlloc",
                            b"WriteProcessMemory",
                            b"ShellExecute",
                            b"WScript.Shell",
                        ]
                        return any(pattern in content for pattern in suspicious_patterns)
                except Exception:
                    pass

            return False

        except Exception as e:
            print(f"Error scanning {filepath}: {e}", file=sys.stderr)
            return False

    def _is_text_file(self, filepath: Path) -> bool:
        """Check if a file is likely to be a text file."""
        try:
            text_extensions = {'.txt', '.py', '.js', '.html', '.css', '.json', '.xml', '.csv', '.log', '.sh', '.bat', '.ps1'}
            if filepath.suffix.lower() in text_extensions:
                return True
                
            with open(filepath, 'rb') as f:
                chunk = f.read(1024)
                return not bool(b'\x00' in chunk)
        except Exception:
            return False

    def scan_directory(self, directory: str) -> List[str]:
        """
        Scan a directory for suspicious files.
        Returns a list of suspicious file paths.
        """
        suspicious_files = []
        try:
            directory_path = Path(directory)
            total_files = sum(1 for _ in directory_path.rglob("*") if _.is_file())
            scanned_files = 0
            
            for filepath in directory_path.rglob("*"):
                if filepath.is_file():
                    try:
                        print(f"Scanning: {filepath}", file=sys.stderr)
                        if self._scan_file(filepath):
                            suspicious_files.append(str(filepath))
                        
                        scanned_files += 1
                        progress = int((scanned_files / total_files) * 100)
                        print(f"Progress: {progress}%", file=sys.stderr)
                        
                    except Exception as e:
                        print(f"Error scanning {filepath}: {e}", file=sys.stderr)

        except Exception as e:
            print(f"Error during scan: {e}", file=sys.stderr)

        return suspicious_files

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sudo python3 elevated_scanner.py <directory>", file=sys.stderr)
        sys.exit(1)
        
    scanner = ElevatedScanner()
    directory = sys.argv[1]
    
    print(f"Starting scan of directory: {directory}", file=sys.stderr)
    
    try:
        suspicious_files = scanner.scan_directory(directory)
        result = {
            "suspicious_files": suspicious_files,
            "total_found": len(suspicious_files)
        }
        print("SCAN_RESULTS_START", file=sys.stderr)
        print(json.dumps(result))
        print("SCAN_RESULTS_END", file=sys.stderr)
    except Exception as e:
        print(f"Fatal error in elevated scanner: {str(e)}", file=sys.stderr)
        sys.exit(1)
