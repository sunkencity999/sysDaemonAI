#!/usr/bin/env python3
"""Helper script for running elevated virus scans."""

import os
import sys
from pathlib import Path

def check_elevated_privileges():
    """Check if we actually have elevated privileges."""
    try:
        # Try to read a protected directory
        test_paths = [
            '/var/root',
            '/System/Library/PrivateFrameworks',
            '/private/var/root'
        ]
        for path in test_paths:
            try:
                os.listdir(path)
                return True
            except:
                continue
        return False
    except:
        return False

def scan_directory(directory: str):
    """Perform the elevated scan."""
    try:
        print(f"Starting elevated scan of {directory}", file=sys.stderr)
        
        # Check actual privileges
        is_elevated = check_elevated_privileges()
        euid = os.geteuid()
        print(f"Privilege check - Elevated: {is_elevated}", file=sys.stderr)
        print(f"Current effective UID: {euid}", file=sys.stderr)
        
        if not is_elevated or euid != 0:
            print("Error: Not running with elevated privileges", file=sys.stderr)
            sys.exit(1)
        
        # Import here to avoid GUI initialization
        from virus_scanner import VirusScanner
        import signal
        
        # Set up signal handler for clean shutdown
        def signal_handler(signum, frame):
            print(f"Received signal {signum}", file=sys.stderr)
            sys.exit(1)
        
        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        
        scanner = VirusScanner()
        scanner.elevated_mode = True
        
        # Track scan progress
        files_scanned = 0
        suspicious_found = []
        
        def print_progress(progress: int, current_file: str):
            nonlocal files_scanned
            files_scanned += 1
            if progress >= 0:
                print(f"PROGRESS:{progress}", file=sys.stderr)
            print(f"FILE:{current_file}", file=sys.stderr)
        
        def print_complete(suspicious_files: list):
            nonlocal suspicious_found
            suspicious_found.extend(suspicious_files)
            for file in suspicious_files:
                print(f"SUSPICIOUS:{file}", file=sys.stderr)
        
        def print_error(error: str):
            print(f"ERROR:{error}", file=sys.stderr)
        
        scanner.scan_progress.connect(print_progress)
        scanner.scan_complete.connect(print_complete)
        scanner.scan_error.connect(print_error)
        
        print("Starting scan worker...", file=sys.stderr)
        scanner._scan_worker([directory])
        
        print(f"Scan statistics:", file=sys.stderr)
        print(f"Files scanned: {files_scanned}", file=sys.stderr)
        print(f"Suspicious files found: {len(suspicious_found)}", file=sys.stderr)
        print("Scan completed successfully", file=sys.stderr)
        
    except Exception as e:
        import traceback
        print(f"Error in elevated scan: {str(e)}", file=sys.stderr)
        print(f"Traceback: {traceback.format_exc()}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: elevated_helper.py <directory>", file=sys.stderr)
        sys.exit(1)
    
    directory = sys.argv[1]
    scan_directory(directory)
