#!/usr/bin/env python3
import os
import sys
import subprocess
import platform
import json
import getpass
import signal
import atexit
from pathlib import Path
import time
import tempfile

# Global variables for cleanup
TEMP_FILES = []
PROCESSES_TO_KILL = []

def cleanup():
    """Clean up temporary files and processes on exit"""
    print("\nCleaning up...")
    
    # Clean up temporary files
    for temp_file in TEMP_FILES:
        try:
            if os.path.exists(temp_file):
                os.remove(temp_file)
                print(f"Removed temporary file: {temp_file}")
        except Exception as e:
            print(f"Error removing temporary file {temp_file}: {e}")
    
    # Kill any remaining processes
    for process in PROCESSES_TO_KILL:
        try:
            if process.poll() is None:  # Process is still running
                process.terminate()
                time.sleep(0.5)
                if process.poll() is None:
                    process.kill()
                print(f"Terminated process: {process.pid}")
        except Exception as e:
            print(f"Error terminating process {process.pid}: {e}")

def signal_handler(signum, frame):
    """Handle interruption signals"""
    print("\n\nReceived interrupt signal. Cleaning up...")
    cleanup()
    print("\nSetup interrupted. You can run the script again to continue setup.")
    sys.exit(1)

# Register cleanup functions
atexit.register(cleanup)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class SetupError(Exception):
    """Custom exception for setup errors"""
    pass

def print_step(step, message):
    """Print a formatted step message"""
    print(f"\n[{step}] {message}")
    print("=" * 80)

def run_command(command, shell=False, timeout=None):
    """Run a command and return its output with better error handling"""
    try:
        if shell:
            process = subprocess.Popen(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            process = subprocess.Popen(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        PROCESSES_TO_KILL.append(process)
        stdout, stderr = process.communicate(timeout=timeout)
        PROCESSES_TO_KILL.remove(process)
        
        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        
        return stdout.strip()
    except subprocess.TimeoutExpired:
        process.kill()
        raise SetupError(f"Command timed out: {command}")
    except subprocess.CalledProcessError as e:
        raise SetupError(f"Command failed: {e.stderr}")
    except Exception as e:
        raise SetupError(f"Error running command: {str(e)}")

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    print_step(1, "Checking Python version")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        raise SetupError(f"Python 3.8 or higher is required. Current version: {sys.version}")
    print("✓ Python version check passed")

def install_requirements():
    """Install Python package requirements"""
    print_step(2, "Installing Python packages")
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        raise SetupError("requirements.txt not found")
    
    try:
        # Create a temporary file for pip output
        with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp:
            TEMP_FILES.append(temp.name)
            process = subprocess.Popen(
                [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"],
                stdout=temp,
                stderr=subprocess.STDOUT,
                text=True
            )
            PROCESSES_TO_KILL.append(process)
            process.wait()
            PROCESSES_TO_KILL.remove(process)
            
            if process.returncode != 0:
                with open(temp.name, 'r') as f:
                    error_output = f.read()
                raise SetupError(f"Failed to install requirements:\n{error_output}")
    
        print("✓ Python packages installed successfully")
    except Exception as e:
        raise SetupError(f"Error installing requirements: {str(e)}")

def check_install_ollama():
    """Check and install Ollama if needed"""
    print_step(3, "Checking Ollama installation")
    
    if platform.system() != "Darwin":
        raise SetupError("This script currently only supports macOS")
    
    try:
        ollama_path = run_command(["which", "ollama"])
        if not ollama_path:
            print("Ollama not found. Installing...")
            # Create a temporary file for installation output
            with tempfile.NamedTemporaryFile(delete=False, suffix='.log') as temp:
                TEMP_FILES.append(temp.name)
                install_cmd = f"curl https://ollama.ai/install.sh | tee {temp.name} | sh"
                run_command(install_cmd, shell=True, timeout=300)
            print("✓ Ollama installed successfully")
        else:
            print("✓ Ollama is already installed")
        
        print("\nPulling required Ollama model...")
        run_command(["ollama", "pull", "llama2"], timeout=600)
        print("✓ Ollama model pulled successfully")
    except Exception as e:
        raise SetupError(f"Error with Ollama setup: {str(e)}")

def setup_api_keys():
    """Setup API keys in environment"""
    print_step(4, "Setting up API keys")
    
    try:
        env_file = Path(".env")
        env_vars = {}
        
        # Backup existing .env file if it exists
        if env_file.exists():
            backup_file = f".env.backup.{int(time.time())}"
            env_file.rename(backup_file)
            TEMP_FILES.append(backup_file)
            with open(backup_file, "r") as f:
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        env_vars[key] = value.strip('"').strip("'")
        
        # AbuseIPDB API key
        if "ABUSEIPDB_API_KEY" not in env_vars:
            print("\nAbuseIPDB API key is required for malicious IP detection.")
            print("Get your API key at: https://www.abuseipdb.com/api")
            api_key = getpass.getpass("Enter your AbuseIPDB API key: ")
            if not api_key:
                raise SetupError("API key is required")
            env_vars["ABUSEIPDB_API_KEY"] = api_key
        
        # Write environment variables to .env file
        with open(env_file, "w") as f:
            for key, value in env_vars.items():
                f.write(f'{key}="{value}"\n')
        
        print("✓ API keys configured successfully")
    except Exception as e:
        raise SetupError(f"Error setting up API keys: {str(e)}")

def check_permissions():
    """Check for necessary system permissions"""
    print_step(5, "Checking system permissions")
    
    try:
        if os.geteuid() != 0:
            print("Note: Some features may require administrative privileges.")
            print("You may need to run the application with 'sudo' for full functionality.")
        else:
            print("✓ Running with administrative privileges")
    except Exception as e:
        raise SetupError(f"Error checking permissions: {str(e)}")

def create_config():
    """Create default configuration file"""
    print_step(6, "Creating configuration file")
    
    config = {
        "monitoring": {
            "cpu_alert_threshold": 75,
            "memory_alert_threshold": 75,
            "disk_alert_threshold": 75,
            "network_latency_threshold": 200,
            "bandwidth_spike_multiplier": 2
        },
        "security": {
            "malicious_ip_cache_duration": 3600,
            "abuseipdb_confidence_score": 90,
            "alert_cooldown": 300
        },
        "ui": {
            "refresh_interval": 5000,
            "max_history_points": 100,
            "dark_mode": True
        }
    }
    
    try:
        config_file = Path("config.json")
        if not config_file.exists():
            # Create a backup of the config if it exists
            if config_file.exists():
                backup_file = f"config.json.backup.{int(time.time())}"
                config_file.rename(backup_file)
                TEMP_FILES.append(backup_file)
            
            with open(config_file, "w") as f:
                json.dump(config, f, indent=4)
            print("✓ Default configuration file created")
        else:
            print("✓ Configuration file already exists")
    except Exception as e:
        raise SetupError(f"Error creating configuration: {str(e)}")

def main():
    """Main setup function"""
    print("\nSysDaemon AI Setup Script")
    print("=" * 80)
    
    try:
        check_python_version()
        install_requirements()
        check_install_ollama()
        setup_api_keys()
        check_permissions()
        create_config()
        
        print("\n✨ Setup completed successfully!")
        print("\nTo start the application, run:")
        print("    python network_gui.py")
        
    except SetupError as e:
        print(f"\n❌ Setup failed: {str(e)}")
        sys.exit(1)
    except KeyboardInterrupt:
        # Cleanup is handled by signal_handler
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
