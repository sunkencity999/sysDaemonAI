#!/bin/bash

# Get the directory where the script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Change to the project directory
cd "$DIR"

# Function to check if the monitoring system is already running
check_running() {
    if [ -f .monitor.pid ]; then
        pid=$(cat .monitor.pid)
        if ps -p $pid > /dev/null; then
            echo "Network monitoring system is already running (PID: $pid)"
            echo "To restart, first stop the existing process:"
            echo "  sudo kill $pid"
            exit 1
        else
            sudo rm .monitor.pid
        fi
    fi
}

# Function to request and verify sudo access
request_sudo() {
    echo "Administrator privileges are required for network monitoring."
    
    # Check if we already have sudo privileges
    if sudo -n true 2>/dev/null; then
        echo "Administrator access already granted (using cached credentials)."
        return 0
    fi
    
    echo "Please enter your password when prompted."
    
    # Request sudo and keep it alive
    if ! sudo -v; then
        echo "Failed to obtain administrator privileges. The application may have limited functionality."
        exit 1
    fi
    
    # Keep sudo alive in the background
    while true; do
        sudo -n true
        sleep 60
        kill -0 "$$" || exit
    done 2>/dev/null &
    
    echo "Administrator access granted."
}

# Function to check if Python 3.8+ is installed
check_python() {
    if ! command -v python3 &> /dev/null; then
        echo "Python 3 is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
    
    version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [ "$(echo $version | cut -d. -f1)" -lt 3 ] || [ "$(echo $version | cut -d. -f2)" -lt 8 ]; then
        echo "Python 3.8 or higher is required. Current version: $version"
        exit 1
    fi
}

# Function to create and activate virtual environment
setup_venv() {
    if [ ! -d "venv-3.12" ]; then
        echo "Creating virtual environment with Python 3.12..."
        /opt/homebrew/bin/python3.12 -m venv venv-3.12
    fi
    
    echo "Activating virtual environment..."
    source venv-3.12/bin/activate
    
    # Install dependencies if requirements.txt exists
    if [ -f "requirements.txt" ]; then
        echo "Installing dependencies..."
        pip install -r requirements.txt
    fi
}

# Function to setup directories and permissions
setup_directories() {
    # Create necessary directories
    mkdir -p logs
    mkdir -p data
    
    # Set permissions
    chmod 755 logs
    chmod 755 data
    
    # Create log files if they don't exist
    touch logs/monitoring.log
    touch logs/sysdaemon.log
    touch logs/sysdaemon.error.log
    
    # Set log file permissions
    chmod 644 logs/monitoring.log
    chmod 644 logs/sysdaemon.log
    chmod 644 logs/sysdaemon.error.log
}

# Function to start the monitoring system
start_monitoring() {
    echo "Starting network monitoring system..."
    
    # Set environment variables
    export PYTHONPATH="$DIR:$PYTHONPATH"
    export QT_MAC_WANTS_LAYER=1
    export QT_DEBUG_PLUGINS=1
    
    # Set Python environment variables
    export PYTHONUNBUFFERED=1
    export PYTHONDONTWRITEBYTECODE=1
    
    # Get the virtual environment Python path
    VENV_PYTHON="$DIR/venv-3.12/bin/python"
    
    # Start the monitoring system using the virtual environment Python with sudo
    sudo -E "$VENV_PYTHON" -m network_monitor.network_gui
}

# Function to check license
check_license() {
    echo "Checking license..."
    # Run the Python script to check for a valid license
    /Users/christopher.bradford/sysDaemonAI/venv/bin/python3 client_license_cli.py info
    if [ $? -ne 0 ]; then
        echo "No valid license found. Please install a license before proceeding."
        exit 1
    else
        echo "Valid license found. Proceeding with application startup..."
    fi
}

# Main execution
echo "Initializing network monitoring system..."

# Check license first
check_license

# Check if already running first
check_running

# Request sudo access
request_sudo

# Check Python installation
check_python

# Setup virtual environment
setup_venv

# Setup directories and permissions
setup_directories

# Start the monitoring system in the foreground
start_monitoring

# Deactivate virtual environment when done
deactivate
