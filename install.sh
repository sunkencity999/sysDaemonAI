#!/bin/bash

# Exit on error
set -e

# Check if running on macOS first
if [[ "$(uname)" != "Darwin" ]]; then
    echo "This script is designed for macOS only."
    exit 1
fi

# Check for sudo privileges at the start
if [ "$EUID" -ne 0 ]; then
    echo "This script requires sudo privileges for installation and packet capture capabilities."
    echo "Please run with sudo: sudo $0"
    exit 1
fi

# Store the real user's home directory and username
REAL_USER=$(stat -f '%Su' /dev/console)
REAL_HOME=$(eval echo ~$REAL_USER)

# Trap for cleanup on script exit
cleanup() {
    local exit_code=$?
    
    # Deactivate virtual environment if it's active
    if [ -n "$VIRTUAL_ENV" ]; then
        deactivate 2>/dev/null || true
    fi
    
    # Unmount DMG if it's mounted
    if [ -d "/Volumes/Ollama" ]; then
        hdiutil detach "/Volumes/Ollama" -quiet || true
    fi
    
    # Clean up temporary files if they exist
    if [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    
    if [ $exit_code -ne 0 ]; then
        log_error "Installation failed. Please check the error messages above."
        print_status "yellow" "You can try running the script again after fixing any issues."
    fi
    
    exit $exit_code
}

# Set up trap for interrupts and errors
trap cleanup EXIT
trap 'exit 1' INT TERM

# Helper function to show progress
show_progress() {
    pid=$1
    message=$2
    spin='-\|/'
    i=0
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %4 ))
        printf "\r$message ${spin:$i:1}"
        sleep .1
    done
    printf "\r$message Complete!\n"
}

# Create installation checkpoint
create_checkpoint() {
    echo "$1" > .install_checkpoint
}

# Check if installation can be resumed
resume_install() {
    if [ -f .install_checkpoint ]; then
        checkpoint=$(cat .install_checkpoint)
        case $checkpoint in
            "system_dependencies")
                return 0
                ;;
            "python_setup")
                return 0
                ;;
            "database_setup")
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    fi
    return 1
}

# Backup existing configuration
backup_config() {
    if [ -f ".env" ] || [ -f "config.py" ]; then
        backup_dir="backups/$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        [ -f ".env" ] && cp .env "$backup_dir/.env.bak"
        [ -f "config.py" ] && cp config.py "$backup_dir/config.py.bak"
        print_status "green" "Configuration backed up to $backup_dir"
    fi
}

# Check system requirements
check_system_requirements() {
    print_status "yellow" "Checking system requirements..."
    
    # Check disk space
    required_space=2048  # 2GB in MB
    available_space=$(df -m . | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt "$required_space" ]; then
        handle_error "Insufficient disk space. Need at least ${required_space}MB"
    fi
    
    # Check memory
    required_memory=2048  # 2GB in MB
    available_memory=$(sysctl hw.memsize | awk '{print $2/1024/1024}' | cut -d. -f1)
    if [ "$available_memory" -lt "$required_memory" ]; then
        handle_error "Insufficient memory. Need at least ${required_memory}MB"
    fi
    
    # Check macOS version
    os_version=$(sw_vers -productVersion)
    if [[ "$os_version" < "10.15" ]]; then
        handle_error "macOS 10.15 or higher required"
    fi
    
    print_status "green" "System requirements check passed"
}

# Check network connectivity
check_network() {
    print_status "yellow" "Checking network connectivity..."
    if ! ping -c 1 github.com &> /dev/null; then
        handle_error "No internet connection. Please check your network."
    fi
    
    # Check if required ports are available
    required_ports=(8000 11434)  # Add any other required ports
    for port in "${required_ports[@]}"; do
        if lsof -i ":$port" &> /dev/null; then
            print_status "yellow" "Warning: Port $port is already in use"
        fi
    done
    
    print_status "green" "Network connectivity check passed"
}

# Post-installation health check
check_installation() {
    print_status "yellow" "Running post-installation checks..."
    
    # Check Python installation
    if ! command_exists python3; then
        print_status "red" "Python installation failed"
        return 1
    fi
    
    # Check database
    if [ ! -f "data/sysdaemon.db" ]; then
        print_status "red" "Database initialization failed"
        return 1
    fi
    
    # Check Ollama
    if ! curl -s http://localhost:11434/api/tags >/dev/null; then
        print_status "red" "Ollama is not responding"
        return 1
    fi
    
    # Check admin user
    if ! sudo -u $REAL_USER python3 -c "
from auth_manager import AuthManager
from database import DatabaseManager
db = DatabaseManager()
auth = AuthManager(db)
exists = db.fetch_one('SELECT id FROM users WHERE username = ?', ('Admin',))
exit(0 if exists else 1)
"; then
        print_status "red" "Admin user setup failed"
        return 1
    fi
    
    print_status "green" "All post-installation checks passed!"
    return 0
}

# Create temporary directory
TMP_DIR=$(mktemp -d)

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    case $color in
        "green") echo -e "\033[32m$message\033[0m" ;;
        "red") echo -e "\033[31m$message\033[0m" ;;
        "yellow") echo -e "\033[33m$message\033[0m" ;;
        *) echo "$message" ;;
    esac
}

# Function to handle errors
handle_error() {
    log_error "$1"
    exit 1
}

# Enhanced error logging
log_error() {
    local message=$1
    local log_file="install_error.log"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $message" >> "$log_file"
    print_status "red" "Error: $message"
    print_status "yellow" "Check $log_file for detailed error information"
}

# Function to install Ollama
install_ollama() {
    print_status "yellow" "Installing Ollama..."
    
    # Check if port 11434 is available
    if lsof -i :11434 >/dev/null 2>&1; then
        handle_error "Port 11434 is in use. Please free this port and try again."
    fi
    
    # Create temporary directory for download
    local temp_dir=$(mktemp -d)
    local installer_path="$temp_dir/Ollama.dmg"
    
    # Download Ollama installer for macOS
    print_status "yellow" "Downloading Ollama installer for macOS..."
    if ! curl -L https://ollama.ai/download/Ollama-darwin.dmg -o "$installer_path"; then
        rm -rf "$temp_dir"
        handle_error "Failed to download Ollama installer"
    fi
    
    # Mount the DMG
    print_status "yellow" "Mounting Ollama installer..."
    local mount_point="/Volumes/Ollama"
    hdiutil attach "$installer_path" -quiet || handle_error "Failed to mount Ollama installer"
    
    # Copy Ollama.app to Applications
    print_status "yellow" "Installing Ollama..."
    cp -R "$mount_point/Ollama.app" /Applications/ || handle_error "Failed to install Ollama"
    
    # Set proper permissions
    chown -R $REAL_USER:staff "/Applications/Ollama.app"
    
    # Unmount the DMG
    hdiutil detach "$mount_point" -quiet || print_status "yellow" "Warning: Failed to unmount installer"
    
    # Clean up
    rm -rf "$temp_dir"
    
    # Add Ollama to PATH
    print_status "yellow" "Adding Ollama to PATH..."
    local ollama_path="/Applications/Ollama.app/Contents/MacOS"
    
    # Update shell profiles for the real user
    for profile in "$REAL_HOME/.zshrc" "$REAL_HOME/.bash_profile"; do
        if [ -f "$profile" ]; then
            if ! grep -q "export PATH=\"$ollama_path:\$PATH\"" "$profile"; then
                echo "export PATH=\"$ollama_path:\$PATH\"" >> "$profile"
            fi
        fi
    done
    
    # Update current session PATH
    export PATH="$ollama_path:$PATH"
    
    # Source the updated profile
    if [ -f "$REAL_HOME/.zshrc" ]; then
        sudo -u $REAL_USER zsh -c "source $REAL_HOME/.zshrc" || true
    fi
    if [ -f "$REAL_HOME/.bash_profile" ]; then
        sudo -u $REAL_USER bash -c "source $REAL_HOME/.bash_profile" || true
    fi
    
    # Verify installation
    if ! command_exists ollama; then
        handle_error "Ollama installation failed verification. Please try restarting your terminal and running the script again."
    fi
    
    print_status "green" "Ollama installed successfully"
    
    # Start Ollama service
    print_status "yellow" "Starting Ollama service..."
    sudo -u $REAL_USER ollama serve &
    
    # Wait for Ollama to be ready
    print_status "yellow" "Waiting for Ollama service to be ready..."
    for i in {1..30}; do
        if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
            break
        fi
        sleep 1
        if [ $i -eq 30 ]; then
            handle_error "Ollama service failed to start properly"
        fi
    done
    print_status "green" "Ollama service started successfully"
}

# Function to ensure Ollama service is running
ensure_ollama_running() {
    if ! pgrep -x "ollama" > /dev/null; then
        print_status "yellow" "Starting Ollama service..."
        sudo -u $REAL_USER ollama serve &
        
        # Wait for Ollama to be ready
        print_status "yellow" "Waiting for Ollama service to be ready..."
        for i in {1..30}; do
            if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
                break
            fi
            sleep 1
            if [ $i -eq 30 ]; then
                handle_error "Ollama service failed to start properly"
            fi
        done
        print_status "green" "Ollama service started successfully"
    else
        print_status "green" "Ollama service is already running"
    fi
}

# Function to check and pull required model
check_and_pull_model() {
    print_status "yellow" "Checking for required model..."
    if ! ollama list | grep -q "llama3.2-vision:latest"; then
        print_status "yellow" "Pulling Ollama model (this may take a while)..."
        sudo -u $REAL_USER ollama pull llama3.2-vision:latest || handle_error "Failed to pull Ollama model"
        print_status "green" "Model installed successfully"
    else
        print_status "green" "Required model is already installed"
    fi
}

# Function to generate launch agent plist
generate_launch_agent_plist() {
    print_status "yellow" "Generating LaunchAgent plist..."
    
    # Get the installation directory
    local INSTALL_DIR="$1"
    
    # Create startup wrapper script
    cat > "$INSTALL_DIR/startup_wrapper.command" << EOF
#!/bin/bash

# Get the directory where the script is located
DIR="\$( cd "\$( dirname "\${BASH_SOURCE[0]}" )" && pwd )"

# Open Terminal.app and run the launch script
osascript -e "tell application \\"Terminal\\"
    do script \\"cd '\$DIR' && '\$DIR/launch_network_monitoring.command'\\"
    activate
end tell"
EOF
    
    # Make startup wrapper executable
    chmod +x "$INSTALL_DIR/startup_wrapper.command"
    chown $REAL_USER:staff "$INSTALL_DIR/startup_wrapper.command"
    
    # Create the plist content with the correct paths
    cat > "$INSTALL_DIR/com.sysdaemonai.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sysdaemonai</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$INSTALL_DIR/startup_wrapper.command</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/sysdaemon.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/sysdaemon.error.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>PYTHONPATH</key>
        <string>$INSTALL_DIR</string>
        <key>HOME</key>
        <string>$REAL_HOME</string>
    </dict>
    <key>UserName</key>
    <string>$REAL_USER</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
</dict>
</plist>
EOF
    
    # Set correct permissions
    chmod 644 "$INSTALL_DIR/com.sysdaemonai.plist"
    chown $REAL_USER:staff "$INSTALL_DIR/com.sysdaemonai.plist"
    
    print_status "green" "LaunchAgent plist generated successfully"
}

# Function to install Python dependencies
install_python_deps() {
    print_status "yellow" "Installing Python dependencies..."
    
    # Activate virtual environment
    source venv-3.12/bin/activate || handle_error "Failed to activate virtual environment"
    
    # Install production dependencies
    pip install -r requirements.txt || handle_error "Failed to install Python dependencies"
    
    # Install development and testing dependencies
    pip install pytest pytest-asyncio pytest-cov pytest-mock pytest-timeout pytest-xdist || handle_error "Failed to install testing dependencies"
    
    print_status "green" "Python dependencies installed successfully"
}

# Main installation steps
main() {
    print_status "green" "Starting SysDaemon AI installation..."
    
    # Pre-installation checks
    check_macos_version
    check_network
    check_disk_space
    check_system_load
    check_ports
    
    # Check for resume
    if resume_install; then
        print_status "yellow" "Resuming installation..."
    else
        print_status "yellow" "Starting fresh installation..."
    fi
    
    # Backup existing configuration
    backup_config
    
    # Check system requirements
    check_system_requirements
    
    # Check network connectivity
    check_network
    
    # Check Ollama installation and model
    if command_exists ollama; then
        print_status "green" "Ollama is already installed"
        ensure_ollama_running
        check_and_pull_model
    else
        print_status "yellow" "Ollama not found. Installing..."
        install_ollama
        check_and_pull_model
    fi
    
    # Install system dependencies
    create_checkpoint "system_dependencies"
    print_status "yellow" "Installing system dependencies..."
    if ! command_exists brew; then
        print_status "yellow" "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || handle_error "Failed to install Homebrew"
    fi
    
    # Install Python and check version
    print_status "yellow" "Installing Python..."
    brew install python@3.11 || handle_error "Failed to install Python"
    check_python_version
    
    # Install other dependencies
    print_status "yellow" "Installing required packages..."
    brew install tcpdump || handle_error "Failed to install dependencies"
    
    # Install libmagic for file type detection
    if ! command_exists "brew"; then
        print_status "yellow" "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || handle_error "Failed to install Homebrew"
    fi
    
    print_status "yellow" "Installing libmagic..."
    brew install libmagic || handle_error "Failed to install libmagic"
    
    # Create rules directory if it doesn't exist
    if [ ! -d "rules" ]; then
        mkdir -p rules
        print_status "green" "Created rules directory for YARA rules"
    fi
    
    # Set up environment variables file if it doesn't exist
    if [ ! -f ".env" ]; then
        cat > .env << EOL
# Threat Intelligence API Keys
VIRUSTOTAL_API_KEY=""
OTX_API_KEY=""
MALWAREBAZAAR_API_KEY=""
EOL
        print_status "yellow" "Created .env file. Please add your API keys."
    fi
    
    # Optional Wireshark installation
    print_status "yellow" "Would you like to install Wireshark for packet analysis? (y/n)"
    read -r install_wireshark
    if [[ $install_wireshark =~ ^[Yy]$ ]]; then
        (brew install --cask wireshark & show_progress $! "Installing Wireshark...") || print_status "yellow" "Failed to install Wireshark, continuing without it..."
    fi
    
    # Python environment setup
    create_checkpoint "python_setup"
    if [ ! -d "venv" ]; then
        print_status "yellow" "Creating virtual environment..."
        python3 -m venv venv || handle_error "Failed to create virtual environment"
    fi
    
    print_status "yellow" "Activating virtual environment..."
    source venv/bin/activate || handle_error "Failed to activate virtual environment"
    
    # Install Python requirements with progress indicator
    print_status "yellow" "Installing Python requirements..."
    if [ -f "requirements.txt" ]; then
        (pip install -r requirements.txt & show_progress $! "Installing Python packages...") || handle_error "Failed to install Python requirements"
    else
        handle_error "requirements.txt not found"
    fi
    
    # License check
    print_status "yellow" "Checking license..."
    python3 - << EOF
from license_manager import LicenseManager
from license_dialog import LicenseDialog
import tkinter as tk

def check_license():
    root = tk.Tk()
    root.withdraw()  # Hide the main window
    dialog = LicenseDialog(root)
    root.wait_window(dialog)  # Wait for the dialog to close
    root.destroy()

if __name__ == '__main__':
    lm = LicenseManager()
    if not lm.get_license_info():
        check_license()
EOF
    
    # Create and setup directories
    create_checkpoint "directory_setup"
    for dir in "data" "logs" "exports"; do
        if [ ! -d "$dir" ]; then
            print_status "yellow" "Creating $dir directory..."
            mkdir -p "$dir" || handle_error "Failed to create $dir directory"
        fi
    done
    
    # Set permissions
    print_status "yellow" "Setting up permissions..."
    chmod +s "$(which tcpdump)" || handle_error "Failed to set tcpdump permissions"
    
    # Get user's primary group
    USER_GROUP=$(id -gn $REAL_USER)
    
    # Database setup
    create_checkpoint "database_setup"
    print_status "yellow" "Initializing database..."
    
    # Ensure data directory exists with correct permissions
    mkdir -p "data" || handle_error "Failed to create data directory"
    chown $REAL_USER:staff "data"
    chmod 755 "data"
    
    # Initialize the database with proper ownership
    sudo -u $REAL_USER python3 -c "
from database import DatabaseManager, Base
from sqlalchemy import create_engine
import os

# Create database directory if it doesn't exist
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'sysdaemon.db')
os.makedirs(os.path.dirname(db_path), exist_ok=True)

# Initialize database
engine = create_engine(f'sqlite:///{db_path}')
Base.metadata.create_all(engine)
" || handle_error "Failed to initialize database"

    # Set proper permissions on the database file
    chown $REAL_USER:staff "data/sysdaemon.db"
    chmod 644 "data/sysdaemon.db"
    
    # Verify database creation
    if [ ! -f "data/sysdaemon.db" ]; then
        handle_error "Database file was not created successfully"
    fi
    
    print_status "green" "Database initialized successfully"
    
    # Set up default admin user
    print_status "yellow" "Setting up default admin user..."
    sudo -u $REAL_USER python3 setup_admin.py || handle_error "Failed to set up admin user"
    print_status "green" "Default admin user created successfully (username: Admin, password: sysdaemonAI)"
    
    # Alembic setup for migrations
    if [ ! -d "alembic" ]; then
        print_status "yellow" "Setting up database migrations..."
        pip install alembic || handle_error "Failed to install alembic"
        alembic init alembic || handle_error "Failed to initialize alembic"
        alembic revision --autogenerate -m "Initial migration" || handle_error "Failed to create initial migration"
        alembic upgrade head || handle_error "Failed to apply migrations"
    fi
    
    # Make launch script executable
    chmod +x launch_network_monitoring.command || handle_error "Failed to make launch script executable"
    
    # Generate launch agent plist
    generate_launch_agent_plist "$(pwd)"
    
    # API key setup
    create_checkpoint "api_setup"
    print_status "yellow" "Would you like to set up your AbuseIPDB API key now? (y/n)"
    read -r setup_api
    if [[ $setup_api =~ ^[Yy]$ ]]; then
        print_status "yellow" "Please enter your AbuseIPDB API key:"
        read -r api_key
        echo "ABUSEIPDB_API_KEY='$api_key'" > .env || handle_error "Failed to create .env file"
        print_status "green" "API key saved to .env file"
    fi
    
    # Advanced configuration setup
    print_status "yellow" "Would you like to configure advanced settings? (y/n)"
    read -r configure_advanced
    if [[ $configure_advanced =~ ^[Yy]$ ]]; then
        # Port configuration
        print_status "yellow" "Enter the port for the monitoring interface (default: 8000):"
        read -r port
        port=${port:-8000}
        echo "MONITOR_PORT=$port" >> .env
        
        # Log retention
        print_status "yellow" "Enter log retention period in days (default: 90):"
        read -r retention
        retention=${retention:-90}
        echo "LOG_RETENTION_DAYS=$retention" >> .env
        
        # Performance monitoring interval
        print_status "yellow" "Enter performance monitoring interval in seconds (default: 60):"
        read -r interval
        interval=${interval:-60}
        echo "MONITOR_INTERVAL=$interval" >> .env
        
        print_status "green" "Advanced settings configured successfully"
    fi
    
    # Run post-installation health check
    if ! check_installation; then
        print_status "red" "Installation verification failed. Please check the errors above."
        print_status "yellow" "You may need to run the installer again or contact support."
        exit 1
    fi
    
    # Cleanup checkpoint file
    rm -f .install_checkpoint
    
    print_status "green" "Installation complete!"
    print_status "yellow" "Important Notes:"
    print_status "yellow" "1. Default admin credentials:"
    print_status "yellow" "   Username: Admin"
    print_status "yellow" "   Password: sysdaemonAI"
    print_status "yellow" "2. Please change the admin password on first login"
    print_status "yellow" "3. Configuration files are in: $(pwd)"
    print_status "yellow" "4. Logs directory: $(pwd)/logs"
    print_status "yellow" "5. To start the application, run: ./launch_network_monitoring.command"
    
    if [ -d "backups" ]; then
        print_status "yellow" "6. Configuration backups are in: $(pwd)/backups"
    fi
    
    print_status "green" "Thank you for installing SysDaemon AI!"
}

# Run main installation
main
