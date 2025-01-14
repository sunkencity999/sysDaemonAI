#!/usr/bin/env python3

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
import platform
import getpass

def get_install_path():
    """Get the appropriate installation path based on the OS"""
    if platform.system() == 'Darwin':  # macOS
        return os.path.expanduser('~/Library/Application Support/SysDaemonAgent')
    elif platform.system() == 'Linux':
        return os.path.expanduser('~/.local/share/sysdaemon-agent')
    else:
        return os.path.expanduser('~/.sysdaemon-agent')

def create_directories(base_path):
    """Create necessary directories"""
    directories = ['bin', 'config', 'logs', 'data']
    for directory in directories:
        os.makedirs(os.path.join(base_path, directory), exist_ok=True)

def install_dependencies():
    """Install required Python packages"""
    requirements = [
        'psutil',
        'requests',
        'PyQt6'
    ]
    
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install'] + requirements)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error installing dependencies: {e}")
        return False

def setup_autostart():
    """Set up the agent to run at system startup"""
    if platform.system() == 'Darwin':  # macOS
        plist_path = os.path.expanduser('~/Library/LaunchAgents/com.sysdaemon.agent.plist')
        agent_path = os.path.join(get_install_path(), 'bin/agent.py')
        
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sysdaemon.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
        <string>{agent_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{os.path.join(get_install_path(), 'logs/agent.log')}</string>
    <key>StandardErrorPath</key>
    <string>{os.path.join(get_install_path(), 'logs/agent_error.log')}</string>
</dict>
</plist>"""
        
        os.makedirs(os.path.dirname(plist_path), exist_ok=True)
        with open(plist_path, 'w') as f:
            f.write(plist_content)
        
        # Load the launch agent
        subprocess.run(['launchctl', 'load', plist_path])

def copy_files():
    """Copy agent files to installation directory"""
    install_path = get_install_path()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Copy agent files
    shutil.copy2(
        os.path.join(current_dir, 'sysdaemon_agent/agent.py'),
        os.path.join(install_path, 'bin/agent.py')
    )
    
    # Make agent executable
    os.chmod(os.path.join(install_path, 'bin/agent.py'), 0o755)
    
    # Copy icon if available
    icon_source = os.path.join(current_dir, '..', 'network_monitor/icons/app_icon.png')
    if os.path.exists(icon_source):
        os.makedirs(os.path.join(install_path, 'bin/icons'), exist_ok=True)
        shutil.copy2(icon_source, os.path.join(install_path, 'bin/icons/app_icon.png'))

def create_config(master_url=None):
    """Create initial configuration file"""
    config = {
        'master_url': master_url or 'http://localhost:5000',
        'check_interval': 300,
        'daily_report_time': '00:00',
        'last_report_date': None
    }
    
    config_path = os.path.join(get_install_path(), 'config/agent_config.json')
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

def main():
    print("Installing SysDaemon AI Remote Agent...")
    
    # Get master server URL
    master_url = input("Enter master server URL [http://localhost:5000]: ").strip()
    if not master_url:
        master_url = "http://localhost:5000"
    
    # Create installation directory
    install_path = get_install_path()
    create_directories(install_path)
    
    # Install dependencies
    print("Installing dependencies...")
    if not install_dependencies():
        print("Failed to install dependencies. Please try again.")
        sys.exit(1)
    
    # Copy files
    print("Copying files...")
    copy_files()
    
    # Create configuration
    print("Creating configuration...")
    create_config(master_url)
    
    # Setup autostart
    print("Setting up autostart...")
    setup_autostart()
    
    print(f"""
SysDaemon AI Remote Agent installed successfully!
Installation path: {install_path}
Configuration file: {os.path.join(install_path, 'config/agent_config.json')}
Logs directory: {os.path.join(install_path, 'logs')}

The agent will start automatically at system startup.
To start it now, run: {os.path.join(install_path, 'bin/agent.py')}
""")

if __name__ == '__main__':
    main()
