#!/bin/bash

# Get the directory where the script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create the AppleScript command that will run in Terminal
osascript << EOF
tell application "Terminal"
    # Create a new terminal window and run the command
    do script "clear; echo 'Starting SysDaemon AI Network Monitor...'; '$DIR/launch_network_monitoring.command'"
    
    # Activate Terminal and bring it to front
    activate
    
    # Get the current terminal window
    set currentWindow to front window
    
    # Set the window position and size
    set bounds of currentWindow to {50, 50, 800, 600}
    
    # Set the window title
    set custom title of front window to "SysDaemon AI Network Monitor"
end tell
EOF
