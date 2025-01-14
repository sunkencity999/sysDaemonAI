# SysDaemon AI

A powerful system monitoring and security suite powered by advanced AI technology. This application combines real-time network monitoring, threat detection, and intelligent system analysis to provide comprehensive protection for your system.

## Screenshots

### Network Monitoring Dashboard
![Network Monitoring Dashboard](https://github.com/user-attachments/assets/0dff9e09-86b6-439f-a9e6-fa1c1fcf194e)

*Real-time network traffic analysis with basic protocol identification*

### Data Visualizations
![Virus Scanner Interface](https://github.com/user-attachments/assets/3336337e-c567-468e-83a0-63ba29f0073e)

*Customizeable graphing solutions*

### AI Agent Management
![AI Agent Management](https://github.com/user-attachments/assets/4062f8c2-cf73-4500-b46a-d3ccf7ba7ab5)

*Local LLM integration for system management and security analysis*

### Packet Capture Functionality
![System Analysis](https://github.com/user-attachments/assets/dd56cdc2-065f-42a0-9270-d7d6cd5d7080)

*Easy export of pcap files and network data*

## Core Features

### 1. Network Monitoring
- **Real-time Traffic Analysis**: Monitor network traffic with basic protocol identification
- **Protocol Analysis**: Basic protocol identification and traffic categorization
- **Bandwidth Monitoring**: Track bandwidth usage by connection
- **Connection Tracking**: Monitor active connections and their states
- **Network Visualization**: Basic visualization of network traffic patterns

### 2. Advanced Virus Scanner
- **Multi-layered Threat Detection**:
  - YARA Rules for pattern matching
  - VirusTotal API integration for cloud-based threat intelligence
  - File entropy analysis for detecting packed/encrypted malware
  - File type detection using libmagic
- **Smart False Positive Reduction**:
  - Whitelist system for development files and trusted locations
  - Context-aware scanning with different thresholds
- **Secure Quarantine System**:
  - Isolated quarantine storage with metadata tracking
  - File integrity verification
  - Ability to restore quarantined files
  - Detailed threat information storage

### 3. AI Integration
- **Agentic AI System**:
  - Autonomous monitoring and decision making
  - Context-aware threat analysis
  - Adaptive learning from system behavior
  - Proactive threat detection
- **Natural Language Processing**:
  - Command interpretation for system management
  - Threat description in plain language
  - Context-aware responses
- **Machine Learning Models**:
  - Network traffic pattern analysis
  - Anomaly detection
  - Behavior-based threat detection
  - Adaptive threshold adjustment

### 4. Local AI Agents (CrewAI & Ollama)
- **CrewAI Integration**:
  - Autonomous agent teams for system monitoring
  - Role-based agents with specialized functions:
    - Security Analyst: Monitors threats and suspicious activity
    - System Monitor: Tracks system performance and resources
    - Network Inspector: Analyzes network traffic patterns
    - Threat Researcher: Investigates potential security issues
  - Agent collaboration for complex problem-solving
  - Adaptive response planning based on system state
  - Human-in-the-loop decision making for critical actions

- **Ollama Integration**:
  - Local LLM deployment for privacy-sensitive operations
  - Real-time packet analysis and threat assessment
  - Natural language processing for system commands
  - Custom-trained models for:
    - Network traffic pattern recognition
    - Malware behavior analysis
    - System anomaly detection
    - Command interpretation and validation
  - Efficient resource usage with optimized models
  - Offline capability for core functions

- **AI Agent Orchestration**:
  - Seamless coordination between CrewAI agents
  - Dynamic task allocation based on system needs
  - Intelligent escalation of security concerns
  - Automated report generation and analysis
  - Resource-aware agent scheduling
  - Configurable automation levels

### 5. Remote Agent System
- **Auto-Discovery and Connection**:
  - Agents automatically discover and connect to the main application
  - UDP broadcast-based discovery on port 5776
  - TCP connections for data transfer on port 5775
  - Automatic reconnection on network changes
  - Support for multiple network interfaces
  - Fallback to localhost for development

- **Agent Features**:
  - System metrics collection and reporting
  - Real-time monitoring of remote systems
  - Resource usage tracking (CPU, memory, disk, network)
  - Process monitoring and management
  - Event logging and notification
  - Secure communication channel with the main server

- **Data Collection**:
  - System performance metrics
  - Network connection statistics
  - Process information and resource usage
  - System events and logs
  - Security-related events
  - Custom metric collection through plugins

- **Security and Privacy**:
  - Encrypted communication between agents and server
  - Authentication for agent connections
  - Rate limiting to prevent DoS attacks
  - Configurable data collection policies
  - Data anonymization options
  - Audit logging of all agent activities

### Remote Agent Setup (For Monitored Systems)
1. Download just the agent installer:
   ```bash
   curl -O https://raw.githubusercontent.com/sunkencity999/sysDaemonAI/main/remote_agent/install.py
   ```

2. Run the agent installation script:
   ```bash
   python3 install.py
   ```
   This will:
   - Install agent-specific dependencies
   - Set up agent directories
   - Configure autostart
   - Create initial configuration

3. The agent will be installed to:
   - macOS: `~/Library/Application Support/SysDaemonAgent`
   - Linux: `~/.local/share/sysdaemon-agent`
   - Other: `~/.sysdaemon-agent`

4. Start the agent service:
   ```bash
   python3 ~/Library/Application\ Support/SysDaemonAgent/bin/agent.py
   ```
   Or use the system autostart (configured during installation)

The agent will automatically:
1. Listen for server broadcasts on port 5776
2. Connect to the discovered server on port 5775
3. Begin sending system metrics and data
4. Maintain connection and reconnect if needed

### Remote Agent Configuration
Create `agent_config.yaml` in the agent installation directory:
```yaml
server:
  discovery_port: 5776  # UDP discovery port
  connection_port: 5775  # TCP connection port
  reconnect_interval: 5  # Seconds between reconnection attempts

metrics:
  collection_interval: 60  # Seconds between metric collections
  include:
    - cpu
    - memory
    - disk
    - network
    - processes
  exclude:
    - sensitive_data

security:
  encrypt_data: true
  verify_server: true
  allowed_servers: []  # Empty list means accept any server
```

## Technology Stack

### Core Technologies
- **Python 3.12+**: Core application framework
- **PyQt6**: Modern, responsive GUI interface
- **asyncio**: Asynchronous I/O for efficient operations
- **Ollama**: Local LLM capabilities

#### Network Components
- **socket**: Network communication
- **netifaces**: Network interface discovery
- **psutil**: System and process monitoring

#### Security Components
- **yara-python**: Pattern matching engine
- **python-magic**: File type detection
- **VirusTotal API**: Cloud-based threat intelligence
- **logging**: Event and error logging
- **json**: Data serialization
- **threading**: Concurrent operations

#### External Dependencies
- **Ollama**: Required for LLM features
  - codellama model
  - mistral model

## Setup and Configuration

### Prerequisites
- Python 3.12 or higher
- Homebrew (for macOS dependencies)
- Ollama (for local LLM capabilities)
- System dependencies (installed automatically):
  - libmagic
  - tcpdump
  - Wireshark (optional)

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/sysDaemonAI.git
   cd sysDaemonAI
   ```

2. Install Ollama:
   ```bash
   curl https://ollama.ai/install.sh | sh
   ```

3. Run the main installation script:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```
   This will install the full SysDaemon AI application with all its components.

4. Configure API keys in `.env`:
   ```
   VIRUSTOTAL_API_KEY="your_key_here"
   OTX_API_KEY="your_key_here"
   MALWAREBAZAAR_API_KEY="your_key_here"
   ```

5. Initialize Ollama models:
   ```bash
   ollama pull codellama
   ollama pull mistral
   ```

### Running the Application
```bash
python3 -m network_monitor.network_gui
```

## Usage

### Network Monitoring
1. Launch the application
2. Select network interface to monitor
3. Use the dashboard to view real-time network statistics
4. Configure alerts for suspicious activity

### Virus Scanning
1. Click "Scan" in the virus scanner tab
2. Select directory to scan
3. Review suspicious files with confidence levels
4. Choose to quarantine or ignore detected threats

### AI System Management
1. Use natural language commands in the AI terminal
2. Review AI-generated recommendations
3. Configure autonomous response settings
4. Monitor AI learning patterns
5. Adjust agent team composition and roles
6. Review agent collaboration logs
7. Configure LLM settings for local processing

### Security Agent Chat
The Security Agent Chat provides an interactive interface for discussing and analyzing security concerns:

1. **Contextual Security Analysis**:
   - Maintains conversation history for in-depth security discussions
   - Understands context from previous messages for better assistance
   - Provides precise, security-focused responses

2. **Security Expertise**:
   - Helps analyze potential security threats
   - Explains security concepts and best practices
   - Assists with incident response planning
   - Provides guidance on security configurations

3. **User-Friendly Interface**:
   - Clean, modern chat interface
   - Real-time streaming responses
   - Easy-to-use message input
   - Copy functionality for responses
   - New chat option to start fresh conversations

4. **Integration with System Data**:
   - References real-time system security status
   - Provides context-aware security recommendations
   - Analyzes current network activity patterns

## Configuration

### Agent Configuration
The `config/agents.yaml` file allows you to customize the behavior of your AI agents:
```yaml
security_analyst:
  model: codellama
  temperature: 0.1
  max_tokens: 2000
  
system_monitor:
  model: mistral
  temperature: 0.2
  max_tokens: 1000
  
network_inspector:
  model: codellama
  temperature: 0.1
  max_tokens: 1500
```

### Ollama Configuration
Configure local LLM settings in `config/ollama.yaml`:
```yaml
default_model: codellama
fallback_model: mistral
max_concurrent_requests: 5
timeout: 30
memory_limit: 4096
```

## Security Considerations
- Requires root/sudo access for packet capture
- API keys should be kept secure
- Quarantined files are stored safely with integrity checks
- System makes no autonomous changes without user approval

## Contributing
Contributions are welcome! Please read our contributing guidelines and submit pull requests to our repository.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Commercial License

This software is licensed for commercial use. By purchasing a license, you agree to the following terms:

- You may install and use the software on the specified number of machines as per the license tier purchased.
- You may not redistribute, modify, or reverse-engineer the software without written permission from the author.
- Support and updates are provided for the duration of the license.
- Licenses are non-transferable.

For more details, please refer to the licensing agreement provided upon purchase.

## Licensing Information

- **Personal License**: $30/year (single machine)
- **Professional License**: $99/year (up to five machines)
- **Enterprise License**: $1499 (unlimited installations)

Visit [sysdaemonai.com](https://sysdaemonai.com) to purchase licenses.

## Acknowledgments
- Codeium AI team for AI integration support
- VirusTotal for threat intelligence
- Open source community for various tools and libraries

## Support
For support, please open an issue in the GitHub repository or contact our support team.

## Prerequisites

Before installing SysDaemon AI, ensure you have:

- macOS 11.0 or later
- Python 3.8 or later
- Administrative privileges
- Command Line Tools for Xcode (for compilation of dependencies)
- Homebrew (recommended for easy installation)

## Installation Guide

You can install SysDaemon AI using either the automated install script (recommended) or manual installation.

### Option 1: Automated Installation (Recommended)

The automated install script will guide you through the entire installation process, handling all dependencies and configuration:

```bash
# Clone the repository
git clone https://github.com/sunkencity999/sysdaemon-ai.git
cd sysdaemon-ai

# Run the installation script
sudo python3 install.py
```

The install script will:
1. Check and install all system requirements
2. Install and configure Ollama with the required model
3. Set up Python virtual environment
4. Install all Python dependencies
5. Configure permissions for packet capture
6. Initialize the database
7. Set up your AbuseIPDB API key
8. Create necessary directories and files

During installation, you'll be prompted to:
- Install Wireshark (optional)
- Enter your AbuseIPDB API key
- Grant necessary permissions

### Option 2: Manual Installation

If you prefer to install components manually, follow these steps:

### 1. System Preparation

First, ensure you have the necessary system tools:

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Command Line Tools
xcode-select --install

# Install Ollama
brew install ollama
```

### 2. Ollama Setup

```bash
# Start Ollama service
ollama serve

# In a new terminal, pull the required model
ollama pull llama2
```

### 3. Application Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sysdaemon-ai.git
cd sysdaemon-ai

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Wireshark (optional, for advanced packet analysis)
brew install --cask wireshark
```

### 4. Configuration

1. Create your configuration file:
```bash
cp config.example.py config.py
```

2. Edit `config.py` with your settings:
   - Add your AbuseIPDB API key (get one at https://www.abuseipdb.com/api)
   - Adjust monitoring thresholds if needed
   - Configure backup settings

3. Initialize the database:
```bash
python3 init_db.py
```

## Usage Guide

### Starting the Application

1. Ensure Ollama is running:
```bash
ollama serve
```

2. In a new terminal, launch SysDaemon AI:
```bash
cd sysdaemon-ai
source venv/bin/activate
sudo python3 network_gui.py
```

### Best Practices

1. System Health Monitoring
   - Keep the System Health panel visible to monitor resource usage
   - Set appropriate alert thresholds in config.py
   - Review historical data periodically to identify patterns

2. Network Monitoring
   - Use the connections table filters to focus on specific traffic
   - Enable notifications for suspicious connections
   - Review the security analysis panel regularly

3. Packet Capture
   - Start with broad filters and narrow down as needed
   - Use the "Export to PCAP" feature for detailed Wireshark analysis
   - Keep capture sessions focused and time-limited

4. Security Analysis
   - Review the AI-powered security insights daily
   - Investigate high-severity threats promptly
   - Keep the threat database updated

5. Data Management
   - Export important data regularly
   - Configure appropriate retention periods
   - Use the backup feature for critical data

### Troubleshooting

1. Permission Issues
```bash
# Ensure proper permissions
sudo chown -R $(whoami) /var/log/sysdaemon
sudo chmod 755 /var/log/sysdaemon
```

2. Database Issues
```bash
# Reset the database if corrupted
rm data/monitoring.db
python3 init_db.py
```

3. Ollama Connection
```bash
# Check Ollama status
curl http://localhost:11434/api/tags

# Restart Ollama if needed
brew services restart ollama
```

4. Network Capture Issues
```bash
# Check tcpdump permissions
sudo chmod +s $(which tcpdump)
```

## Testing

SysDaemon AI includes a comprehensive test suite to ensure reliability and functionality. To run the tests:

1. Activate the virtual environment:
```bash
source venv-3.12/bin/activate  # On macOS/Linux
```

2. Run all tests with coverage report:
```bash
python -m pytest tests/ -v --cov=.
```

3. Run specific test files:
```bash
python -m pytest tests/test_network_monitor.py -v
```

4. Run tests in parallel (faster execution):
```bash
python -m pytest tests/ -v -n auto
```

The test suite includes:
- Unit tests for core functionality
- Integration tests for system components
- Asynchronous operation tests
- Mock-based tests for external dependencies
- Performance monitoring tests
- Network connection handling tests

Test coverage reports are generated in both terminal output and HTML format. View the detailed HTML report by opening `htmlcov/index.html` in your browser after running the tests with the `--cov` flag.

## Maintenance

### Regular Maintenance Tasks

1. Database Optimization
```bash
# Compact the database monthly
sqlite3 data/monitoring.db "VACUUM;"
```

2. Log Management
```bash
# Rotate logs weekly
./scripts/rotate_logs.sh
```

3. Update Dependencies
```bash
pip install --upgrade -r requirements.txt
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Version History

### v1.3.0 (December 19, 2024)
- Added PCAP export functionality
- Enhanced packet capture capabilities
- Improved packet analysis and visualization
- Added Wireshark integration support
- Updated installation process for better permission handling

### v1.2.0 (December 16, 2024)
- Added LLM-powered security analysis with elevated privilege support
- Improved error handling for permission-related issues
- Enhanced logging system initialization
- Added clear feedback for permission requirements
- Updated security analysis to handle connection data more robustly

### v1.1.0 (Initial Release)
- Core monitoring and security features
- Integration with AbuseIPDB
- Basic automated responses
- Data persistence and analytics
