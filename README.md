# SysDaemon AI

A powerful system monitoring and security suite powered by advanced AI technology. This application combines real-time network monitoring, threat detection, and intelligent system analysis to provide comprehensive protection for your system.

## Screenshots

### Network Monitoring Dashboard
![Network Monitoring Dashboard]([(https://github.com/sunkencity999/sysDaemonAI/blob/main/resources/Screenshot%202025-01-02%20at%2010.41.34%E2%80%AFAM.png))
*Real-time network traffic analysis with protocol breakdown and connection tracking*

### Virus Scanner Interface
![Virus Scanner Interface](https://raw.githubusercontent.com/sunkencity999/sysDaemonAI/main/resources/Screenshot%202025-01-02%20at%2010.42.51%20AM.png)
*Advanced virus scanning with threat confidence levels and quarantine options*

### AI Agent Management
![AI Agent Management](https://raw.githubusercontent.com/sunkencity999/sysDaemonAI/main/resources/Screenshot%202025-01-02%20at%2010.43.20%20AM.png)
*CrewAI agent configuration and monitoring interface*

### System Analysis
![System Analysis](https://raw.githubusercontent.com/sunkencity999/sysDaemonAI/main/resources/Screenshot%202025-01-02%20at%2010.46.32%20AM.png)
*Detailed system analysis with AI-powered insights*

## Core Features

### 1. Network Monitoring
- **Real-time Traffic Analysis**: Monitor network traffic with detailed packet inspection
- **Protocol Analysis**: Deep packet inspection for various protocols (HTTP, HTTPS, DNS, etc.)
- **Bandwidth Monitoring**: Track bandwidth usage by application and process
- **Connection Tracking**: Monitor active connections and their states
- **Network Visualization**: Interactive visualization of network traffic patterns
- **Anomaly Detection**: AI-powered detection of unusual network behavior

### 2. Advanced Virus Scanner
- **Multi-layered Threat Detection**:
  - YARA Rules for pattern matching
  - VirusTotal API integration for cloud-based threat intelligence
  - File entropy analysis for detecting packed/encrypted malware
  - Suspicious pattern recognition
  - File type detection using libmagic
  - Behavioral analysis
- **Smart False Positive Reduction**:
  - Context-aware scanning with different thresholds for different file types
  - Whitelist system for development files and trusted locations
  - Source code-aware scanning with adjusted confidence levels
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

## Technology Stack

### Core Technologies
- **Python 3.12+**: Core application framework
- **PyQt6**: Modern, responsive GUI interface
- **asyncio**: Asynchronous I/O for efficient operations
- **CrewAI**: Multi-agent system for autonomous operations
- **Ollama**: Local LLM deployment for AI operations

### Network Components
- **tcpdump**: Low-level packet capture
- **pyshark**: Packet analysis and protocol inspection
- **scapy**: Network packet manipulation
- **Wireshark** (optional): Advanced packet analysis

### Security Components
- **yara-python**: Pattern matching engine
- **python-magic**: File type detection
- **cryptography**: Secure operations and hash verification
- **aiohttp**: Async HTTP for API interactions

### AI and Machine Learning
- **TensorFlow/Keras**: Machine learning models
- **scikit-learn**: Statistical analysis
- **Natural Language Processing**: Command interpretation
- **Codeium AI**: Advanced code analysis and threat detection

### APIs and External Services
- **VirusTotal API**: Cloud-based threat intelligence
- **Open Threat Exchange (OTX)**: Threat data sharing
- **MalwareBazaar**: Malware sample analysis

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

3. Run the installation script:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

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
sudo ./install.sh
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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

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

## Support

For issues, questions, or contributions, please contact:
- Email: contact@christopherdanielbradford.com
- GitHub Issues: [Project Issues Page](https://github.com/sunkencity999/sysdaemon-ai/issues)
