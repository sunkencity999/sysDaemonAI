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
  - Pattern-based threat detection
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
- **python-magic**: File type detection
- **VirusTotal API**: Cloud-based threat intelligence
- **logging**: Event and error logging

#### AI Components
- **Ollama**: Local LLM capabilities:
  - codellama model
  - mistral model

## Setup and Configuration

### Prerequisites
- Python 3.12 or higher
- Homebrew (for macOS dependencies)
- Ollama (for local LLM capabilities)
- System dependencies (installed automatically):
  - libmagic
  - libpcap
  - libffi

### Installation Steps

1. Clone the repository:
```bash
git clone https://github.com/sunkencity999/sysDaemonAI.git
cd sysDaemonAI
```

2. Install Python dependencies:
```bash
python3 -m pip install -r requirements.txt
```

3. Initialize the database:
```bash
python3 init_db.py
```

4. Install Ollama (if not already installed):
```bash
curl https://ollama.ai/install.sh | sh
```

5. Pull required models:
```bash
ollama pull codellama
ollama pull mistral
```

### Configuration

1. Copy the example configuration:
```bash
cp config.example.yaml config.yaml
```

2. Edit the configuration file:
```yaml
network:
  monitor_interfaces:
    - en0
    - en1
  exclude_ports:
    - 22
    - 80
    - 443

virus_scanner:
  scan_interval: 3600  # seconds
  excluded_dirs:
    - /System
    - /Library
  quarantine_dir: ~/.sysdaemon/quarantine

ai:
  ollama:
    host: localhost
    port: 11434
    models:
      - codellama
      - mistral
  agent_teams:
    - security
    - network
    - system
```

### Running the Application

1. Start the main application:
```bash
python3 main.py
```

2. Start the network monitor:
```bash
python3 network_monitor.py
```

3. Start the AI agents:
```bash
python3 ai_agents.py
```

## Development

### Setting Up Development Environment

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install development dependencies:
```bash
pip install -r requirements-dev.txt
```

### Running Tests

```bash
pytest tests/
```

### Building Documentation

```bash
cd docs
make html
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run the tests
5. Submit a pull request

## System Requirements

Before installing SysDaemon AI, ensure you have:

- macOS 11.0 or later
- Python 3.12 or later
- Administrative privileges
- Command Line Tools for Xcode (for compilation of dependencies)
- Homebrew (recommended for easy installation)

## Licensing Information

- **Personal License**: $39/year (single machine)
- **Professional License**: $99/year (up to five machines)
- **Enterprise License**: $1499 (unlimited installations)

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Open a new issue if needed
4. Email support@sysdaemonai.com
