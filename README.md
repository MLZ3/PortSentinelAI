# PortSentinel AI

## Description
PortSentinel AI is an intelligent network security scanner that identifies open ports on a local network and uses AI-based analysis to assess potential security risks. The tool is designed to be used by cybersecurity beginners to quickly identify risky configurations on their network.

## Key Features
- **Secure Port Scanning**: Uses Nmap via Python to scan open ports
- **Security Checks**: Prevents accidental scanning of external networks
- **Intelligent Risk Assessment**: Classifies security risks based on open ports
- **Personalized Recommendations**: Suggests actions to mitigate detected issues
- **Detailed Reports**: Generates reports in TXT, JSON, and CSV formats
- **Interactive Interface**: Guides the user through the scanning process

## Prerequisites
- Python 3.6+
- Nmap installed on your system
- Python modules: python-nmap, ipaddress

## Installation

### 1. Install Nmap
- **Linux**: `sudo apt-get install nmap`
- **macOS**: `brew install nmap`
- **Windows**: Download and install from [nmap.org](https://nmap.org/download.html)

### 2. Install Python dependencies
```bash
pip install python-nmap ipaddress
```

### 3. Clone the repository or download the script
```bash
git clone https://github.com/yourusername/portsentinel-ai.git
cd portsentinel-ai
```
Or simply download the `portsentinel.py` file.

## Usage

### Interactive Mode
Run the script without arguments to start interactive mode:
```bash
python portsentinel.py
```

The program will guide you through the following steps:
1. Checking your local IP address
2. Choosing the scan target (localhost, specific IP, entire network)
3. Selecting the scan intensity level
4. Choosing output formats for the reports

### Command-Line Mode
You can also use command-line arguments:
```bash
python portsentinel.py --target 192.168.1.0/24 --intensity 2 --format txt,json
```

### Main Options
- `--target`: IP address, hostname, or CIDR range to scan
- `--intensity`: Scan intensity level (1=fast, 2=standard, 3=intensive)
- `--format`: Output report formats (txt, json, csv)
- `--output-dir`: Directory for reports (default: "reports")

## Understanding the Results

### Risk Levels
- **CRITICAL**: Severe vulnerability requiring immediate action
- **HIGH**: Significant risk requiring quick attention
- **MEDIUM**: Potential security concern to be examined
- **LOW**: Minimal risk, but worth noting
- **INFO**: Information that is not considered a risk

### Common Ports and Associated Risks
- 21 (FTP): HIGH - Unencrypted file transfer protocol
- 22 (SSH): MEDIUM - Secure remote access, but should be limited
- 23 (Telnet): CRITICAL - Unencrypted remote access protocol
- 80 (HTTP): MEDIUM - Unencrypted web server
- 443 (HTTPS): LOW - Encrypted web server (normal)
- 3389 (RDP): HIGH - Remote desktop protocol, a frequent target for attacks

## ⚠️ Security Best Practices ⚠️
1. Only scan networks you have permission to scan
2. Start by scanning only your own machine (localhost)
3. Avoid scanning corporate networks without authorization
4. Close unused ports identified as risky

## Troubleshooting

### Nmap Not Detected
Ensure Nmap is installed and added to your system PATH.

### Permission Errors
On Linux/macOS, you may need to run with `sudo` for certain scanning features:
```bash
sudo python portsentinel.py
```

### Scan Too Slow
Use the intensity option `1` for a faster scan or limit your scan to a single IP address.

## Advanced Features
- **Evolving Knowledge Base**: The tool remembers new port-risk associations
- **Detailed Service Analysis**: Identifies service versions for more accurate assessment
- **Detection of Improper Configurations**: Flags combinations of ports that pose a high risk

## 📜 License  
This project is private and **cannot be used, modified, or distributed without permission**.  
All rights reserved © 2025.  

## Disclaimer
This tool is intended for educational and defensive security purposes. Use it only on networks for which you have explicit authorization to perform security testing.
