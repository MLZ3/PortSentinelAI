# PortSentinel AI

## Description

PortSentinel AI is an intelligent network port scanner designed for cybersecurity beginners and professionals. It identifies open ports on a network and employs AI-based analysis to assess potential security risks. This version operates without relying on Nmap, using pure Python libraries for enhanced portability and ease of use.

## Key Features

*   **Comprehensive Port Scanning:** Identifies open TCP ports on a target system or network.
*   **Intelligent Risk Assessment:** Classifies security risks based on identified open ports and known vulnerabilities, using an AI-inspired risk engine.
*   **Customizable Scan Intensity:** Offers "quick," "standard," and "intensive" scan modes to balance speed and thoroughness.
*   **Safety Checks:** Prevents accidental scanning of external networks through built-in safety mechanisms.
*   **Clear Recommendations:** Suggests actions to mitigate identified security issues.
*   **Detailed Text Reports:** Generates easy-to-understand reports in plain text format.
*   **Graphical User Interface (GUI):** Provides an interactive experience with simple controls for target selection, scan intensity, and results display.
*   **Threaded Scanning:** Utilizes multi-threading for faster and more efficient port scanning.

## Prerequisites

*   Python 3.6+
*   Tkinter (usually included with Python, but may require separate installation on some systems)
*   No external dependencies are required beyond standard Python libraries.

## Installation

1.  Ensure you have Python 3.6 or higher installed.
2.  Download the `port_sentinel.py` file.

    ```bash
    wget https://github.com/yourusername/portsentinel-ai/blob/main/port_sentinel.py # Or clone the repo if you prefer
    ```

## Usage

### Graphical User Interface (GUI) Mode

1.  Run the script:

    ```bash
    python port_sentinel.py
    ```

2.  The PortSentinel AI GUI will appear.
3.  Enter the target IP address or network range in the "Target IP/Network" field.
4.  Choose the scan intensity from the "Intensity" dropdown menu (Quick, Standard, or Intensive).
5.  Check the "Scan Common Ports Only" box to only scan a limited set of common ports.
6.  Click the "Start Scan" button.
7.  The scan results and risk assessment will be displayed in the text area.

### Report Generation

*   The results of the scan, including a risk assessment and recommendations, are displayed directly in the GUI.
*   To save the report, copy the content from the results text area to a text file.

### Understanding the Results

#### Risk Levels

*   **CRITICAL:** Severe vulnerability requiring immediate action.
*   **HIGH:** Significant risk requiring quick attention.
*   **MEDIUM:** Potential security concern to be examined.
*   **LOW:** Minimal risk, but worth noting.
*   **INFO:** Information that is not considered a risk.

#### Common Ports and Associated Risks

*   21 (FTP): HIGH - Unencrypted file transfer protocol.
*   22 (SSH): MEDIUM - Secure remote access, but should be limited.
*   23 (Telnet): CRITICAL - Unencrypted remote access protocol.
*   80 (HTTP): MEDIUM - Unencrypted web server.
*   443 (HTTPS): LOW - Encrypted web server (normal).
*   3389 (RDP): HIGH - Remote Desktop Protocol, a frequent target for attacks.

⚠️ **Security Best Practices** ⚠️

*   Only scan networks you have permission to scan.
*   Start by scanning only your own machine (localhost).
*   Avoid scanning corporate networks without authorization.
*   Close unused ports identified as risky.

### Troubleshooting

#### GUI Not Displaying Correctly

*   Ensure you have Tkinter installed correctly. On some systems, you may need to install it separately:

    ```bash
    sudo apt-get install python3-tk  # Debian/Ubuntu
    ```

#### Scan Too Slow

*   Use the "Quick" intensity option for a faster scan.
*   Limit your scan to a single IP address.

### Advanced Features

*   Evolving Knowledge Base: The tool remembers new port-risk associations.
*   Detailed Service Analysis: Identifies service versions for more accurate assessment.
*   Detection of Improper Configurations: Flags combinations of ports that pose a high risk.

## Licence

This project is private and cannot be used, modified, or distributed without permission.
All rights reserved © 2025.

### Disclaimer

This tool is intended for educational and defensive security purposes. Use it only on networks for which you have explicit authorization to perform security testing.
