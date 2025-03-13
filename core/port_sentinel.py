#!/usr/bin/env python3
"""
PortSentinel AI - Intelligent Network Port Scanner (Pure Python Version)
A security tool for scanning networks for open ports and assessing risk.
This version is not dependent on nmap, using only standard Python libraries.
"""

import sys
import socket
import ipaddress
import logging
import json
import csv
import threading
import time
import concurrent.futures
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional, Union
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox


# Configuring logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("PortSentinel")

# Risk assessment database with common ports and their security implications
PORT_RISK_DB = {
    21: {"service": "FTP", "risk": "HIGH", "reason": "Unencrypted file transfer protocol"},
    22: {"service": "SSH", "risk": "MEDIUM", "reason": "Remote access - secure but should be restricted"},
    23: {"service": "Telnet", "risk": "CRITICAL", "reason": "Unencrypted remote access protocol"},
    25: {"service": "SMTP", "risk": "MEDIUM", "reason": "Mail server port - should be secured"},
    53: {"service": "DNS", "risk": "LOW", "reason": "Domain name resolution - normal for servers"},
    80: {"service": "HTTP", "risk": "MEDIUM", "reason": "Unencrypted web server"},
    110: {"service": "POP3", "risk": "HIGH", "reason": "Unencrypted mail retrieval"},
    135: {"service": "RPC", "risk": "HIGH", "reason": "Windows RPC service - often exploited"},
    139: {"service": "NetBIOS", "risk": "HIGH", "reason": "Windows/Samba file sharing - should be firewalled"},
    143: {"service": "IMAP", "risk": "HIGH", "reason": "Unencrypted mail access protocol"},
    443: {"service": "HTTPS", "risk": "LOW", "reason": "Encrypted web server - normal"},
    445: {"service": "SMB", "risk": "HIGH", "reason": "Windows file sharing - frequent attack target"},
    1433: {"service": "MSSQL", "risk": "MEDIUM", "reason": "Database server - restrict access"},
    1521: {"service": "Oracle", "risk": "MEDIUM", "reason": "Database server - restrict access"},
    3306: {"service": "MySQL", "risk": "MEDIUM", "reason": "Database server - restrict access"},
    3389: {"service": "RDP", "risk": "HIGH", "reason": "Remote Desktop Protocol - frequent attack target"},
    5432: {"service": "PostgreSQL", "risk": "MEDIUM", "reason": "Database server - restrict access"},
    5900: {"service": "VNC", "risk": "HIGH", "reason": "Remote desktop sharing - restrict access"},
    8080: {"service": "HTTP-ALT", "risk": "MEDIUM", "reason": "Alternative HTTP port - often used for admin interfaces"},
}

# Risk levels and their corresponding numerical scores for sorting
RISK_LEVELS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}

# Dictionary of known services and their standard ports
SERVICE_PORT_MAP = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-TRAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    464: "Kerberos-Change",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC-1",
    5902: "VNC-2",
    5903: "VNC-3",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class NetworkUtils:
    """Utility methods for network operations and validation."""

    @staticmethod
    def get_local_ip() -> str:
        """Get the local IP address of the machine."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return local_ip
        except Exception as e:
            logger.error(f"Error determining local IP: {e}")
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    @staticmethod
    def is_private_ip(ip_addr: str) -> bool:
        """Check if an IP address is in a private range."""
        try:
            ip = ipaddress.ip_address(ip_addr)
            return ip.is_private
        except ValueError:
            return False

    @staticmethod
    def validate_ip_or_network(target: str) -> bool:
        """Validate if the input is a valid IP address or network."""
        try:
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
            else:
                ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_network_from_ip(ip_addr: str, prefix_length: int = 24) -> str:
        """Get network address from IP with specified prefix length."""
        try:
            ip = ipaddress.ip_address(ip_addr)
            network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
            return str(network)
        except ValueError as e:
            logger.error(f"Error calculating network from IP: {e}")
            return f"{ip_addr}/{prefix_length}"

    @staticmethod
    def resolve_hostname(hostname: str) -> str:
        """Resolve a hostname to an IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return None

    @staticmethod
    def get_hostname(ip_addr: str) -> str:
        """Get the hostname for an IP address."""
        try:
            return socket.gethostbyaddr(ip_addr)[0]
        except (socket.herror, socket.gaierror):
            return ""


class PortScanner:
    """Main port scanning engine with security checks."""

    def __init__(self, target: str = None, port_range: Tuple[int, int] = (1, 1024),
                 timeout: float = 1.0, threads: int = 100, intensity: str = "standard"):
        """Initialize the scanner."""
        self.target = target
        self.port_range = port_range
        self.timeout = timeout
        self.threads = min(threads, 200)
        self.intensity = intensity
        self.intelligence_engine = RiskAssessmentEngine()

        if intensity == "quick":
            self.common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                                 1433, 3306, 3389, 5432, 5900, 8080]
            self.scan_common_only = True
        elif intensity == "intensive":
            self.timeout = max(0.5, self.timeout)
            self.scan_common_only = False
        else:
            self.scan_common_only = False

    def verify_target_safety(self) -> Tuple[bool, str]:
        """Perform safety checks before scanning."""
        if not self.target:
            return False, "No target specified."

        if self.target == "127.0.0.1" or self.target == "localhost":
            return True, "Scanning localhost is safe."

        if not NetworkUtils.validate_ip_or_network(self.target):
            resolved_ip = NetworkUtils.resolve_hostname(self.target)
            if resolved_ip:
                self.target = resolved_ip
            else:
                return False, f"Invalid IP address or network format: {self.target}"

        if '/' not in self.target:
            if not NetworkUtils.is_private_ip(self.target):
                return False, ("⚠️ WARNING: "
                               f"{self.target} appears to be a public IP address. "
                               "Scanning public IPs may be illegal without proper authorization.")
            return True, f"{self.target} is a private IP address, safe to scan."

        try:
            network = ipaddress.ip_network(self.target, strict=False)
            if not network.is_private:
                return False, ("⚠️ WARNING: "
                               f"{self.target} appears to be a public network. "
                               "Scanning public networks may be illegal without proper authorization.")
            if network.num_addresses > 1024:
                return False, ("⚠️ The network "
                               f"{self.target} contains {network.num_addresses} addresses. "
                               "Scanning large networks can take a long time and potentially disrupt the network.")
            return True, f"{self.target} is a private network, safe to scan."
        except ValueError as e:
            return False, f"Error validating network: {e}"

    def _check_port(self, ip: str, port: int) -> Dict:
        """Check if a specific port is open."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        result = sock.connect_ex((ip, port))
        is_open = (result == 0)

        port_info = {
            "port": port,
            "protocol": "tcp",
            "state": "open" if is_open else "closed"
        }

        if is_open:
            service = "unknown"
            try:
                service = socket.getservbyport(port)
            except (OSError, socket.error):
                if port in SERVICE_PORT_MAP:
                    service = SERVICE_PORT_MAP[port]

            port_info["service"] = service

            if self.intensity == "intensive":
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                    if banner:
                        banner_str = banner.decode('utf-8', errors='ignore').strip()
                        port_info["banner"] = banner_str

                        if "Server:" in banner_str:
                            server_info = banner_str.split("Server:")[1].split("\r\n")[0].strip()
                            port_info["product"] = server_info
                except Exception:
                    pass

        sock.close()
        return port_info

    def _scan_host(self, ip: str) -> Dict:
        """Scan a host for open ports."""
        start_time = time.time()

        is_up = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            is_up = sock.connect_ex((ip, 80)) == 0 or sock.connect_ex((ip, 443)) == 0
            sock.close()

            if not is_up:
                is_up = True
        except Exception:
            pass

        if not is_up:
            return {
                "state": "down",
                "hostname": "",
                "ports": []
            }

        hostname = NetworkUtils.get_hostname(ip)

        ports_to_scan = []
        if self.scan_common_only:
            ports_to_scan = self.common_ports
        else:
            ports_to_scan = list(range(self.port_range[0], self.port_range[1] + 1))

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip, port): port for port in ports_to_scan
            }

            for future in concurrent.futures.as_completed(future_to_port):
                port_info = future.result()
                if port_info["state"] == "open":
                    risk_data = self.intelligence_engine.assess_port_risk(
                        port_info["port"], port_info["service"])
                    port_info.update(risk_data)
                    open_ports.append(port_info)

        open_ports.sort(
            key=lambda x: (RISK_LEVELS.get(x.get("risk", "INFO"), 0) * -1, x["port"])
        )

        overall_risk = self.intelligence_engine.assess_host_risk(open_ports)

        end_time = time.time()

        return {
            "hostname": hostname,
            "state": "up",
            "scan_time": end_time - start_time,
            "ports": open_ports,
            "overall_risk": overall_risk
        }

    def scan(self) -> Dict:
        """Perform the port scan on the specified target."""
        if not self.target:
            logger.error("No target specified for the scan")
            return {"error": "No target specified"}

        start_time = datetime.now()

        try:
            hosts_to_scan = []

            if '/' in self.target:
                try:
                    network = ipaddress.ip_network(self.target, strict=False)
                    hosts_to_scan = [str(ip) for ip in network.hosts()]
                except ValueError as e:
                    return {"error": f"Invalid network format: {e}"}
            else:
                if not NetworkUtils.validate_ip_or_network(self.target):
                    resolved_ip = NetworkUtils.resolve_hostname(self.target)
                    if not resolved_ip:
                        return {"error": f"Unable to resolve hostname: {self.target}"}
                    hosts_to_scan = [resolved_ip]
                else:
                    hosts_to_scan = [self.target]

            logger.info(f"Starting scan on {len(hosts_to_scan)} hosts with intensity {self.intensity}")

            results = {
                "scan_info": {
                    "target": self.target,
                    "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "elapsed": "In progress...",
                    "hosts_total": len(hosts_to_scan),
                    "hosts_up": 0,
                    "port_range": (f"{self.port_range[0]}-{self.port_range[1]}"
                                   if not self.scan_common_only else "common ports")
                },
                "hosts": {}
            }

            for ip in hosts_to_scan:
                logger.info(f"Scanning {ip}...")
                host_results = self._scan_host(ip)
                results["hosts"][ip] = host_results

                if host_results["state"] == "up":
                    results["scan_info"]["hosts_up"] += 1

            end_time = datetime.now()
            elapsed = end_time - start_time
            results["scan_info"]["elapsed"] = str(elapsed)
            logger.info(f"Scan completed. Duration: {elapsed}, Active hosts: {results['scan_info']['hosts_up']}")

            return results

        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return {"error": str(e)}


class RiskAssessmentEngine:
    """AI-inspired engine that analyzes scan results to identify security risks."""

    def __init__(self, db: Dict = None):
        """Initialize with an optional custom risk database."""
        self.risk_db = db if db else PORT_RISK_DB
        self.learning_data = []

    def assess_port_risk(self, port: int, service: str) -> Dict:
        """Assess the risk level of an open port."""
        if port in self.risk_db:
            risk_info = self.risk_db[port].copy()
            self.learning_data.append({
                "port": port,
                "service": service,
                "source": "database",
                "risk": risk_info["risk"]
            })
            return risk_info

        if port < 1024:
            return {
                "service": service,
                "risk": "MEDIUM",
                "reason": "Unknown privileged port - potentially sensitive service"
            }
        elif port < 49152:
            return {
                "service": service,
                "risk": "LOW",
                "reason": "Unknown registered port - may be an application service"
            }
        else:
            return {
                "service": service,
                "risk": "INFO",
                "reason": "High-numbered port - likely a temporary or private application"
            }

    def assess_host_risk(self, ports: List[Dict]) -> Dict:
        """Calculate the overall risk for a host based on its open ports."""
        if not ports:
            return {"level": "INFO", "reason": "No open ports detected"}

        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for port in ports:
            risk_level = port.get("risk", "INFO")
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

        if risk_counts["CRITICAL"] > 0:
            level = "CRITICAL"
            reason = f"Found {risk_counts['CRITICAL']} ports with critical risk"
        elif risk_counts["HIGH"] > 2:
            level = "CRITICAL"
            reason = "Multiple high-risk ports indicate significant exposure"
        elif risk_counts["HIGH"] > 0:
            level = "HIGH"
            reason = f"Found {risk_counts['HIGH']} ports with high risk"
        elif risk_counts["MEDIUM"] > 3:
            level = "HIGH"
            reason = "Multiple medium-risk ports indicate potential exposure"
        elif risk_counts["MEDIUM"] > 0:
            level = "MEDIUM"
            reason = f"Found {risk_counts['MEDIUM']} ports with medium risk"
        elif risk_counts["LOW"] > 0:
            level = "LOW"
            reason = "Only low-risk ports detected"
        else:
            level = "INFO"
            reason = "Only informational ports detected"

        if level in ["CRITICAL", "HIGH"]:
            recommendations = [
                "Review and close unnecessary ports immediately",
                "Implement firewall rules",
                "Ensure all services are updated"
            ]
        elif level == "MEDIUM":
            recommendations = [
                "Examine open ports and restrict access if possible",
                "Implement proper authentication",
                "Keep all services updated"
            ]
        else:
            recommendations = [
                "Monitor services regularly",
                "Keep software updated"
            ]

        return {
            "level": level,
            "reason": reason,
            "statistics": risk_counts,
            "recommendations": recommendations
        }

    def update_knowledge(self, port: int, service: str, risk: str, reason: str) -> None:
        """Update the risk database with new information."""
        if risk not in RISK_LEVELS:
            logger.warning(f"Invalid risk level: {risk}")
            return

        self.risk_db[port] = {
            "service": service,
            "risk": risk,
            "reason": reason
        }
        logger.info(f"Risk database updated for port {port}/{service}")


class ReportGenerator:
    """Generates human-readable reports from scan results."""

    @staticmethod
    def generate_text_report(scan_results: Dict) -> str:
        """Generate a plain text report from the scan results."""
        if "error" in scan_results:
            return f"ERROR: {scan_results['error']}"

        if not scan_results.get("hosts"):
            return "No hosts found in scan results."

        report = []
        report.append("===== PORTSENTINEL AI SCAN REPORT =====")
        report.append(f"Target: {scan_results['scan_info']['target']}")
        report.append(f"Time: {scan_results['scan_info']['start_time']}")
        report.append(f"Duration: {scan_results['scan_info']['elapsed']}")
        report.append(f"Hosts Scanned: {scan_results['scan_info']['hosts_total']}")
        report.append(f"Active Hosts: {scan_results['scan_info']['hosts_up']}")
        report.append(f"Port Range: {scan_results['scan_info'].get('port_range', 'Unspecified')}")
        report.append("\n")

        for host, host_data in scan_results["hosts"].items():
            report.append(f"HOST: {host} ({host_data['hostname']})")
            report.append(f"Status: {host_data['state']}")

            if host_data["state"] == "down":
                report.append("Host is down - no ports scanned.\n")
                continue

            overall_risk = host_data.get("overall_risk", {})
            risk_level = overall_risk.get("level", "UNKNOWN")
            report.append(f"RISK ASSESSMENT: {risk_level}")
            report.append(f"Reason: {overall_risk.get('reason', 'N/A')}")

            if "statistics" in overall_risk:
                stats = []
                for level, count in overall_risk["statistics"].items():
                    if count > 0:
                        stats.append(f"{level}: {count}")
                report.append(f"Risk Breakdown: {', '.join(stats)}")

            if "recommendations" in overall_risk:
                report.append("\nRECOMMENDATIONS:")
                for i, rec in enumerate(overall_risk["recommendations"], 1):
                    report.append(f"{i}. {rec}")

            report.append("\nOpen Ports:")
            if host_data["ports"]:
                for port_info in host_data["ports"]:
                    report.append(
                        f"  Port {port_info['port']}/{port_info['protocol'].upper()} - "
                        f"Service: {port_info.get('service', 'Unknown')}, "
                        f"Risk: {port_info.get('risk', 'INFO')}, "
                        f"Reason: {port_info.get('reason', 'N/A')}"
                    )
                    if "banner" in port_info:
                        report.append(f"    Banner: {port_info['banner']}")
                    if "product" in port_info:
                        report.append(f"    Product: {port_info['product']}")
            else:
                report.append("  No open ports found.")
            report.append("\n")

        report_str = "\n".join(report)
        return report_str

    @staticmethod
    def save_report(report_content: str, filename: str = None) -> None:
        """Save the report content to a file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"PortSentinel_ScanReport_{timestamp}.txt"

        try:
            with open(filename, "w") as f:
                f.write(report_content)
            logger.info(f"Report saved to: {filename}")
        except Exception as e:
            logger.error(f"Error saving report to file: {e}")


class PortScannerGUI:
    """Graphical User Interface for PortSentinel AI."""

    def __init__(self, master):
        """Initialize the GUI."""
        self.master = master
        master.title("PortSentinel AI - GUI")

        # Target Input
        self.target_label = ttk.Label(master, text="Target IP/Network:")
        self.target_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.target_entry = ttk.Entry(master, width=30)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.E)

        # Port Range Input (Simplified)
        self.common_ports_var = tk.BooleanVar()
        self.common_ports_checkbox = ttk.Checkbutton(master, text="Scan Common Ports Only", variable=self.common_ports_var)
        self.common_ports_checkbox.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

        # Intensity Selection
        self.intensity_label = ttk.Label(master, text="Intensity:")
        self.intensity_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.intensity_var = tk.StringVar(value="standard")
        self.intensity_combo = ttk.Combobox(master, textvariable=self.intensity_var,
                                             values=["quick", "standard", "intensive"], state="readonly")
        self.intensity_combo.grid(row=2, column=1, padx=5, pady=5, sticky=tk.E)

        # Scan Button
        self.scan_button = ttk.Button(master, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, padx=5, pady=10)

        # Results Display
        self.results_text = tk.Text(master, height=10, width=50)
        self.results_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def start_scan(self):
        """Start the port scan."""
        target = self.target_entry.get()
        common_ports_only = self.common_ports_var.get()
        intensity = self.intensity_var.get()

        if not target:
            messagebox.showerror("Error", "Please enter a target IP or network.")
            return

        self.scan_button["state"] = "disabled"
        self.results_text.delete("1.0", tk.END)
        self.results_text.insert(tk.END, "Scanning... Please wait.\n")

        def run_scan():
            """Inner function to run scan in a separate thread."""
            try:
                port_range = (1, 1024) if not common_ports_only else (1, 1024)

                scanner = PortScanner(target=target, port_range=port_range, intensity=intensity)

                is_safe, message = scanner.verify_target_safety()
                if not is_safe:
                    messagebox.showerror("Error", message)
                    self.scan_button["state"] = "normal"
                    return

                scan_results = scanner.scan()

                report_content = ReportGenerator.generate_text_report(scan_results)

                self.results_text.delete("1.0", tk.END)
                self.results_text.insert(tk.END, report_content)

                messagebox.showinfo("Success", "Scan Completed!")

            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")
                self.results_text.insert(tk.END, f"Error: {e}\n")
            finally:
                self.scan_button["state"] = "normal"  # Re-enable button in all cases

        scan_thread = threading.Thread(target=run_scan)
        scan_thread.start()


if __name__ == "__main__":
    root = tk.Tk()
    gui = PortScannerGUI(root)
    root.mainloop()
