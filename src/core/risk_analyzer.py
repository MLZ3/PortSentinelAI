"""
Risk analysis for open ports
"""
from dataclasses import dataclass
from typing import List

@dataclass
class PortRisk:
    port: int
    service: str
    risk_level: str
    description: str

class RiskAnalyzer:
    def __init__(self):
        self.risk_levels = {
            'HIGH': ['21', '23', '3389'],  # FTP, Telnet, RDP
            'MEDIUM': ['80', '443', '8080'],  # HTTP, HTTPS
            'LOW': ['53', '123']  # DNS, NTP
        }
    
    def analyze_port(self, port: int, service: str) -> PortRisk:
        """Analyze risk level of a specific port"""
        port_str = str(port)
        
        for level, ports in self.risk_levels.items():
            if port_str in ports:
                return PortRisk(
                    port=port,
                    service=service,
                    risk_level=level,
                    description=self._get_risk_description(port, service)
                )
        
        return PortRisk(
            port=port,
            service=service,
            risk_level='INFO',
            description='Standard port with no known high-risk vulnerabilities'
        )
    
    def _get_risk_description(self, port: int, service: str) -> str:
        """Generate risk description based on port and service"""
        # This would be expanded with more detailed descriptions
        return f"Port {port} ({service}) may pose security risks if not properly configured"