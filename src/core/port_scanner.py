"""
Port scanning functionality using nmap
"""
import nmap
from typing import Dict, List, Optional

class PortScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()
        
    def scan_target(self, target_ip: str, scan_type: str = 'quick') -> Dict:
        """
        Scan a specific target IP with the specified scan type
        
        Args:
            target_ip: The IP address to scan
            scan_type: Type of scan ('quick', 'medium', 'slow')
            
        Returns:
            Dict containing scan results
        """
        scan_types = {
            'quick': '-sS -T4 --top-ports 100',  # Fast SYN scan of top 100 ports
            'medium': '-sT -T3 -p-',  # Full TCP Connect scan
            'slow': '-sS -sV -O -T2 -p-'  # Comprehensive scan with service detection
        }
        
        args = scan_types.get(scan_type, scan_types['quick'])
        
        try:
            scan_results = self.scanner.scan(target_ip, arguments=args)
            return self._process_results(scan_results)
        except Exception as e:
            print(f"Scan failed: {str(e)}")
            return {"error": str(e)}
            
    def _process_results(self, results: Dict) -> Dict:
        """Process and format scan results"""
        if not results or 'scan' not in results:
            return {"error": "No scan results"}
            
        processed = {
            "ports": [],
            "summary": {
                "total": 0,
                "open": 0,
                "closed": 0,
                "filtered": 0
            }
        }
        
        for host in results['scan'].values():
            if 'tcp' not in host:
                continue
                
            for port, data in host['tcp'].items():
                port_info = {
                    "number": port,
                    "status": data['state'],
                    "service": data.get('name', 'unknown'),
                    "riskLevel": self._assess_risk_level(port, data)
                }
                processed["ports"].append(port_info)
                
                # Update summary
                processed["summary"]["total"] += 1
                processed["summary"][data['state']] = processed["summary"].get(data['state'], 0) + 1
                
        return processed
        
    def _assess_risk_level(self, port: int, data: Dict) -> str:
        """Assess the risk level of a port based on service and state"""
        high_risk_ports = {21, 23, 3389, 445}  # FTP, Telnet, RDP, SMB
        medium_risk_ports = {80, 443, 8080, 22}  # HTTP, HTTPS, Alt HTTP, SSH
        low_risk_ports = {53, 123}  # DNS, NTP
        
        if port in high_risk_ports and data['state'] == 'open':
            return 'HIGH'
        elif port in medium_risk_ports and data['state'] == 'open':
            return 'MEDIUM'
        elif port in low_risk_ports and data['state'] == 'open':
            return 'LOW'
        return 'INFO'