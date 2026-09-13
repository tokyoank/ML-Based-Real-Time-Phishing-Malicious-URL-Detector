"""
Fake Wi-Fi / Evil Twin Detection Tool
Detects fake Wi-Fi networks and evil twin attacks
"""

import subprocess
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import platform


class EvilTwinDetector:
    """Detects fake Wi-Fi networks and evil twin attacks"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.known_legitimate_networks = set()  # User-defined legitimate networks
    
    def scan_wifi_networks(self) -> Dict[str, any]:
        """
        Scan for available Wi-Fi networks
        
        Returns:
            Dictionary with network scan results
        """
        result = {
            'networks_found': [],
            'suspicious_networks': [],
            'total_networks': 0,
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            if self.os_type == 'windows':
                networks = self._scan_windows_wifi()
            elif self.os_type == 'linux':
                networks = self._scan_linux_wifi()
            elif self.os_type == 'darwin':  # macOS
                networks = self._scan_macos_wifi()
            else:
                result['error'] = f'Wi-Fi scanning not supported on {self.os_type}'
                return result
            
            result['networks_found'] = networks
            result['total_networks'] = len(networks)
            
            # Analyze networks for suspicious patterns
            result['suspicious_networks'] = self._analyze_networks(networks)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _scan_windows_wifi(self) -> List[Dict]:
        """Scan Wi-Fi networks on Windows"""
        networks = []
        
        try:
            # Use netsh command
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], 
                                            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                                            text=True, errors='ignore')
            
            # Also try to get available networks
            try:
                output2 = subprocess.check_output(['netsh', 'wlan', 'show', 'network', 'mode=Bssid'],
                                                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
                                                text=True, errors='ignore')
                
                # Parse networks
                lines = output2.split('\n')
                current_network = {}
                
                for line in lines:
                    line = line.strip()
                    if 'SSID' in line and ':' in line:
                        if current_network:
                            networks.append(current_network)
                        current_network = {
                            'ssid': line.split(':', 1)[1].strip(),
                            'bssid': '',
                            'signal': '',
                            'encryption': ''
                        }
                    elif 'BSSID' in line and ':' in line:
                        current_network['bssid'] = line.split(':', 1)[1].strip()
                    elif 'Signal' in line and ':' in line:
                        current_network['signal'] = line.split(':', 1)[1].strip()
                    elif 'Authentication' in line and ':' in line:
                        current_network['encryption'] = line.split(':', 1)[1].strip()
                
                if current_network:
                    networks.append(current_network)
            
            except:
                # Fallback: create placeholder networks
                networks = [{'ssid': 'Network scanning requires admin privileges', 'note': 'Run as administrator'}]
        
        except Exception as e:
            networks = [{'error': str(e)}]
        
        return networks
    
    def _scan_linux_wifi(self) -> List[Dict]:
        """Scan Wi-Fi networks on Linux"""
        networks = []
        
        try:
            # Use nmcli or iw command
            try:
                output = subprocess.check_output(['nmcli', '-t', '-f', 'SSID,BSSID,SIGNAL,SECURITY', 'device', 'wifi', 'list'],
                                                text=True, errors='ignore')
                lines = output.split('\n')
                for line in lines:
                    if line.strip():
                        parts = line.split(':')
                        if len(parts) >= 4:
                            networks.append({
                                'ssid': parts[0],
                                'bssid': parts[1],
                                'signal': parts[2],
                                'encryption': parts[3]
                            })
            except:
                # Try iw command
                try:
                    output = subprocess.check_output(['iw', 'dev', 'wlan0', 'scan'], text=True, errors='ignore')
                    # Parse iw output (simplified)
                    current_network = {}
                    for line in output.split('\n'):
                        if 'SSID:' in line:
                            if current_network:
                                networks.append(current_network)
                            current_network = {'ssid': line.split('SSID:')[1].strip()}
                except:
                    networks = [{'note': 'Wi-Fi scanning requires appropriate permissions'}]
        
        except Exception as e:
            networks = [{'error': str(e)}]
        
        return networks
    
    def _scan_macos_wifi(self) -> List[Dict]:
        """Scan Wi-Fi networks on macOS"""
        networks = []
        
        try:
            # Use airport command or system_profiler
            output = subprocess.check_output(['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-s'],
                                            text=True, errors='ignore')
            
            lines = output.split('\n')[1:]  # Skip header
            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        networks.append({
                            'ssid': parts[0],
                            'bssid': parts[1] if len(parts) > 1 else '',
                            'signal': parts[2] if len(parts) > 2 else '',
                            'encryption': ' '.join(parts[3:]) if len(parts) > 3 else ''
                        })
        
        except:
            # Fallback
            networks = [{'note': 'Wi-Fi scanning may require permissions'}]
        
        return networks
    
    def _analyze_networks(self, networks: List[Dict]) -> List[Dict]:
        """
        Analyze networks for evil twin and suspicious patterns
        
        Args:
            networks: List of network dictionaries
        
        Returns:
            List of suspicious networks
        """
        suspicious = []
        
        # Group networks by SSID (case-insensitive)
        ssid_groups = {}
        for network in networks:
            ssid = network.get('ssid', '').lower()
            if ssid:
                if ssid not in ssid_groups:
                    ssid_groups[ssid] = []
                ssid_groups[ssid].append(network)
        
        # Check for duplicate SSIDs with different BSSIDs (evil twin)
        for ssid, network_list in ssid_groups.items():
            if len(network_list) > 1:
                bssids = [n.get('bssid', '') for n in network_list if n.get('bssid')]
                if len(set(bssids)) > 1:
                    suspicious.append({
                        'type': 'evil_twin',
                        'ssid': network_list[0].get('ssid'),
                        'networks': network_list,
                        'reason': f'Multiple networks with same SSID but different BSSIDs (possible evil twin)',
                        'severity': 'high'
                    })
        
        # Check for suspicious SSID patterns
        for network in networks:
            ssid = network.get('ssid', '')
            if ssid:
                # Check for lookalike SSIDs
                if any(self._similar_ssid(ssid, legit) for legit in self.known_legitimate_networks):
                    suspicious.append({
                        'type': 'lookalike',
                        'ssid': ssid,
                        'reason': f'SSID similar to known legitimate network',
                        'severity': 'medium'
                    })
                
                # Check for open networks with common names
                encryption = network.get('encryption', '').lower()
                common_names = ['free wifi', 'public wifi', 'guest', 'hotel', 'airport']
                if 'none' in encryption or 'open' in encryption:
                    if any(name in ssid.lower() for name in common_names):
                        suspicious.append({
                            'type': 'open_network',
                            'ssid': ssid,
                            'reason': 'Open network with common name (could be trap)',
                            'severity': 'medium'
                        })
        
        return suspicious
    
    def _similar_ssid(self, ssid1: str, ssid2: str, threshold: float = 0.8) -> bool:
        """
        Check if two SSIDs are similar (for lookalike detection)
        
        Args:
            ssid1: First SSID
            ssid2: Second SSID
            threshold: Similarity threshold
        
        Returns:
            True if similar
        """
        ssid1_lower = ssid1.lower()
        ssid2_lower = ssid2.lower()
        
        if ssid1_lower == ssid2_lower:
            return True
        
        # Simple character overlap similarity
        set1 = set(ssid1_lower)
        set2 = set(ssid2_lower)
        
        if len(set1) == 0 or len(set2) == 0:
            return False
        
        intersection = set1 & set2
        union = set1 | set2
        
        similarity = len(intersection) / len(union) if len(union) > 0 else 0
        
        return similarity >= threshold
    
    def detect_evil_twin(self, target_ssid: str) -> Dict[str, any]:
        """
        Specifically detect evil twin for a target SSID
        
        Args:
            target_ssid: SSID to check for evil twin
        
        Returns:
            Detection result
        """
        result = {
            'target_ssid': target_ssid,
            'evil_twin_detected': False,
            'legitimate_networks': [],
            'suspicious_networks': [],
            'recommendations': []
        }
        
        scan_result = self.scan_wifi_networks()
        networks = scan_result.get('networks_found', [])
        
        # Find all networks with matching SSID
        matching_networks = [n for n in networks if n.get('ssid', '').lower() == target_ssid.lower()]
        
        if len(matching_networks) > 1:
            result['evil_twin_detected'] = True
            bssids = [n.get('bssid', '') for n in matching_networks if n.get('bssid')]
            unique_bssids = len(set(bssids))
            
            if unique_bssids > 1:
                result['suspicious_networks'] = matching_networks
                result['recommendations'].append('EVIL TWIN DETECTED - Multiple networks with same SSID')
                result['recommendations'].append('Do not connect to any of these networks')
                result['recommendations'].append('Verify network BSSID with legitimate source')
        else:
            result['legitimate_networks'] = matching_networks
        
        return result
    
    def add_legitimate_network(self, ssid: str):
        """
        Add a network to the legitimate networks list
        
        Args:
            ssid: SSID of legitimate network
        """
        self.known_legitimate_networks.add(ssid.lower())
    
    def generate_network_report(self) -> str:
        """
        Generate Wi-Fi network security report
        
        Returns:
            Formatted report string
        """
        scan_result = self.scan_wifi_networks()
        
        report = f"""
Wi-Fi Network Security Report
{'='*60}
Scan Time: {scan_result['scan_time']}
{'='*60}

Networks Found: {scan_result['total_networks']}
Suspicious Networks: {len(scan_result['suspicious_networks'])}

Networks:
"""
        for network in scan_result.get('networks_found', [])[:20]:  # Show first 20
            ssid = network.get('ssid', 'Unknown')
            bssid = network.get('bssid', 'N/A')
            signal = network.get('signal', 'N/A')
            encryption = network.get('encryption', 'N/A')
            report += f"  {ssid}\n"
            report += f"    BSSID: {bssid}\n"
            report += f"    Signal: {signal}\n"
            report += f"    Encryption: {encryption}\n"
        
        if scan_result.get('suspicious_networks'):
            report += f"\n⚠ Suspicious Networks:\n"
            for suspicious in scan_result['suspicious_networks']:
                report += f"  {suspicious['type'].upper()}: {suspicious.get('ssid', 'N/A')}\n"
                report += f"    {suspicious['reason']}\n"
                report += f"    Severity: {suspicious.get('severity', 'unknown')}\n"
        
        report += f"\nRecommendations:\n"
        report += f"  → Only connect to known, trusted networks\n"
        report += f"  → Avoid open/public Wi-Fi networks\n"
        report += f"  → Use VPN when on public networks\n"
        report += f"  → Verify network names carefully\n"
        
        return report
