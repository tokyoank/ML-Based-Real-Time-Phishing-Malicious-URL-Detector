"""
Intrusion Detection System (IDS)
Monitors and detects suspicious network and system activities
"""

import re
import os
import socket
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict, Counter
try:
    from security_utilities import SecurityUtilities
    SECURITY_UTILS_AVAILABLE = True
except ImportError:
    SECURITY_UTILS_AVAILABLE = False


class IntrusionDetectionSystem:
    """Intrusion Detection System for monitoring security events"""
    
    def __init__(self):
        self.detection_rules = self._load_default_rules()
        self.alert_threshold = 5
        self.time_window = timedelta(hours=1)
        self.suspicious_activities = []
        
        # Known attack patterns
        self.attack_patterns = {
            'sql_injection': [
                r'union.*select',
                r'select.*from',
                r'drop.*table',
                r'exec.*\(.*\)',
                r'xp_cmdshell',
                r'1=1',
                r'1\'=\'1',
            ],
            'xss_attack': [
                r'<script.*>',
                r'javascript:',
                r'onerror=',
                r'onload=',
                r'eval\(',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\\\',
                r'/etc/passwd',
                r'/windows/system32',
                r'/etc/shadow',
            ],
            'command_injection': [
                r'\|\s*sh',
                r'\|\s*bash',
                r';\s*rm\s',
                r';\s*cat\s',
                r'&&\s*',
            ],
            'brute_force': [
                r'authentication.*failed',
                r'login.*failed',
                r'invalid.*password',
                r'access.*denied',
            ],
        }
    
    def _load_default_rules(self) -> Dict:
        """Load default intrusion detection rules"""
        return {
            'failed_login_threshold': 5,
            'port_scan_threshold': 10,
            'suspicious_request_threshold': 3,
            'time_window_minutes': 60,
        }
    
    def analyze_log_entry(self, log_entry: str, source_ip: str = None) -> Dict[str, any]:
        """
        Analyze a single log entry for intrusion indicators
        
        Args:
            log_entry: Log entry to analyze
            source_ip: Source IP address (optional)
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'suspicious': False,
            'threat_types': [],
            'confidence': 0.0,
            'indicators': [],
            'recommended_action': None
        }
        
        log_lower = log_entry.lower()
        
        # Check against attack patterns
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, log_lower, re.IGNORECASE):
                    result['suspicious'] = True
                    if attack_type not in result['threat_types']:
                        result['threat_types'].append(attack_type)
                    result['indicators'].append(f"{attack_type} pattern detected")
                    result['confidence'] += 20
        
        # Determine recommended action
        if result['suspicious']:
            if 'sql_injection' in result['threat_types'] or 'xss_attack' in result['threat_types']:
                result['recommended_action'] = 'BLOCK_IP'
            elif 'brute_force' in result['threat_types']:
                result['recommended_action'] = 'RATE_LIMIT'
            else:
                result['recommended_action'] = 'ALERT'
        
        result['confidence'] = min(100, result['confidence'])
        
        return result
    
    def detect_port_scan(self, port_attempts: List[Tuple[str, int]], 
                        time_window: timedelta = None) -> Dict[str, any]:
        """
        Detect port scanning activity
        
        Args:
            port_attempts: List of (ip, port) tuples
            time_window: Time window for analysis
        
        Returns:
            Dictionary with port scan detection results
        """
        if time_window is None:
            time_window = self.time_window
        
        result = {
            'port_scan_detected': False,
            'suspicious_ips': [],
            'scan_patterns': {}
        }
        
        # Group by IP
        ip_ports = defaultdict(set)
        for ip, port in port_attempts:
            ip_ports[ip].add(port)
        
        # Check for port scanning patterns
        for ip, ports in ip_ports.items():
            if len(ports) >= self.detection_rules['port_scan_threshold']:
                result['port_scan_detected'] = True
                result['suspicious_ips'].append({
                    'ip': ip,
                    'ports_scanned': len(ports),
                    'ports': sorted(list(ports))[:20],  # First 20 ports
                    'severity': 'high' if len(ports) > 50 else 'medium'
                })
                
                # Check for sequential port scanning
                sorted_ports = sorted(ports)
                sequential_count = 0
                for i in range(len(sorted_ports) - 1):
                    if sorted_ports[i+1] - sorted_ports[i] == 1:
                        sequential_count += 1
                
                if sequential_count > 10:
                    result['scan_patterns'][ip] = 'sequential'
        
        return result
    
    def detect_brute_force(self, failed_attempts: List[Dict]) -> Dict[str, any]:
        """
        Detect brute force attacks
        
        Args:
            failed_attempts: List of dictionaries with 'ip', 'timestamp', 'type' keys
        
        Returns:
            Dictionary with brute force detection results
        """
        result = {
            'brute_force_detected': False,
            'attacking_ips': [],
            'total_attempts': len(failed_attempts)
        }
        
        # Group by IP
        ip_attempts = Counter()
        ip_timestamps = defaultdict(list)
        
        for attempt in failed_attempts:
            ip = attempt.get('ip')
            if ip:
                ip_attempts[ip] += 1
                if 'timestamp' in attempt:
                    ip_timestamps[ip].append(attempt['timestamp'])
        
        # Check threshold
        threshold = self.detection_rules['failed_login_threshold']
        
        for ip, count in ip_attempts.items():
            if count >= threshold:
                result['brute_force_detected'] = True
                
                # Calculate attempt rate
                if ip in ip_timestamps and len(ip_timestamps[ip]) > 1:
                    timestamps = sorted(ip_timestamps[ip])
                    time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                    rate = count / time_span if time_span > 0 else count
                else:
                    rate = count
                
                result['attacking_ips'].append({
                    'ip': ip,
                    'attempts': count,
                    'rate_per_second': rate,
                    'severity': 'critical' if count > 20 else 'high' if count > 10 else 'medium',
                    'recommended_action': 'BLOCK_IP'
                })
        
        return result
    
    def detect_anomalous_traffic(self, traffic_data: List[Dict]) -> Dict[str, any]:
        """
        Detect anomalous network traffic patterns
        
        Args:
            traffic_data: List of traffic records with 'ip', 'bytes', 'timestamp'
        
        Returns:
            Dictionary with anomaly detection results
        """
        result = {
            'anomalies_detected': False,
            'suspicious_ips': [],
            'traffic_patterns': {}
        }
        
        # Group by IP
        ip_traffic = defaultdict(list)
        for record in traffic_data:
            ip = record.get('ip')
            if ip:
                ip_traffic[ip].append(record.get('bytes', 0))
        
        # Calculate statistics
        for ip, bytes_list in ip_traffic.items():
            if bytes_list:
                avg_bytes = sum(bytes_list) / len(bytes_list)
                max_bytes = max(bytes_list)
                
                # Detect spikes
                if max_bytes > avg_bytes * 10 and max_bytes > 1000000:  # 10x average and >1MB
                    result['anomalies_detected'] = True
                    result['suspicious_ips'].append({
                        'ip': ip,
                        'average_bytes': avg_bytes,
                        'max_bytes': max_bytes,
                        'spike_ratio': max_bytes / avg_bytes,
                        'severity': 'high' if max_bytes > 10000000 else 'medium'
                    })
        
        return result
    
    def monitor_file_changes(self, file_path: str, baseline_hash: str = None) -> Dict[str, any]:
        """
        Monitor file for unauthorized changes
        
        Args:
            file_path: Path to file to monitor
            baseline_hash: Expected hash value (optional)
        
        Returns:
            Dictionary with file monitoring results
        """
        result = {
            'file_path': file_path,
            'modified': False,
            'integrity': 'unknown',
            'change_detected': False
        }
        
        try:
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result
            
            # Get file stats
            stat = os.stat(file_path)
            result['size'] = stat.st_size
            result['modified_time'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            # Check hash if baseline provided
            if baseline_hash and SECURITY_UTILS_AVAILABLE:
                su = SecurityUtilities()
                current_hash = su.hash_file(file_path)
                if current_hash:
                    result['current_hash'] = current_hash
                    if current_hash != baseline_hash:
                        result['change_detected'] = True
                        result['integrity'] = 'compromised'
                    else:
                        result['integrity'] = 'intact'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def generate_alert(self, event_type: str, details: Dict) -> Dict[str, any]:
        """
        Generate security alert
        
        Args:
            event_type: Type of security event
            details: Event details
        
        Returns:
            Alert dictionary
        """
        alert = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'severity': details.get('severity', 'medium'),
            'details': details,
            'alert_id': f"{event_type}_{datetime.now().timestamp()}"
        }
        
        self.suspicious_activities.append(alert)
        return alert
    
    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """
        Get recent security alerts
        
        Args:
            hours: Number of hours to look back
        
        Returns:
            List of recent alerts
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        recent_alerts = [
            alert for alert in self.suspicious_activities
            if datetime.fromisoformat(alert['timestamp']) >= cutoff_time
        ]
        
        return sorted(recent_alerts, key=lambda x: x['timestamp'], reverse=True)
    
    def generate_ids_report(self, log_file: str = None) -> str:
        """
        Generate IDS activity report
        
        Args:
            log_file: Optional log file to analyze
        
        Returns:
            Formatted report string
        """
        report = f"""
Intrusion Detection System Report
{'='*60}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Recent Alerts ({len(self.suspicious_activities)} total):
"""
        
        recent_alerts = self.get_recent_alerts(24)
        for alert in recent_alerts[:20]:  # Show last 20
            report += f"\n{alert['timestamp']} - {alert['event_type']} ({alert['severity']})\n"
            for key, value in alert['details'].items():
                if key != 'severity':
                    report += f"  {key}: {value}\n"
        
        if log_file:
            report += f"\nLog File Analysis: {log_file}\n"
            # Could add log analysis here
        
        return report
    
    def configure_rules(self, rules: Dict):
        """
        Configure IDS detection rules
        
        Args:
            rules: Dictionary of rule configurations
        """
        self.detection_rules.update(rules)
    
    def reset_alerts(self):
        """Clear all stored alerts"""
        self.suspicious_activities = []
