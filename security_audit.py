"""
Security Audit and Log Analysis Module
Provides log analysis and security audit capabilities
"""

import re
import os
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from collections import Counter


class SecurityAudit:
    """Handles security audit and log analysis"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'failed_login': [
                r'failed.*login',
                r'authentication.*failed',
                r'invalid.*password',
                r'login.*denied',
                r'access.*denied',
            ],
            'suspicious_activity': [
                r'root.*login',
                r'sudo.*command',
                r'privilege.*escalation',
                r'unauthorized.*access',
                r'breach.*attempt',
            ],
            'error_patterns': [
                r'error.*\d{3}',
                r'exception.*thrown',
                r'critical.*error',
                r'system.*failure',
            ],
            'sql_injection': [
                r'select.*from',
                r'union.*select',
                r'drop.*table',
                r'exec.*\(.*\)',
                r'xp_cmdshell',
            ],
            'xss_attempts': [
                r'<script.*>',
                r'javascript:',
                r'onerror=',
                r'onload=',
            ],
            'path_traversal': [
                r'\.\./',
                r'\.\.\\\\',
                r'/etc/passwd',
                r'/windows/system32',
            ],
        }
    
    def analyze_log_file(self, log_file: str, pattern_type: str = 'all') -> Dict[str, any]:
        """
        Analyze log file for security events
        
        Args:
            log_file: Path to log file
            pattern_type: Type of patterns to check ('all', 'failed_login', 'suspicious_activity', etc.)
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'file': log_file,
            'total_lines': 0,
            'matches': {},
            'severity': 'low',
            'recommendations': []
        }
        
        try:
            if not os.path.exists(log_file):
                result['error'] = 'File not found'
                return result
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            result['total_lines'] = len(lines)
            
            # Determine which patterns to check
            if pattern_type == 'all':
                patterns_to_check = self.suspicious_patterns.keys()
            else:
                patterns_to_check = [pattern_type] if pattern_type in self.suspicious_patterns else []
            
            # Analyze each line
            for pattern_key in patterns_to_check:
                matches = []
                patterns = self.suspicious_patterns[pattern_key]
                
                for line_num, line in enumerate(lines, 1):
                    line_lower = line.lower()
                    for pattern in patterns:
                        if re.search(pattern, line_lower, re.IGNORECASE):
                            matches.append({
                                'line': line_num,
                                'content': line.strip()[:100],  # First 100 chars
                                'pattern': pattern
                            })
                            break  # Only count once per line
                
                if matches:
                    result['matches'][pattern_key] = matches
            
            # Determine severity
            total_matches = sum(len(matches) for matches in result['matches'].values())
            if total_matches > 100:
                result['severity'] = 'critical'
            elif total_matches > 50:
                result['severity'] = 'high'
            elif total_matches > 20:
                result['severity'] = 'medium'
            elif total_matches > 0:
                result['severity'] = 'low'
            
            # Generate recommendations
            if 'failed_login' in result['matches']:
                result['recommendations'].append('Review failed login attempts - possible brute force attack')
            if 'sql_injection' in result['matches']:
                result['recommendations'].append('CRITICAL: SQL injection attempts detected - immediate action required')
            if 'xss_attempts' in result['matches']:
                result['recommendations'].append('XSS attempts detected - review input validation')
            if 'path_traversal' in result['matches']:
                result['recommendations'].append('Path traversal attempts detected - review file access controls')
            
            result['match_count'] = total_matches
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def detect_brute_force(self, log_file: str, threshold: int = 10) -> Dict[str, any]:
        """
        Detect brute force attack patterns in logs
        
        Args:
            log_file: Path to log file
            threshold: Number of failed attempts to consider as brute force
        
        Returns:
            Dictionary with brute force detection results
        """
        result = {
            'brute_force_detected': False,
            'suspicious_ips': [],
            'attempt_counts': {},
            'time_windows': []
        }
        
        try:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            failed_login_patterns = self.suspicious_patterns['failed_login']
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            ip_attempts = Counter()
            
            for line in lines:
                line_lower = line.lower()
                # Check for failed login patterns
                if any(re.search(pattern, line_lower, re.IGNORECASE) for pattern in failed_login_patterns):
                    # Extract IP address
                    ip_matches = re.findall(ip_pattern, line)
                    if ip_matches:
                        ip_attempts[ip_matches[0]] += 1
            
            # Find IPs exceeding threshold
            for ip, count in ip_attempts.items():
                if count >= threshold:
                    result['brute_force_detected'] = True
                    result['suspicious_ips'].append({
                        'ip': ip,
                        'attempts': count,
                        'severity': 'critical' if count > 50 else 'high' if count > 20 else 'medium'
                    })
            
            result['attempt_counts'] = dict(ip_attempts.most_common(10))
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def analyze_access_logs(self, log_file: str) -> Dict[str, any]:
        """
        Analyze web access logs for security issues
        
        Args:
            log_file: Path to access log file
        
        Returns:
            Dictionary with access log analysis
        """
        result = {
            'total_requests': 0,
            'status_codes': Counter(),
            'top_ips': Counter(),
            'top_paths': Counter(),
            'suspicious_requests': [],
            'error_requests': []
        }
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            result['total_requests'] = len(lines)
            
            # Common log patterns
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            status_pattern = r'\s(\d{3})\s'
            path_pattern = r'"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s]+)\s+HTTP'
            
            for line in lines:
                # Extract status code
                status_match = re.search(status_pattern, line)
                if status_match:
                    status_code = status_match.group(1)
                    result['status_codes'][status_code] += 1
                    
                    # Track error requests (4xx, 5xx)
                    if status_code.startswith(('4', '5')):
                        result['error_requests'].append({
                            'status': status_code,
                            'line': line.strip()[:150]
                        })
                
                # Extract IP
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    result['top_ips'][ip_match.group(0)] += 1
                
                # Extract path
                path_match = re.search(path_pattern, line)
                if path_match:
                    path = path_match.group(1)
                    result['top_paths'][path] += 1
                    
                    # Check for suspicious paths
                    if any(pattern in path.lower() for pattern in ['admin', 'login', 'config', '.env', 'wp-admin']):
                        result['suspicious_requests'].append({
                            'path': path,
                            'line': line.strip()[:150]
                        })
            
            # Convert counters to dicts for JSON serialization
            result['status_codes'] = dict(result['status_codes'].most_common(10))
            result['top_ips'] = dict(result['top_ips'].most_common(10))
            result['top_paths'] = dict(result['top_paths'].most_common(20))
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def generate_audit_report(self, log_file: str) -> str:
        """
        Generate human-readable security audit report
        
        Args:
            log_file: Path to log file
        
        Returns:
            Formatted audit report string
        """
        analysis = self.analyze_log_file(log_file)
        brute_force = self.detect_brute_force(log_file)
        
        report = f"""
Security Audit Report
{'='*60}
File: {log_file}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Summary:
  Total Lines: {analysis['total_lines']}
  Matches Found: {analysis.get('match_count', 0)}
  Severity Level: {analysis['severity'].upper()}

Security Events:
"""
        
        for pattern_type, matches in analysis.get('matches', {}).items():
            report += f"\n  {pattern_type.replace('_', ' ').title()}: {len(matches)} matches\n"
            for match in matches[:5]:  # Show first 5
                report += f"    Line {match['line']}: {match['content']}\n"
        
        if brute_force.get('brute_force_detected'):
            report += f"\nBRUTE FORCE DETECTED:\n"
            for ip_info in brute_force['suspicious_ips']:
                report += f"  IP: {ip_info['ip']} - {ip_info['attempts']} attempts ({ip_info['severity']})\n"
        
        if analysis.get('recommendations'):
            report += f"\nRecommendations:\n"
            for rec in analysis['recommendations']:
                report += f"  → {rec}\n"
        
        return report
    
    def monitor_log_realtime(self, log_file: str, callback=None, check_interval: int = 5) -> Dict[str, any]:
        """
        Monitor log file for new security events (basic implementation)
        
        Args:
            log_file: Path to log file
            callback: Optional callback function for events
            check_interval: Check interval in seconds
        
        Returns:
            Dictionary with monitoring results
        """
        result = {
            'monitoring': False,
            'events_detected': 0,
            'last_check': None
        }
        
        try:
            # Get file size
            last_size = os.path.getsize(log_file) if os.path.exists(log_file) else 0
            
            # This is a simplified version - real implementation would use file watching
            result['last_check'] = datetime.now().isoformat()
            result['file_size'] = last_size
            result['monitoring'] = True
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def extract_ips_from_log(self, log_file: str) -> List[str]:
        """Extract all unique IP addresses from log file"""
        ips = set()
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    ip_matches = re.findall(ip_pattern, line)
                    ips.update(ip_matches)
        except Exception as e:
            print(f"Error extracting IPs: {str(e)}")
        
        return sorted(list(ips))
    
    def count_events_by_time(self, log_file: str, time_pattern: str = r'\d{4}-\d{2}-\d{2}') -> Dict[str, int]:
        """
        Count security events by time period
        
        Args:
            log_file: Path to log file
            time_pattern: Regex pattern to extract time/date
        
        Returns:
            Dictionary mapping time periods to event counts
        """
        events_by_time = Counter()
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    time_match = re.search(time_pattern, line)
                    if time_match:
                        time_period = time_match.group(0)
                        events_by_time[time_period] += 1
        except Exception as e:
            print(f"Error counting events: {str(e)}")
        
        return dict(events_by_time)
