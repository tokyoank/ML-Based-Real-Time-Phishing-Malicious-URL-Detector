"""
Network Security Module
Provides basic network scanning and security checks
"""

import socket
import requests
import subprocess
import platform
from typing import List, Dict, Tuple
from urllib.parse import urlparse


class NetworkSecurity:
    """Handles network security operations"""
    
    def __init__(self):
        self.timeout = 5
    
    def check_port(self, host: str, port: int) -> Tuple[bool, str]:
        """
        Check if a port is open on a host
        
        Args:
            host: Hostname or IP address
            port: Port number to check
        
        Returns:
            Tuple of (is_open, status_message)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                return True, f"Port {port} is OPEN"
            else:
                return False, f"Port {port} is CLOSED"
        
        except socket.gaierror:
            return False, f"Hostname '{host}' could not be resolved"
        except Exception as e:
            return False, f"Error checking port: {str(e)}"
    
    def scan_common_ports(self, host: str, ports: List[int] = None) -> Dict[int, Tuple[bool, str]]:
        """
        Scan common ports on a host
        
        Args:
            host: Hostname or IP address
            ports: List of ports to scan (defaults to common ports)
        
        Returns:
            Dictionary mapping port numbers to (is_open, status) tuples
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432]
        
        results = {}
        for port in ports:
            is_open, status = self.check_port(host, port)
            results[port] = (is_open, status)
        
        return results
    
    def check_website_ssl(self, url: str) -> Dict[str, any]:
        """
        Check SSL certificate information for a website
        
        Args:
            url: Website URL to check
        
        Returns:
            Dictionary with SSL information
        """
        result = {
            'url': url,
            'has_ssl': False,
            'valid': False,
            'error': None
        }
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
                parsed = urlparse(url)
            
            response = requests.get(url, timeout=self.timeout, verify=True)
            result['has_ssl'] = True
            result['valid'] = True
            result['status_code'] = response.status_code
            
        except requests.exceptions.SSLError as e:
            result['has_ssl'] = True
            result['valid'] = False
            result['error'] = f"SSL Error: {str(e)}"
        
        except requests.exceptions.ConnectionError:
            result['error'] = "Connection failed"
        
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
        
        return result
    
    def check_dns_security(self, domain: str) -> Dict[str, any]:
        """
        Check DNS-related security information
        
        Args:
            domain: Domain name to check
        
        Returns:
            Dictionary with DNS security information
        """
        result = {
            'domain': domain,
            'resolves': False,
            'ip_addresses': [],
            'error': None
        }
        
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            result['resolves'] = True
            result['ip_addresses'] = ip_addresses
        
        except socket.gaierror:
            result['error'] = f"Domain '{domain}' could not be resolved"
        
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
        
        return result
    
    def ping_host(self, host: str) -> Dict[str, any]:
        """
        Ping a host to check connectivity
        
        Args:
            host: Hostname or IP address
        
        Returns:
            Dictionary with ping results
        """
        result = {
            'host': host,
            'reachable': False,
            'error': None
        }
        
        try:
            # Determine ping command based on OS
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', host]
            
            process = subprocess.run(command, capture_output=True, text=True, timeout=10)
            result['reachable'] = process.returncode == 0
            
            if not result['reachable']:
                result['error'] = "Host unreachable"
        
        except subprocess.TimeoutExpired:
            result['error'] = "Ping timeout"
        
        except Exception as e:
            result['error'] = f"Error: {str(e)}"
        
        return result
    
    def get_local_network_info(self) -> Dict[str, str]:
        """
        Get local network information
        
        Returns:
            Dictionary with local network info
        """
        info = {}
        
        try:
            hostname = socket.gethostname()
            info['hostname'] = hostname
            
            local_ip = socket.gethostbyname(hostname)
            info['local_ip'] = local_ip
            
        except Exception as e:
            info['error'] = str(e)
        
        return info
