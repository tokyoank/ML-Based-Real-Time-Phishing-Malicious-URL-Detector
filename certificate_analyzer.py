"""
Certificate Analyzer Module
Provides detailed SSL/TLS certificate analysis
"""

import socket
import ssl
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse


class CertificateAnalyzer:
    """Handles SSL/TLS certificate analysis"""
    
    def __init__(self):
        self.timeout = 10
    
    def analyze_certificate(self, hostname: str, port: int = 443) -> Dict[str, any]:
        """
        Analyze SSL/TLS certificate for a hostname
        
        Args:
            hostname: Hostname or IP address
            port: Port number (default: 443)
        
        Returns:
            Dictionary with certificate information
        """
        result = {
            'hostname': hostname,
            'port': port,
            'certificate_found': False,
            'valid': False,
            'expired': False,
            'error': None,
            'certificate_info': {},
            'security_score': 0,
            'warnings': [],
            'recommendations': []
        }
        
        try:
            # Remove port if present in hostname
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    result['certificate_found'] = True
                    
                    # Extract certificate information
                    cert_info = self._extract_cert_info(cert)
                    result['certificate_info'] = cert_info
                    
                    # Check validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.utcnow()
                    
                    if now > not_after:
                        result['expired'] = True
                        result['warnings'].append('Certificate has expired!')
                        result['security_score'] -= 50
                    elif now < not_before:
                        result['warnings'].append('Certificate is not yet valid')
                        result['security_score'] -= 30
                    else:
                        result['valid'] = True
                        result['security_score'] += 50
                    
                    # Check expiration date
                    days_until_expiry = (not_after - now).days
                    if days_until_expiry < 30:
                        result['warnings'].append(f'Certificate expires in {days_until_expiry} days')
                        result['security_score'] -= 20
                    elif days_until_expiry < 90:
                        result['warnings'].append(f'Certificate expires in {days_until_expiry} days - renew soon')
                        result['security_score'] -= 10
                    
                    # Check certificate chain (basic)
                    # Check issuer
                    if 'issuer' in cert_info:
                        issuer = cert_info['issuer']
                        trusted_issuers = ['Let\'s Encrypt', 'DigiCert', 'GlobalSign', 'Comodo', 'GoDaddy']
                        if not any(trusted in issuer for trusted in trusted_issuers):
                            result['recommendations'].append('Consider using a certificate from a trusted CA')
                    
                    # Check subject alternative names
                    if 'subject_alt_names' in cert_info:
                        sans = cert_info['subject_alt_names']
                        if hostname not in sans and not any(hostname.endswith(f'.{san}') for san in sans):
                            result['warnings'].append('Hostname mismatch - certificate may not be valid for this domain')
                            result['security_score'] -= 30
                    
                    # Check key size (if available)
                    # SSL version check
                    result['ssl_version'] = ssock.version()
                    if ssock.version() in ['TLSv1', 'TLSv1.1']:
                        result['warnings'].append(f'Using deprecated SSL/TLS version: {ssock.version()}')
                        result['security_score'] -= 30
                        result['recommendations'].append('Upgrade to TLS 1.2 or higher')
                    elif ssock.version() in ['TLSv1.2', 'TLSv1.3']:
                        result['security_score'] += 20
                    
                    result['security_score'] = max(0, min(100, result['security_score']))
        
        except socket.gaierror:
            result['error'] = f'Could not resolve hostname: {hostname}'
        except socket.timeout:
            result['error'] = 'Connection timeout'
        except ssl.SSLError as e:
            result['error'] = f'SSL Error: {str(e)}'
            result['certificate_found'] = False
        except Exception as e:
            result['error'] = f'Error: {str(e)}'
        
        return result
    
    def _extract_cert_info(self, cert: dict) -> Dict[str, any]:
        """Extract and format certificate information"""
        info = {}
        
        # Subject
        if 'subject' in cert:
            subject_items = []
            for item in cert['subject']:
                for key, value in item:
                    subject_items.append(f"{key}={value}")
            info['subject'] = ', '.join(subject_items)
        
        # Issuer
        if 'issuer' in cert:
            issuer_items = []
            for item in cert['issuer']:
                for key, value in item:
                    issuer_items.append(f"{key}={value}")
            info['issuer'] = ', '.join(issuer_items)
        
        # Validity dates
        if 'notBefore' in cert:
            info['valid_from'] = cert['notBefore']
        if 'notAfter' in cert:
            info['valid_until'] = cert['notAfter']
        
        # Serial number
        if 'serialNumber' in cert:
            info['serial_number'] = cert['serialNumber']
        
        # Subject Alternative Names
        if 'subjectAltName' in cert:
            info['subject_alt_names'] = [name for name_type, name in cert['subjectAltName']]
        
        # Version
        if 'version' in cert:
            info['version'] = cert['version']
        
        return info
    
    def check_certificate_chain(self, hostname: str, port: int = 443) -> Dict[str, any]:
        """
        Check certificate chain (basic implementation)
        
        Args:
            hostname: Hostname to check
            port: Port number
        
        Returns:
            Dictionary with chain information
        """
        result = {
            'chain_length': 0,
            'root_trusted': False,
            'intermediate_certs': [],
            'error': None
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate chain
                    # Note: This is a simplified version
                    cert = ssock.getpeercert()
                    result['chain_length'] = 1
                    result['root_trusted'] = True  # Simplified - would need deeper analysis
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_multiple_certificates(self, hostnames: List[str]) -> Dict[str, Dict]:
        """
        Check certificates for multiple hostnames
        
        Args:
            hostnames: List of hostnames to check
        
        Returns:
            Dictionary mapping hostnames to certificate analysis results
        """
        results = {}
        
        for hostname in hostnames:
            results[hostname] = self.analyze_certificate(hostname)
        
        return results
    
    def get_certificate_expiry_date(self, hostname: str, port: int = 443) -> Optional[datetime]:
        """
        Get certificate expiry date
        
        Args:
            hostname: Hostname to check
            port: Port number
        
        Returns:
            Expiry date as datetime object or None
        """
        try:
            analysis = self.analyze_certificate(hostname, port)
            if analysis.get('certificate_info') and 'valid_until' in analysis['certificate_info']:
                date_str = analysis['certificate_info']['valid_until']
                return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
        except Exception:
            pass
        
        return None
    
    def generate_certificate_report(self, hostname: str, port: int = 443) -> str:
        """
        Generate human-readable certificate report
        
        Args:
            hostname: Hostname to analyze
            port: Port number
        
        Returns:
            Formatted certificate report
        """
        analysis = self.analyze_certificate(hostname, port)
        
        report = f"""
SSL/TLS Certificate Analysis Report
{'='*60}
Hostname: {hostname}:{port}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Certificate Status: {'✓ Found' if analysis['certificate_found'] else '✗ Not Found'}
Valid: {'✓ Yes' if analysis['valid'] else '✗ No'}
Expired: {'✗ Yes' if analysis['expired'] else '✓ No'}
Security Score: {analysis['security_score']}/100

Certificate Information:
"""
        
        if analysis.get('certificate_info'):
            cert_info = analysis['certificate_info']
            for key, value in cert_info.items():
                if key == 'subject_alt_names':
                    report += f"  {key.replace('_', ' ').title()}: {', '.join(value[:5])}\n"
                else:
                    report += f"  {key.replace('_', ' ').title()}: {value}\n"
        
        if analysis.get('ssl_version'):
            report += f"\nSSL/TLS Version: {analysis['ssl_version']}\n"
        
        if analysis.get('warnings'):
            report += f"\nWarnings:\n"
            for warning in analysis['warnings']:
                report += f"  ⚠ {warning}\n"
        
        if analysis.get('recommendations'):
            report += f"\nRecommendations:\n"
            for rec in analysis['recommendations']:
                report += f"  → {rec}\n"
        
        if analysis.get('error'):
            report += f"\nError: {analysis['error']}\n"
        
        return report
    
    def check_certificate_from_url(self, url: str) -> Dict[str, any]:
        """
        Analyze certificate from URL
        
        Args:
            url: URL to check
        
        Returns:
            Certificate analysis results
        """
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
        
        return self.analyze_certificate(hostname, port)
