"""
URL and Domain Security Module
Provides URL safety checking, domain analysis, and phishing detection
"""

import re
import socket
import requests
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple


class URLSecurity:
    """Handles URL and domain security analysis"""
    
    def __init__(self):
        self.timeout = 10
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']  # Known suspicious TLDs
        self.suspicious_keywords = ['paypal', 'bank', 'secure', 'verify', 'update', 'login']
        self.shortener_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'is.gd', 'v.gd', 'tiny.cc'
        ]
    
    def analyze_url(self, url: str) -> Dict[str, any]:
        """
        Comprehensive URL security analysis
        
        Args:
            url: URL to analyze
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'url': url,
            'is_valid': False,
            'is_safe': True,
            'warnings': [],
            'suggestions': [],
            'domain_info': {},
            'redirects': [],
            'security_score': 100
        }
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme:
                url = 'http://' + url
                parsed = urlparse(url)
                result['url'] = url
            
            result['is_valid'] = True
            domain = parsed.netloc.lower()
            
            # Check domain
            domain_info = self.analyze_domain(domain)
            result['domain_info'] = domain_info
            
            # Check for suspicious patterns
            url_lower = url.lower()
            
            # Check for IP address instead of domain
            if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
                result['warnings'].append('URL uses IP address instead of domain name')
                result['security_score'] -= 20
                result['is_safe'] = False
            
            # Check for suspicious TLDs
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    result['warnings'].append(f'Domain uses suspicious TLD: {tld}')
                    result['security_score'] -= 15
                    result['is_safe'] = False
            
            # Check for URL shorteners
            if any(shortener in domain for shortener in self.shortener_domains):
                result['warnings'].append('URL uses a URL shortener (could hide real destination)')
                result['security_score'] -= 10
                result['suggestions'].append('Consider using a URL expander to see the final destination')
            
            # Check HTTPS
            if parsed.scheme == 'http':
                result['warnings'].append('URL uses HTTP instead of HTTPS (not encrypted)')
                result['security_score'] -= 30
                result['is_safe'] = False
            elif parsed.scheme == 'https':
                result['domain_info']['has_https'] = True
                # Try to check SSL
                try:
                    ssl_info = self.check_ssl_certificate(url)
                    result['domain_info']['ssl_info'] = ssl_info
                except:
                    pass
            
            # Check for suspicious keywords in URL
            suspicious_count = sum(1 for keyword in self.suspicious_keywords if keyword in url_lower)
            if suspicious_count > 2:
                result['warnings'].append('URL contains multiple suspicious keywords')
                result['security_score'] -= 10
            
            # Check URL length
            if len(url) > 200:
                result['warnings'].append('URL is very long (could be hiding malicious content)')
                result['security_score'] -= 5
            
            # Check for @ symbol (userinfo)
            if '@' in url:
                result['warnings'].append('URL contains @ symbol (potential credential embedding)')
                result['security_score'] -= 25
                result['is_safe'] = False
            
            # Final security assessment
            result['security_score'] = max(0, min(100, result['security_score']))
            
            if result['security_score'] >= 70:
                result['risk_level'] = 'Low'
            elif result['security_score'] >= 40:
                result['risk_level'] = 'Medium'
            else:
                result['risk_level'] = 'High'
        
        except Exception as e:
            result['error'] = str(e)
            result['is_valid'] = False
        
        return result
    
    def analyze_domain(self, domain: str) -> Dict[str, any]:
        """
        Analyze domain for security information
        
        Args:
            domain: Domain name to analyze
        
        Returns:
            Dictionary with domain information
        """
        info = {
            'domain': domain,
            'ip_addresses': [],
            'is_resolvable': False,
            'has_https': False
        }
        
        try:
            # Remove port if present
            domain = domain.split(':')[0]
            
            # Resolve domain
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            info['ip_addresses'] = ip_addresses
            info['is_resolvable'] = True
            
            # Check if domain is local/private
            private_ips = ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.',
                          '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                          '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.']
            
            for ip in ip_addresses:
                if any(ip.startswith(prefix) for prefix in private_ips):
                    info['is_private'] = True
                    break
        
        except socket.gaierror:
            info['error'] = 'Domain could not be resolved'
        except Exception as e:
            info['error'] = str(e)
        
        return info
    
    def check_ssl_certificate(self, url: str) -> Dict[str, any]:
        """
        Check SSL certificate for URL
        
        Args:
            url: URL to check
        
        Returns:
            Dictionary with SSL certificate information
        """
        result = {
            'has_ssl': False,
            'is_valid': False,
            'error': None
        }
        
        try:
            parsed = urlparse(url)
            if parsed.scheme != 'https':
                result['error'] = 'URL does not use HTTPS'
                return result
            
            response = requests.get(url, timeout=self.timeout, verify=True)
            result['has_ssl'] = True
            result['is_valid'] = True
        
        except requests.exceptions.SSLError as e:
            result['has_ssl'] = True
            result['is_valid'] = False
            result['error'] = f"SSL Error: {str(e)}"
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def expand_short_url(self, url: str) -> Optional[str]:
        """
        Expand a shortened URL to see final destination
        
        Args:
            url: Shortened URL
        
        Returns:
            Final URL or None if error
        """
        try:
            response = requests.head(url, allow_redirects=True, timeout=self.timeout)
            return response.url
        except Exception as e:
            print(f"Error expanding URL: {str(e)}")
            return None
    
    def check_url_reputation(self, url: str) -> Dict[str, any]:
        """
        Check URL reputation (basic checks)
        
        Args:
            url: URL to check
        
        Returns:
            Dictionary with reputation information
        """
        result = {
            'url': url,
            'reputation': 'Unknown',
            'checks': {}
        }
        
        analysis = self.analyze_url(url)
        
        # Combine analysis results
        result['security_score'] = analysis.get('security_score', 100)
        result['risk_level'] = analysis.get('risk_level', 'Unknown')
        result['warnings'] = analysis.get('warnings', [])
        
        if result['security_score'] >= 70:
            result['reputation'] = 'Likely Safe'
        elif result['security_score'] >= 40:
            result['reputation'] = 'Caution'
        else:
            result['reputation'] = 'Suspicious'
        
        return result
    
    def validate_url_format(self, url: str) -> Tuple[bool, str]:
        """
        Validate URL format
        
        Args:
            url: URL to validate
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                parsed = urlparse('http://' + url)
            
            if not parsed.netloc:
                return False, "Invalid URL: missing domain"
            
            return True, "Valid URL format"
        
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"
    
    def get_url_domain_age_info(self, domain: str) -> Dict[str, any]:
        """
        Get basic domain information (placeholder for WHOIS integration)
        
        Args:
            domain: Domain name
        
        Returns:
            Dictionary with domain information
        """
        info = {
            'domain': domain,
            'note': 'Full domain age checking requires WHOIS API integration'
        }
        
        # Basic domain analysis
        domain_analysis = self.analyze_domain(domain)
        info.update(domain_analysis)
        
        return info
