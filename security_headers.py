"""
Security Headers Module
Checks website security headers for best practices
"""

import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse


class SecurityHeaders:
    """Analyzes HTTP security headers"""
    
    def __init__(self):
        self.timeout = 10
        self.important_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Strict-Transport-Security',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
    
    def check_security_headers(self, url: str) -> Dict[str, any]:
        """
        Check security headers for a website
        
        Args:
            url: Website URL to check
        
        Returns:
            Dictionary with security headers analysis
        """
        result = {
            'url': url,
            'headers_present': {},
            'headers_missing': [],
            'security_score': 100,
            'recommendations': [],
            'warnings': []
        }
        
        try:
            # Ensure URL has scheme
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
            
            # Make request
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = response.headers
            
            result['status_code'] = response.status_code
            result['final_url'] = response.url
            
            # Check each important header
            for header_name in self.important_headers:
                header_value = headers.get(header_name, None)
                
                if header_value:
                    result['headers_present'][header_name] = header_value
                    analysis = self._analyze_header(header_name, header_value)
                    if analysis.get('issue'):
                        result['warnings'].append(f"{header_name}: {analysis['issue']}")
                        result['security_score'] -= 5
                else:
                    result['headers_missing'].append(header_name)
                    result['security_score'] -= 10
            
            # Specific checks
            self._check_hsts(headers, result)
            self._check_csp(headers, result)
            self._check_cookies(headers, result)
            
            # Generate recommendations
            self._generate_recommendations(result)
            
            result['security_score'] = max(0, min(100, result['security_score']))
            
            # Determine security level
            if result['security_score'] >= 80:
                result['security_level'] = 'Good'
            elif result['security_score'] >= 60:
                result['security_level'] = 'Fair'
            elif result['security_score'] >= 40:
                result['security_level'] = 'Poor'
            else:
                result['security_level'] = 'Very Poor'
        
        except requests.exceptions.SSLError:
            result['error'] = 'SSL certificate error'
            result['security_score'] = 0
        except requests.exceptions.ConnectionError:
            result['error'] = 'Connection error'
            result['security_score'] = 0
        except Exception as e:
            result['error'] = str(e)
            result['security_score'] = 0
        
        return result
    
    def _analyze_header(self, header_name: str, header_value: str) -> Dict[str, any]:
        """Analyze specific header value"""
        analysis = {'value': header_value, 'issue': None}
        
        header_name_lower = header_name.lower()
        header_value_lower = header_value.lower()
        
        # X-Frame-Options
        if header_name_lower == 'x-frame-options':
            if header_value_lower not in ['deny', 'sameorigin']:
                analysis['issue'] = 'Should be DENY or SAMEORIGIN'
        
        # X-Content-Type-Options
        elif header_name_lower == 'x-content-type-options':
            if header_value_lower != 'nosniff':
                analysis['issue'] = 'Should be nosniff'
        
        # X-XSS-Protection
        elif header_name_lower == 'x-xss-protection':
            if '1; mode=block' not in header_value_lower:
                analysis['issue'] = 'Should be "1; mode=block"'
        
        return analysis
    
    def _check_hsts(self, headers: Dict, result: Dict):
        """Check HSTS header"""
        hsts = headers.get('Strict-Transport-Security', '')
        
        if not hsts:
            result['warnings'].append('HSTS header missing (recommended for HTTPS sites)')
            result['security_score'] -= 15
        else:
            if 'max-age' not in hsts.lower():
                result['warnings'].append('HSTS header missing max-age directive')
                result['security_score'] -= 5
            if 'includesubdomains' not in hsts.lower():
                result['recommendations'].append('Consider adding includeSubDomains to HSTS')
    
    def _check_csp(self, headers: Dict, result: Dict):
        """Check Content Security Policy"""
        csp = headers.get('Content-Security-Policy', '')
        
        if not csp:
            result['warnings'].append('Content-Security-Policy missing (important for XSS protection)')
            result['security_score'] -= 20
        else:
            # Check for unsafe-inline
            if 'unsafe-inline' in csp.lower():
                result['warnings'].append('CSP contains unsafe-inline (reduces security)')
                result['security_score'] -= 10
            if 'unsafe-eval' in csp.lower():
                result['warnings'].append('CSP contains unsafe-eval (reduces security)')
                result['security_score'] -= 10
    
    def _check_cookies(self, headers: Dict, result: Dict):
        """Check Set-Cookie headers for security"""
        set_cookie = headers.get('Set-Cookie', '')
        
        if set_cookie:
            cookie_lower = set_cookie.lower()
            
            if 'secure' not in cookie_lower:
                result['warnings'].append('Cookies missing Secure flag')
                result['security_score'] -= 10
            
            if 'httponly' not in cookie_lower:
                result['warnings'].append('Cookies missing HttpOnly flag')
                result['security_score'] -= 10
            
            if 'samesite' not in cookie_lower:
                result['recommendations'].append('Consider adding SameSite attribute to cookies')
    
    def _generate_recommendations(self, result: Dict):
        """Generate security recommendations"""
        missing = result.get('headers_missing', [])
        
        recommendations_map = {
            'Content-Security-Policy': 'Implement Content-Security-Policy to prevent XSS attacks',
            'X-Frame-Options': 'Add X-Frame-Options to prevent clickjacking',
            'Strict-Transport-Security': 'Add HSTS header for HTTPS sites',
            'X-Content-Type-Options': 'Add X-Content-Type-Options: nosniff',
            'X-XSS-Protection': 'Add X-XSS-Protection header',
            'Referrer-Policy': 'Set Referrer-Policy to control referrer information',
            'Permissions-Policy': 'Set Permissions-Policy to restrict browser features',
        }
        
        for header in missing:
            if header in recommendations_map:
                result['recommendations'].append(recommendations_map[header])
    
    def get_header_description(self, header_name: str) -> str:
        """
        Get description of security header
        
        Args:
            header_name: Name of the header
        
        Returns:
            Description string
        """
        descriptions = {
            'Content-Security-Policy': 'Prevents XSS attacks by controlling which resources can be loaded',
            'X-Frame-Options': 'Prevents clickjacking by controlling if page can be embedded in frames',
            'X-Content-Type-Options': 'Prevents MIME type sniffing',
            'Strict-Transport-Security': 'Forces browsers to use HTTPS',
            'X-XSS-Protection': 'Enables XSS filtering in browsers',
            'Referrer-Policy': 'Controls referrer information sent in requests',
            'Permissions-Policy': 'Restricts browser features and APIs',
            'X-Permitted-Cross-Domain-Policies': 'Controls Flash and Acrobat cross-domain policies'
        }
        
        return descriptions.get(header_name, 'Security header')
    
    def check_multiple_urls(self, urls: List[str]) -> Dict[str, Dict]:
        """
        Check security headers for multiple URLs
        
        Args:
            urls: List of URLs to check
        
        Returns:
            Dictionary mapping URLs to their security header results
        """
        results = {}
        
        for url in urls:
            results[url] = self.check_security_headers(url)
        
        return results
    
    def generate_security_report(self, url: str) -> str:
        """
        Generate a human-readable security report
        
        Args:
            url: URL to analyze
        
        Returns:
            Formatted security report string
        """
        result = self.check_security_headers(url)
        
        report = f"""
Security Headers Report for: {url}
{'='*60}

Security Score: {result['security_score']}/100
Security Level: {result['security_level']}

Headers Present ({len(result['headers_present'])}/{len(self.important_headers)}):
"""
        
        for header, value in result['headers_present'].items():
            report += f"  ✓ {header}: {value}\n"
        
        if result['headers_missing']:
            report += f"\nMissing Headers ({len(result['headers_missing'])}):\n"
            for header in result['headers_missing']:
                report += f"  ✗ {header}\n"
        
        if result['warnings']:
            report += f"\nWarnings:\n"
            for warning in result['warnings']:
                report += f"  ⚠ {warning}\n"
        
        if result['recommendations']:
            report += f"\nRecommendations:\n"
            for rec in result['recommendations']:
                report += f"  → {rec}\n"
        
        if result.get('error'):
            report += f"\nError: {result['error']}\n"
        
        return report
