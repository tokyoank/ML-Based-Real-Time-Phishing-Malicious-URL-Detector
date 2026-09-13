"""
Phishing & Malicious URL Detection System
Advanced phishing detection with multiple detection methods
"""

import re
import os
import requests
import socket
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional
from datetime import datetime
try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False


class PhishingDetector:
    """Advanced phishing and malicious URL detection system"""
    
    def __init__(self):
        self.timeout = 10
        
        # Known malicious TLDs
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz', '.click']
        
        # Known phishing keywords
        self.phishing_keywords = [
            'verify', 'confirm', 'update', 'security', 'suspended', 'locked',
            'expired', 'urgent', 'action required', 'click here', 'login now',
            'reset password', 'account verification', 'security alert'
        ]
        
        # Known legitimate domains (whitelist)
        self.legitimate_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'paypal.com', 'ebay.com', 'facebook.com', 'twitter.com',
            'linkedin.com', 'github.com', 'netflix.com', 'yahoo.com'
        ]
        
        # URL shortener services
        self.shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'short.link', 'is.gd', 'v.gd', 'tiny.cc', 'rebrand.ly'
        ]
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'ip_address': r'^\d+\.\d+\.\d+\.\d+',
            'long_url': r'.{200,}',
            'many_subdomains': r'([a-z0-9-]+\.){4,}',
            'suspicious_chars': r'[^\w\.-]',
            'homoglyph': r'[а-я]',  # Cyrillic characters
        }
    
    def detect_phishing(self, url: str, deep_analysis: bool = True) -> Dict[str, any]:
        """
        Comprehensive phishing detection for a URL
        
        Args:
            url: URL to analyze
            deep_analysis: Perform deep analysis including DNS and content checks
        
        Returns:
            Dictionary with phishing detection results
        """
        result = {
            'url': url,
            'is_phishing': False,
            'confidence': 0.0,
            'risk_level': 'low',
            'indicators': [],
            'scores': {},
            'recommendations': []
        }
        
        try:
            # Parse URL
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'http://' + url
                parsed = urlparse(url)
            
            domain = parsed.netloc.lower()
            
            # 1. Basic URL analysis
            basic_score = self._analyze_url_structure(url, domain)
            result['scores']['structure'] = basic_score
            if basic_score > 60:
                result['indicators'].append('Suspicious URL structure')
            
            # 2. Domain analysis
            domain_score = self._analyze_domain(domain)
            result['scores']['domain'] = domain_score
            if domain_score > 60:
                result['indicators'].append('Suspicious domain characteristics')
            
            # 3. TLD analysis
            tld_score = self._analyze_tld(domain)
            result['scores']['tld'] = tld_score
            if tld_score > 70:
                result['indicators'].append('Suspicious TLD detected')
            
            # 4. URL length and complexity
            length_score = self._analyze_url_length(url)
            result['scores']['length'] = length_score
            if length_score > 70:
                result['indicators'].append('Unusually long or complex URL')
            
            # 5. Keyword analysis
            keyword_score = self._analyze_keywords(url)
            result['scores']['keywords'] = keyword_score
            if keyword_score > 60:
                result['indicators'].append('Suspicious keywords detected')
            
            # 6. Deep analysis if requested
            if deep_analysis:
                # DNS analysis
                dns_score = self._analyze_dns(domain)
                result['scores']['dns'] = dns_score
                
                # SSL analysis
                ssl_score = self._analyze_ssl(url)
                result['scores']['ssl'] = ssl_score
                
                # Content analysis (if accessible)
                try:
                    content_score = self._analyze_content(url)
                    result['scores']['content'] = content_score
                except:
                    pass
            
            # Calculate overall confidence
            scores = result['scores']
            if scores:
                avg_score = sum(scores.values()) / len(scores)
                result['confidence'] = min(100, avg_score)
            else:
                result['confidence'] = 0
            
            # Determine if phishing
            result['is_phishing'] = result['confidence'] > 50
            
            # Determine risk level
            if result['confidence'] >= 80:
                result['risk_level'] = 'critical'
            elif result['confidence'] >= 60:
                result['risk_level'] = 'high'
            elif result['confidence'] >= 40:
                result['risk_level'] = 'medium'
            else:
                result['risk_level'] = 'low'
            
            # Generate recommendations
            if result['is_phishing']:
                result['recommendations'].append('DO NOT visit this URL')
                result['recommendations'].append('Do not enter any credentials')
                result['recommendations'].append('Report this URL to security team')
            else:
                result['recommendations'].append('Exercise caution when visiting')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_url_structure(self, url: str, domain: str) -> float:
        """Analyze URL structure for suspicious patterns"""
        score = 0.0
        
        # Check for IP address instead of domain
        if re.match(self.suspicious_patterns['ip_address'], domain):
            score += 40
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            score += 30
        elif subdomain_count > 3:
            score += 15
        
        # Check for URL shortener
        if any(shortener in domain for shortener in self.shorteners):
            score += 20
        
        # Check for homoglyphs (cyrillic, etc.)
        if re.search(self.suspicious_patterns['homoglyph'], url):
            score += 50
        
        return score
    
    def _analyze_domain(self, domain: str) -> float:
        """Analyze domain characteristics"""
        score = 0.0
        
        # Check if domain is too similar to legitimate domains
        for legit_domain in self.legitimate_domains:
            if self._domain_similarity(domain, legit_domain) > 0.7:
                score += 40
                break
        
        # Check for suspicious substrings
        suspicious_substrings = ['secure-', 'verify-', 'update-', 'support-']
        for substr in suspicious_substrings:
            if substr in domain:
                score += 25
        
        # Check domain age (would require WHOIS - placeholder)
        # Very new domains are more suspicious
        
        return score
    
    def _analyze_tld(self, domain: str) -> float:
        """Analyze TLD for suspicious patterns"""
        score = 0.0
        
        for suspicious_tld in self.suspicious_tlds:
            if domain.endswith(suspicious_tld):
                score += 40
        
        # Uncommon TLDs
        common_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.co.uk']
        has_common_tld = any(domain.endswith(tld) for tld in common_tlds)
        if not has_common_tld:
            score += 20
        
        return score
    
    def _analyze_url_length(self, url: str) -> float:
        """Analyze URL length"""
        score = 0.0
        
        if len(url) > 200:
            score += 40
        elif len(url) > 100:
            score += 20
        
        return score
    
    def _analyze_keywords(self, url: str) -> float:
        """Analyze URL for phishing keywords"""
        score = 0.0
        url_lower = url.lower()
        
        matching_keywords = [kw for kw in self.phishing_keywords if kw in url_lower]
        score += len(matching_keywords) * 15
        
        return min(100, score)
    
    def _analyze_dns(self, domain: str) -> float:
        """Analyze DNS records"""
        score = 0.0
        
        if not DNS_AVAILABLE:
            # Fallback to socket-based resolution
            try:
                socket.gethostbyname(domain)
                score -= 10  # DNS works, reduce suspicion
            except socket.gaierror:
                score += 30  # DNS failure is suspicious
            return score
        
        try:
            # Try to resolve domain
            answers = dns.resolver.resolve(domain, 'A', lifetime=5)
            if len(answers) == 0:
                score += 30
            
            # Check for MX records (legitimate sites usually have email)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
                if len(mx_records) == 0:
                    score += 20
            except:
                score += 20
        
        except dns.exception.DNSException:
            score += 40  # DNS resolution failure is suspicious
        except:
            pass  # Could not perform DNS check
        
        return score
    
    def _analyze_ssl(self, url: str) -> float:
        """Analyze SSL certificate"""
        score = 0.0
        
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            score += 30
        else:
            try:
                response = requests.get(url, timeout=5, verify=True)
                # HTTPS is good, reduce score
                score -= 10
            except requests.exceptions.SSLError:
                score += 40  # SSL error is suspicious
            except:
                pass
        
        return max(0, score)
    
    def _analyze_content(self, url: str) -> float:
        """Analyze webpage content for phishing indicators"""
        score = 0.0
        
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            content = response.text.lower()
            
            # Check for phishing keywords in content
            matching_keywords = [kw for kw in self.phishing_keywords if kw in content]
            if len(matching_keywords) > 5:
                score += 40
            elif len(matching_keywords) > 2:
                score += 20
            
            # Check for form elements (login forms)
            if 'input type="password"' in content or 'input type="password"' in content:
                if 'login' in content or 'sign in' in content:
                    # Could be legitimate, but combined with other indicators...
                    score += 10
        
        except:
            pass  # Could not fetch content
        
        return score
    
    def _domain_similarity(self, domain1: str, domain2: str) -> float:
        """Calculate similarity between two domains (Levenshtein-like)"""
        # Simple similarity calculation
        if domain1 == domain2:
            return 1.0
        
        # Extract base domain (without TLD)
        base1 = domain1.split('.')[0] if '.' in domain1 else domain1
        base2 = domain2.split('.')[0] if '.' in domain2 else domain2
        
        if base1 == base2:
            return 0.8
        
        # Simple character overlap
        common_chars = set(base1) & set(base2)
        total_chars = set(base1) | set(base2)
        
        if len(total_chars) == 0:
            return 0.0
        
        return len(common_chars) / len(total_chars)
    
    def batch_detect(self, urls: List[str]) -> Dict[str, Dict]:
        """
        Detect phishing for multiple URLs
        
        Args:
            urls: List of URLs to check
        
        Returns:
            Dictionary mapping URLs to detection results
        """
        results = {}
        for url in urls:
            results[url] = self.detect_phishing(url, deep_analysis=False)
        return results
    
    def generate_phishing_report(self, url: str) -> str:
        """
        Generate human-readable phishing detection report
        
        Args:
            url: URL to analyze
        
        Returns:
            Formatted report string
        """
        result = self.detect_phishing(url)
        
        report = f"""
Phishing Detection Report
{'='*60}
URL: {url}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Result: {'⚠ PHISHING DETECTED' if result['is_phishing'] else '✓ Likely Safe'}
Confidence: {result['confidence']:.1f}%
Risk Level: {result['risk_level'].upper()}

Score Breakdown:
"""
        
        for score_type, score_value in result.get('scores', {}).items():
            report += f"  {score_type.replace('_', ' ').title()}: {score_value:.1f}\n"
        
        if result.get('indicators'):
            report += f"\nIndicators:\n"
            for indicator in result['indicators']:
                report += f"  ⚠ {indicator}\n"
        
        if result.get('recommendations'):
            report += f"\nRecommendations:\n"
            for rec in result['recommendations']:
                report += f"  → {rec}\n"
        
        return report
    
    def check_url_against_blacklist(self, url: str, blacklist_file: str = None) -> bool:
        """
        Check URL against blacklist (if provided)
        
        Args:
            url: URL to check
            blacklist_file: Path to blacklist file (optional)
        
        Returns:
            True if URL is in blacklist
        """
        if blacklist_file and os.path.exists(blacklist_file):
            try:
                with open(blacklist_file, 'r') as f:
                    blacklist = [line.strip() for line in f if line.strip()]
                    parsed = urlparse(url)
                    domain = parsed.netloc.lower()
                    return any(domain in entry or entry in url for entry in blacklist)
            except:
                pass
        
        return False
