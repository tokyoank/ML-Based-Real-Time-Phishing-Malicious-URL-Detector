"""
Email Security Module
Provides email header analysis and security checking
"""

import re
import base64
from typing import Dict, List, Optional, Tuple
from email.parser import BytesParser
from email import policy
import socket


class EmailSecurity:
    """Handles email security analysis"""
    
    def __init__(self):
        self.suspicious_patterns = [
            r'urgent',
            r'verify.*account',
            r'suspended',
            r'click.*here',
            r'limited.*time',
            r'act.*now',
            r'verify.*email',
            r'password.*expir',
        ]
        self.common_phishing_domains = [
            'gmail-support.com',
            'paypal-security.com',
            'amazon-customer.com',
        ]
    
    def analyze_email_headers(self, email_content: str) -> Dict[str, any]:
        """
        Analyze email headers for security information
        
        Args:
            email_content: Raw email content (headers + body)
        
        Returns:
            Dictionary with header analysis
        """
        result = {
            'headers_parsed': False,
            'security_score': 100,
            'warnings': [],
            'recommendations': [],
            'header_info': {}
        }
        
        try:
            # Parse email
            email_bytes = email_content.encode('utf-8') if isinstance(email_content, str) else email_content
            msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
            
            result['headers_parsed'] = True
            
            # Extract common headers
            headers = {
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'subject': msg.get('Subject', ''),
                'date': msg.get('Date', ''),
                'message_id': msg.get('Message-ID', ''),
                'return_path': msg.get('Return-Path', ''),
                'reply_to': msg.get('Reply-To', ''),
                'received': msg.get_all('Received', []),
                'dkim': msg.get('DKIM-Signature', ''),
                'spf': None,
                'dmarc': None,
            }
            
            result['header_info'] = headers
            
            # Check for SPF, DKIM, DMARC in headers
            for header_name, header_value in msg.items():
                if 'spf' in header_name.lower():
                    headers['spf'] = header_value
                if 'dmarc' in header_name.lower():
                    headers['dmarc'] = header_value
            
            # Security checks
            self._check_spoofing(headers, result)
            self._check_dkim_spf(headers, result)
            self._check_received_chain(headers, result)
            self._check_suspicious_from(headers, result)
            
            result['security_score'] = max(0, min(100, result['security_score']))
        
        except Exception as e:
            result['error'] = str(e)
            result['headers_parsed'] = False
        
        return result
    
    def _check_spoofing(self, headers: Dict, result: Dict):
        """Check for email spoofing indicators"""
        from_addr = headers.get('from', '').lower()
        return_path = headers.get('return_path', '').lower()
        reply_to = headers.get('reply_to', '').lower()
        
        # Extract domains
        from_domain = self._extract_domain(from_addr)
        return_domain = self._extract_domain(return_path)
        reply_domain = self._extract_domain(reply_to)
        
        # Check domain mismatches
        if from_domain and return_domain and from_domain != return_domain:
            result['warnings'].append(f'Domain mismatch: From ({from_domain}) vs Return-Path ({return_domain})')
            result['security_score'] -= 20
        
        if from_domain and reply_domain and from_domain != reply_domain:
            result['warnings'].append(f'Domain mismatch: From ({from_domain}) vs Reply-To ({reply_domain})')
            result['security_score'] -= 15
    
    def _check_dkim_spf(self, headers: Dict, result: Dict):
        """Check for DKIM and SPF"""
        has_dkim = bool(headers.get('dkim'))
        has_spf = bool(headers.get('spf'))
        
        if not has_dkim:
            result['warnings'].append('No DKIM signature found (email authentication missing)')
            result['security_score'] -= 15
        
        if not has_spf:
            result['warnings'].append('No SPF record found (email authentication missing)')
            result['security_score'] -= 15
        
        if has_dkim and has_spf:
            result['recommendations'].append('Email has DKIM and SPF authentication')
    
    def _check_received_chain(self, headers: Dict, result: Dict):
        """Check Received headers chain"""
        received = headers.get('received', [])
        
        if not received:
            result['warnings'].append('No Received headers found')
            result['security_score'] -= 10
        elif len(received) < 2:
            result['warnings'].append('Very short Received header chain (potential spoofing)')
            result['security_score'] -= 15
    
    def _check_suspicious_from(self, headers: Dict, result: Dict):
        """Check for suspicious From addresses"""
        from_addr = headers.get('from', '').lower()
        
        # Check for suspicious domains
        for domain in self.common_phishing_domains:
            if domain in from_addr:
                result['warnings'].append(f'Suspicious domain in From field: {domain}')
                result['security_score'] -= 30
        
        # Check for IP addresses in From
        if re.search(r'\d+\.\d+\.\d+\.\d+', from_addr):
            result['warnings'].append('IP address found in From field (suspicious)')
            result['security_score'] -= 25
    
    def _extract_domain(self, email_string: str) -> Optional[str]:
        """Extract domain from email address or string"""
        if not email_string:
            return None
        
        # Extract email if in format "Name <email@domain.com>"
        email_match = re.search(r'[\w\.-]+@([\w\.-]+)', email_string)
        if email_match:
            return email_match.group(1).lower()
        
        return None
    
    def analyze_email_content(self, email_body: str) -> Dict[str, any]:
        """
        Analyze email body for phishing indicators
        
        Args:
            email_body: Email body text
        
        Returns:
            Dictionary with content analysis
        """
        result = {
            'phishing_score': 0,
            'suspicious_patterns': [],
            'risk_level': 'Low',
            'recommendations': []
        }
        
        body_lower = email_body.lower()
        
        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            matches = re.findall(pattern, body_lower)
            if matches:
                result['suspicious_patterns'].append(pattern)
                result['phishing_score'] += 10
        
        # Check for links
        links = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', email_body)
        if len(links) > 5:
            result['suspicious_patterns'].append('Too many links in email')
            result['phishing_score'] += 15
        
        # Check for urgency
        urgency_words = ['urgent', 'immediate', 'asap', 'now', 'today', 'expired', 'suspended']
        urgency_count = sum(1 for word in urgency_words if word in body_lower)
        if urgency_count >= 3:
            result['suspicious_patterns'].append('High urgency language detected')
            result['phishing_score'] += 20
        
        # Determine risk level
        if result['phishing_score'] >= 50:
            result['risk_level'] = 'High'
        elif result['phishing_score'] >= 25:
            result['risk_level'] = 'Medium'
        else:
            result['risk_level'] = 'Low'
        
        if result['risk_level'] in ['Medium', 'High']:
            result['recommendations'].append('Be cautious - verify sender authenticity')
            result['recommendations'].append('Do not click links without verification')
            result['recommendations'].append('Contact sender through official channels if unsure')
        
        return result
    
    def check_email_address(self, email: str) -> Dict[str, any]:
        """
        Check email address format and basic security
        
        Args:
            email: Email address to check
        
        Returns:
            Dictionary with email address information
        """
        result = {
            'email': email,
            'is_valid': False,
            'domain': None,
            'warnings': []
        }
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(email_pattern, email):
            result['is_valid'] = True
            result['domain'] = email.split('@')[1]
            
            # Check for suspicious patterns
            email_lower = email.lower()
            if '+' in email:
                result['warnings'].append('Email contains + (could be used for filtering)')
            
            if '..' in email:
                result['warnings'].append('Email contains consecutive dots (suspicious)')
                result['is_valid'] = False
        
        else:
            result['warnings'].append('Invalid email format')
        
        return result
    
    def extract_urls_from_email(self, email_content: str) -> List[str]:
        """
        Extract all URLs from email content
        
        Args:
            email_content: Email content (headers + body)
        
        Returns:
            List of URLs found
        """
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, email_content)
        return list(set(urls))  # Remove duplicates
    
    def analyze_full_email(self, email_content: str) -> Dict[str, any]:
        """
        Comprehensive email analysis (headers + content)
        
        Args:
            email_content: Full email content
        
        Returns:
            Dictionary with complete analysis
        """
        result = {
            'header_analysis': {},
            'content_analysis': {},
            'overall_risk': 'Unknown',
            'urls_found': []
        }
        
        # Analyze headers
        result['header_analysis'] = self.analyze_email_headers(email_content)
        
        # Extract body (basic extraction)
        try:
            email_bytes = email_content.encode('utf-8') if isinstance(email_content, str) else email_content
            msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
            
            # Get text body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
            
            # Analyze content
            result['content_analysis'] = self.analyze_email_content(body)
            
            # Extract URLs
            result['urls_found'] = self.extract_urls_from_email(email_content)
        
        except Exception as e:
            result['content_error'] = str(e)
        
        # Determine overall risk
        header_score = result['header_analysis'].get('security_score', 100)
        phishing_score = result['content_analysis'].get('phishing_score', 0)
        
        overall_score = header_score - phishing_score
        
        if overall_score >= 70:
            result['overall_risk'] = 'Low'
        elif overall_score >= 40:
            result['overall_risk'] = 'Medium'
        else:
            result['overall_risk'] = 'High'
        
        return result
