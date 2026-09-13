"""
Email Spam & Phishing Detection System
Advanced email analysis for spam and phishing detection
"""

import re
import os
import base64
from typing import Dict, List, Optional
from datetime import datetime
from email.parser import BytesParser
from email import policy
from collections import Counter


class EmailSpamPhishingDetector:
    """Advanced email spam and phishing detection system"""
    
    def __init__(self):
        # Spam indicators
        self.spam_keywords = [
            'free', 'win', 'winner', 'prize', 'congratulations', 'claim now',
            'limited time', 'act now', 'click here', 'buy now', 'discount',
            'save money', 'urgent', 'guaranteed', 'risk-free', 'no cost',
            'make money', 'work from home', 'get rich', 'investment opportunity'
        ]
        
        # Phishing indicators
        self.phishing_keywords = [
            'verify', 'confirm', 'update', 'suspended', 'locked', 'expired',
            'security alert', 'unauthorized access', 'account verification',
            'click here to verify', 'reset password', 'update payment',
            'billing problem', 'invoice attached', 'payment required'
        ]
        
        # Suspicious sender patterns
        self.suspicious_sender_patterns = [
            r'noreply@',
            r'no-reply@',
            r'support@.*\.(tk|ml|ga|cf)',
            r'[\w\.-]+@[\w\.-]+\.(tk|ml|ga|cf)',
        ]
        
        # Suspicious subject patterns
        self.suspicious_subject_patterns = [
            r'^\$+',
            r'^re:\s*re:',
            r'^fwd:\s*fwd:',
            r'!!!+',
            r'urgent.*urgent',
        ]
    
    def analyze_email(self, email_content: str) -> Dict[str, any]:
        """
        Comprehensive email spam and phishing analysis
        
        Args:
            email_content: Raw email content (headers + body)
        
        Returns:
            Dictionary with analysis results
        """
        result = {
            'is_spam': False,
            'is_phishing': False,
            'spam_score': 0.0,
            'phishing_score': 0.0,
            'overall_risk': 'low',
            'indicators': [],
            'recommendations': []
        }
        
        try:
            # Parse email
            email_bytes = email_content.encode('utf-8') if isinstance(email_content, str) else email_content
            msg = BytesParser(policy=policy.default).parsebytes(email_bytes)
            
            # Extract components
            from_addr = msg.get('From', '')
            subject = msg.get('Subject', '')
            body = self._extract_body(msg)
            
            # Analyze spam
            spam_result = self._analyze_spam(from_addr, subject, body)
            result['spam_score'] = spam_result['score']
            result['is_spam'] = spam_result['score'] > 60
            result['spam_indicators'] = spam_result['indicators']
            
            # Analyze phishing
            phishing_result = self._analyze_phishing(from_addr, subject, body, msg)
            result['phishing_score'] = phishing_result['score']
            result['is_phishing'] = phishing_result['score'] > 60
            result['phishing_indicators'] = phishing_result['indicators']
            
            # Determine overall risk
            max_score = max(result['spam_score'], result['phishing_score'])
            if max_score >= 80:
                result['overall_risk'] = 'critical'
            elif max_score >= 60:
                result['overall_risk'] = 'high'
            elif max_score >= 40:
                result['overall_risk'] = 'medium'
            else:
                result['overall_risk'] = 'low'
            
            # Combine indicators
            result['indicators'] = spam_result['indicators'] + phishing_result['indicators']
            
            # Generate recommendations
            if result['is_phishing']:
                result['recommendations'].append('DO NOT click any links')
                result['recommendations'].append('DO NOT enter credentials')
                result['recommendations'].append('Delete this email')
                result['recommendations'].append('Report as phishing')
            elif result['is_spam']:
                result['recommendations'].append('Mark as spam')
                result['recommendations'].append('Delete email')
            else:
                result['recommendations'].append('Email appears legitimate')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _extract_body(self, msg) -> str:
        """Extract email body text"""
        body = ""
        try:
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
            else:
                body = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except:
            pass
        return body
    
    def _analyze_spam(self, from_addr: str, subject: str, body: str) -> Dict[str, any]:
        """Analyze email for spam characteristics"""
        result = {
            'score': 0.0,
            'indicators': []
        }
        
        text_combined = f"{subject} {body}".lower()
        
        # Check spam keywords
        spam_keyword_count = sum(1 for keyword in self.spam_keywords if keyword in text_combined)
        result['score'] += spam_keyword_count * 10
        if spam_keyword_count > 0:
            result['indicators'].append(f'Found {spam_keyword_count} spam keywords')
        
        # Check suspicious subject patterns
        for pattern in self.suspicious_subject_patterns:
            if re.search(pattern, subject, re.IGNORECASE):
                result['score'] += 20
                result['indicators'].append('Suspicious subject pattern')
        
        # Check for excessive caps
        if subject and len([c for c in subject if c.isupper()]) / len(subject) > 0.5:
            result['score'] += 15
            result['indicators'].append('Excessive capitalization in subject')
        
        # Check for suspicious sender
        for pattern in self.suspicious_sender_patterns:
            if re.search(pattern, from_addr, re.IGNORECASE):
                result['score'] += 25
                result['indicators'].append('Suspicious sender address')
        
        # Check for excessive links
        link_count = len(re.findall(r'https?://[^\s]+', body))
        if link_count > 5:
            result['score'] += 20
            result['indicators'].append(f'Excessive links ({link_count})')
        
        # Check for image-only emails (suspicious)
        if len(body.strip()) < 50 and '<img' in body.lower():
            result['score'] += 30
            result['indicators'].append('Image-only email (common spam technique)')
        
        result['score'] = min(100, result['score'])
        return result
    
    def _analyze_phishing(self, from_addr: str, subject: str, body: str, msg) -> Dict[str, any]:
        """Analyze email for phishing characteristics"""
        result = {
            'score': 0.0,
            'indicators': []
        }
        
        text_combined = f"{subject} {body}".lower()
        
        # Check phishing keywords
        phishing_keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in text_combined)
        result['score'] += phishing_keyword_count * 15
        if phishing_keyword_count > 0:
            result['indicators'].append(f'Found {phishing_keyword_count} phishing keywords')
        
        # Check for urgency language
        urgency_words = ['urgent', 'immediate', 'asap', 'now', 'today', 'expired', 'suspended']
        urgency_count = sum(1 for word in urgency_words if word in text_combined)
        if urgency_count >= 3:
            result['score'] += 25
            result['indicators'].append('High urgency language (common in phishing)')
        
        # Check for links to suspicious domains
        links = re.findall(r'https?://([^\s/<>"]+)', body)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        for link in links:
            if any(link.endswith(tld) for tld in suspicious_tlds):
                result['score'] += 30
                result['indicators'].append(f'Suspicious domain in link: {link}')
        
        # Check for sender domain mismatch (would need to extract claimed domain)
        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear valued', 'hello friend']
        if any(greeting in text_combined[:200] for greeting in generic_greetings):
            result['score'] += 15
            result['indicators'].append('Generic greeting (not personalized)')
        
        # Check for suspicious attachments
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_disposition() == 'attachment':
                    filename = part.get_filename()
                    if filename:
                        ext = os.path.splitext(filename)[1].lower()
                        if ext in ['.exe', '.bat', '.cmd', '.scr', '.vbs']:
                            result['score'] += 40
                            result['indicators'].append(f'Suspicious attachment: {filename}')
        
        # Check for form/credential requests
        if 'password' in text_combined and 'enter' in text_combined:
            result['score'] += 25
            result['indicators'].append('Email requests credentials')
        
        result['score'] = min(100, result['score'])
        return result
    
    def batch_analyze(self, emails: List[str]) -> Dict[str, Dict]:
        """
        Analyze multiple emails
        
        Args:
            emails: List of email content strings
        
        Returns:
            Dictionary mapping email indices to analysis results
        """
        results = {}
        for i, email_content in enumerate(emails):
            results[f'email_{i}'] = self.analyze_email(email_content)
        return results
    
    def generate_report(self, email_content: str) -> str:
        """
        Generate spam/phishing detection report
        
        Args:
            email_content: Email content to analyze
        
        Returns:
            Formatted report string
        """
        result = self.analyze_email(email_content)
        
        report = f"""
Email Spam & Phishing Detection Report
{'='*60}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Detection Results:
  Spam: {'⚠ YES' if result['is_spam'] else '✓ NO'} (Score: {result['spam_score']:.1f}%)
  Phishing: {'⚠ YES' if result['is_phishing'] else '✓ NO'} (Score: {result['phishing_score']:.1f}%)
  Overall Risk: {result['overall_risk'].upper()}

Indicators:
"""
        for indicator in result.get('indicators', []):
            report += f"  ⚠ {indicator}\n"
        
        if result.get('recommendations'):
            report += f"\nRecommendations:\n"
            for rec in result['recommendations']:
                report += f"  → {rec}\n"
        
        return report
