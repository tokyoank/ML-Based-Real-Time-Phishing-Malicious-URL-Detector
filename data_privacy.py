"""
Data Privacy Module
Provides utilities for protecting user data and privacy
"""

import re
import hashlib
from typing import List, Dict, Optional


class DataPrivacy:
    """Handles data privacy operations"""
    
    def __init__(self):
        # Common patterns for sensitive data
        self.patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
            'ip_address': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        }
    
    def detect_sensitive_data(self, text: str) -> Dict[str, List[str]]:
        """
        Detect sensitive data patterns in text
        
        Args:
            text: Text to analyze
        
        Returns:
            Dictionary mapping data types to lists of detected values
        """
        detected = {}
        
        for data_type, pattern in self.patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                detected[data_type] = matches
        
        return detected
    
    def mask_email(self, email: str) -> str:
        """Mask email address for privacy"""
        if '@' not in email:
            return email
        
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked_local = '*' * len(local)
        else:
            masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
        
        domain_parts = domain.split('.')
        if len(domain_parts) > 1:
            masked_domain = '*' * len(domain_parts[0]) + '.' + '.'.join(domain_parts[1:])
        else:
            masked_domain = '*' * len(domain)
        
        return f"{masked_local}@{masked_domain}"
    
    def mask_phone(self, phone: str) -> str:
        """Mask phone number for privacy"""
        digits = re.sub(r'\D', '', phone)
        if len(digits) == 10:
            return f"***-***-{digits[-4]}"
        return '*' * len(phone)
    
    def mask_ssn(self, ssn: str) -> str:
        """Mask SSN for privacy"""
        digits = re.sub(r'\D', '', ssn)
        if len(digits) == 9:
            return f"XXX-XX-{digits[-4]}"
        return 'XXX-XX-XXXX'
    
    def mask_credit_card(self, card: str) -> str:
        """Mask credit card number for privacy"""
        digits = re.sub(r'\D', '', card)
        if len(digits) >= 4:
            return '*' * (len(digits) - 4) + digits[-4:]
        return '*' * len(digits)
    
    def sanitize_text(self, text: str, mask_all: bool = False) -> str:
        """
        Sanitize text by masking sensitive data
        
        Args:
            text: Text to sanitize
            mask_all: If True, mask all detected sensitive data
        
        Returns:
            Sanitized text
        """
        if mask_all:
            detected = self.detect_sensitive_data(text)
            sanitized = text
            
            for data_type, values in detected.items():
                for value in values:
                    if data_type == 'email':
                        sanitized = sanitized.replace(value, self.mask_email(value))
                    elif data_type == 'phone':
                        sanitized = sanitized.replace(value, self.mask_phone(value))
                    elif data_type == 'ssn':
                        sanitized = sanitized.replace(value, self.mask_ssn(value))
                    elif data_type == 'credit_card':
                        sanitized = sanitized.replace(value, self.mask_credit_card(value))
            
            return sanitized
        
        return text
    
    def generate_pseudonym(self, identifier: str, salt: str = "") -> str:
        """
        Generate a pseudonym (one-way hash) from an identifier
        
        Args:
            identifier: Original identifier
            salt: Optional salt for hashing
        
        Returns:
            Pseudonym hash
        """
        hash_obj = hashlib.sha256()
        hash_obj.update((identifier + salt).encode())
        return hash_obj.hexdigest()[:16]  # Use first 16 chars
    
    def anonymize_data(self, data: Dict[str, any], fields_to_anonymize: List[str]) -> Dict[str, any]:
        """
        Anonymize specific fields in a data dictionary
        
        Args:
            data: Dictionary containing data
            fields_to_anonymize: List of field names to anonymize
        
        Returns:
            Dictionary with anonymized fields
        """
        anonymized = data.copy()
        
        for field in fields_to_anonymize:
            if field in anonymized:
                value = str(anonymized[field])
                anonymized[field] = self.generate_pseudonym(value)
        
        return anonymized
    
    def check_password_exposure(self, password: str) -> Dict[str, any]:
        """
        Check if password might be exposed (basic check)
        
        Args:
            password: Password to check
        
        Returns:
            Dictionary with exposure risk information
        """
        result = {
            'length_check': len(password) >= 8,
            'common_patterns': [],
            'risk_level': 'low'
        }
        
        # Check for common patterns
        if password.lower() in ['password', '123456', 'qwerty', 'admin']:
            result['common_patterns'].append('Common password')
            result['risk_level'] = 'high'
        
        if len(password) < 8:
            result['risk_level'] = 'high'
        elif len(password) < 12:
            result['risk_level'] = 'medium'
        
        return result
