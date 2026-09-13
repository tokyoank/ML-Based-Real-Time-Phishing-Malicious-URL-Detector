"""
Security Configuration Checker Module
Provides security configuration analysis and recommendations
"""

import os
import re
import platform
from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime


class ConfigSecurity:
    """Handles security configuration checking"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
    
    def check_password_policy(self) -> Dict[str, any]:
        """
        Check system password policy (basic checks)
        
        Returns:
            Dictionary with password policy information
        """
        result = {
            'os': self.os_type,
            'checks': {},
            'security_score': 100,
            'recommendations': []
        }
        
        if self.os_type == 'windows':
            # Windows-specific checks would go here
            result['checks']['windows_password_policy'] = 'Use Local Security Policy (secpol.msc) to check'
            result['recommendations'].append('Enable password complexity requirements')
            result['recommendations'].append('Set minimum password length to 12+ characters')
            result['recommendations'].append('Enable password history (prevent reuse)')
        
        elif self.os_type == 'linux':
            result['checks']['linux_password_policy'] = 'Check /etc/pam.d/system-auth or /etc/login.defs'
            result['recommendations'].append('Review PAM configuration for password requirements')
            result['recommendations'].append('Set PASS_MIN_LEN to 12 or higher')
            result['recommendations'].append('Configure password aging policy')
        
        return result
    
    def check_file_permissions(self, file_path: str) -> Dict[str, any]:
        """
        Check file permissions for security
        
        Args:
            file_path: Path to file
        
        Returns:
            Dictionary with permission information
        """
        result = {
            'file': file_path,
            'exists': False,
            'permissions': None,
            'secure': True,
            'warnings': [],
            'recommendations': []
        }
        
        try:
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result
            
            result['exists'] = True
            
            if self.os_type != 'windows':
                # Unix-like permissions
                stat_info = os.stat(file_path)
                mode = oct(stat_info.st_mode)[-3:]
                result['permissions'] = mode
                
                # Check if too permissive
                if mode[-1] in ['4', '5', '6', '7']:  # Others can read
                    result['warnings'].append('File is world-readable')
                    result['security_score'] = 50
                    result['secure'] = False
                
                if mode[-1] in ['2', '3', '6', '7']:  # Others can write
                    result['warnings'].append('File is world-writable (CRITICAL)')
                    result['security_score'] = 0
                    result['secure'] = False
                    result['recommendations'].append('Change permissions immediately: chmod 600 ' + file_path)
                
                if mode[1] in ['4', '5', '6', '7']:  # Group can write
                    result['warnings'].append('File is group-writable')
                    result['security_score'] = min(result.get('security_score', 100), 70)
            
            else:
                # Windows - basic check
                result['permissions'] = 'Windows ACL (use icacls for details)'
                result['recommendations'].append('Review file permissions with icacls command')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_directory_permissions(self, directory: str) -> Dict[str, any]:
        """
        Check directory permissions
        
        Args:
            directory: Path to directory
        
        Returns:
            Dictionary with permission information
        """
        result = {
            'directory': directory,
            'exists': False,
            'permissions': None,
            'secure': True,
            'warnings': [],
            'files_with_issues': []
        }
        
        try:
            if not os.path.isdir(directory):
                result['error'] = 'Directory not found'
                return result
            
            result['exists'] = True
            
            if self.os_type != 'windows':
                stat_info = os.stat(directory)
                mode = oct(stat_info.st_mode)[-3:]
                result['permissions'] = mode
                
                # Check for world-writable directories
                if mode[-1] in ['2', '3', '6', '7']:
                    result['warnings'].append('Directory is world-writable (security risk)')
                    result['secure'] = False
                
                # Check files in directory
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_check = self.check_file_permissions(file_path)
                        if not file_check.get('secure'):
                            result['files_with_issues'].append(file_path)
        
        except PermissionError:
            result['error'] = 'Permission denied'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_environment_variables(self) -> Dict[str, any]:
        """
        Check environment variables for sensitive data
        
        Returns:
            Dictionary with environment variable analysis
        """
        result = {
            'sensitive_vars_found': [],
            'warnings': [],
            'recommendations': []
        }
        
        sensitive_keywords = ['password', 'secret', 'key', 'token', 'api', 'credential']
        env_vars = os.environ
        
        for key, value in env_vars.items():
            key_lower = key.lower()
            if any(keyword in key_lower for keyword in sensitive_keywords):
                result['sensitive_vars_found'].append({
                    'name': key,
                    'has_value': bool(value),
                    'value_length': len(value) if value else 0
                })
        
        if result['sensitive_vars_found']:
            result['warnings'].append(f"Found {len(result['sensitive_vars_found'])} potentially sensitive environment variables")
            result['recommendations'].append('Review environment variables - ensure they are not logged or exposed')
            result['recommendations'].append('Use secure credential storage instead of environment variables when possible')
        
        return result
    
    def check_file_extensions(self, directory: str) -> Dict[str, any]:
        """
        Check for potentially dangerous file extensions
        
        Args:
            directory: Directory to check
        
        Returns:
            Dictionary with file extension analysis
        """
        result = {
            'directory': directory,
            'dangerous_files': [],
            'warnings': []
        }
        
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.sh', '.ps1', '.vbs', '.js', '.jar']
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_ext = os.path.splitext(file)[1].lower()
                    if file_ext in dangerous_extensions:
                        result['dangerous_files'].append({
                            'file': os.path.join(root, file),
                            'extension': file_ext
                        })
            
            if result['dangerous_files']:
                result['warnings'].append(f"Found {len(result['dangerous_files'])} files with potentially dangerous extensions")
                result['recommendations'] = ['Review these files to ensure they are legitimate']
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def generate_security_config_report(self, directory: str = None) -> str:
        """
        Generate security configuration report
        
        Args:
            directory: Optional directory to analyze
        
        Returns:
            Formatted security report
        """
        report = f"""
Security Configuration Report
{'='*60}
OS: {platform.system()} {platform.release()}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

Password Policy:
"""
        
        password_policy = self.check_password_policy()
        for key, value in password_policy.get('checks', {}).items():
            report += f"  {key}: {value}\n"
        
        for rec in password_policy.get('recommendations', []):
            report += f"  → {rec}\n"
        
        # Environment variables
        env_check = self.check_environment_variables()
        report += f"\nEnvironment Variables:\n"
        if env_check.get('sensitive_vars_found'):
            report += f"  Found {len(env_check['sensitive_vars_found'])} potentially sensitive variables\n"
            for rec in env_check.get('recommendations', []):
                report += f"  → {rec}\n"
        
        # Directory check if provided
        if directory:
            dir_check = self.check_directory_permissions(directory)
            report += f"\nDirectory Permissions ({directory}):\n"
            if dir_check.get('warnings'):
                for warning in dir_check['warnings']:
                    report += f"  ⚠ {warning}\n"
        
        return report
    
    def check_ssh_config(self, config_file: str = None) -> Dict[str, any]:
        """
        Check SSH configuration security (Linux/Mac)
        
        Args:
            config_file: Path to SSH config file (default: ~/.ssh/config)
        
        Returns:
            Dictionary with SSH config analysis
        """
        result = {
            'config_file': config_file or os.path.expanduser('~/.ssh/config'),
            'exists': False,
            'secure': True,
            'recommendations': []
        }
        
        if self.os_type == 'windows':
            result['note'] = 'SSH config checking not applicable for Windows'
            return result
        
        try:
            if not config_file:
                config_file = os.path.expanduser('~/.ssh/config')
            
            if not os.path.exists(config_file):
                result['recommendations'].append('SSH config file not found (using defaults)')
                return result
            
            result['exists'] = True
            
            with open(config_file, 'r') as f:
                content = f.read()
            
            # Check for insecure settings
            insecure_patterns = {
                'PasswordAuthentication yes': 'Consider disabling password authentication, use keys instead',
                'PermitRootLogin yes': 'Disable root login for security',
                'X11Forwarding yes': 'Disable X11 forwarding if not needed'
            }
            
            for pattern, recommendation in insecure_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    result['secure'] = False
                    result['recommendations'].append(recommendation)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
