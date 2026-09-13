"""
Keylogger Detection Tool
Detects potential keylogger activity on the system
"""

import os
import sys
import platform
from typing import Dict, List, Optional
from datetime import datetime
import subprocess


class KeyloggerDetector:
    """Detects keylogger and keyboard monitoring software"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        
        # Known keylogger process names (common ones)
        self.known_keyloggers = [
            'keylogger', 'keylog', 'klog', 'hook', 'spy', 'monitor',
            'capture', 'recorder', 'tracker', 'sniffer', 'watcher'
        ]
        
        # Suspicious registry keys (Windows)
        self.suspicious_registry_keys = [
            r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
            r'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
        ]
        
        # Suspicious file locations
        self.suspicious_locations = [
            r'%TEMP%\*.dll',
            r'%APPDATA%\*.exe',
            r'C:\Windows\System32\*.dll',
        ]
    
    def detect_keylogger_processes(self) -> Dict[str, any]:
        """
        Detect keylogger processes running on the system
        
        Returns:
            Dictionary with process detection results
        """
        result = {
            'keyloggers_detected': False,
            'suspicious_processes': [],
            'total_processes_checked': 0,
            'recommendations': []
        }
        
        try:
            processes = self._get_running_processes()
            result['total_processes_checked'] = len(processes)
            
            for process in processes:
                process_name_lower = process.get('name', '').lower()
                
                # Check against known keylogger names
                for keylogger_name in self.known_keyloggers:
                    if keylogger_name in process_name_lower:
                        result['keyloggers_detected'] = True
                        result['suspicious_processes'].append({
                            'name': process.get('name', 'Unknown'),
                            'pid': process.get('pid', 'N/A'),
                            'reason': f'Contains keylogger keyword: {keylogger_name}',
                            'severity': 'high'
                        })
            
            if result['keyloggers_detected']:
                result['recommendations'].append('Terminate suspicious processes')
                result['recommendations'].append('Run antivirus scan')
                result['recommendations'].append('Check system for malware')
            else:
                result['recommendations'].append('No obvious keyloggers detected')
                result['recommendations'].append('Continue monitoring system')
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _get_running_processes(self) -> List[Dict]:
        """Get list of running processes"""
        processes = []
        
        try:
            if self.os_type == 'windows':
                # Use tasklist command
                output = subprocess.check_output(['tasklist', '/FO', 'CSV'], 
                                                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                lines = output.decode('utf-8', errors='ignore').split('\n')[1:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split('","')
                        if len(parts) >= 2:
                            processes.append({
                                'name': parts[0].strip('"'),
                                'pid': parts[1].strip('"'),
                            })
            
            elif self.os_type in ['linux', 'darwin']:
                # Use ps command
                output = subprocess.check_output(['ps', 'aux'], text=True)
                lines = output.split('\n')[1:]  # Skip header
                
                for line in lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            processes.append({
                                'name': parts[10] if len(parts) > 10 else parts[-1],
                                'pid': parts[1],
                            })
        
        except Exception as e:
            print(f"Error getting processes: {str(e)}")
        
        return processes
    
    def check_startup_programs(self) -> Dict[str, any]:
        """
        Check startup programs for keyloggers (Windows)
        
        Returns:
            Dictionary with startup program analysis
        """
        result = {
            'suspicious_startup_programs': [],
            'total_startup_programs': 0,
            'recommendations': []
        }
        
        if self.os_type != 'windows':
            result['note'] = 'Startup program checking is Windows-specific'
            return result
        
        try:
            # Check startup folder
            startup_folders = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp')
            ]
            
            for folder in startup_folders:
                if os.path.exists(folder):
                    for file in os.listdir(folder):
                        file_path = os.path.join(folder, file)
                        file_lower = file.lower()
                        
                        for keylogger_name in self.known_keyloggers:
                            if keylogger_name in file_lower:
                                result['suspicious_startup_programs'].append({
                                    'file': file,
                                    'path': file_path,
                                    'reason': f'Contains keylogger keyword: {keylogger_name}'
                                })
        
        except Exception as e:
            result['error'] = str(e)
        
        result['total_startup_programs'] = sum(
            len(os.listdir(f)) for f in startup_folders if os.path.exists(f)
        )
        
        if result['suspicious_startup_programs']:
            result['recommendations'].append('Remove suspicious startup programs')
        
        return result
    
    def check_network_activity(self) -> Dict[str, any]:
        """
        Check for suspicious network activity (keyloggers may send data)
        
        Returns:
            Dictionary with network activity analysis
        """
        result = {
            'suspicious_connections': [],
            'total_connections': 0,
            'note': 'Full network monitoring requires elevated permissions'
        }
        
        try:
            if self.os_type == 'windows':
                # Use netstat
                output = subprocess.check_output(['netstat', '-ano'], 
                                                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0)
                lines = output.decode('utf-8', errors='ignore').split('\n')
                result['total_connections'] = len([l for l in lines if 'ESTABLISHED' in l])
            
            elif self.os_type in ['linux', 'darwin']:
                output = subprocess.check_output(['netstat', '-an'], text=True)
                lines = output.split('\n')
                result['total_connections'] = len([l for l in lines if 'ESTABLISHED' in l])
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def scan_system(self) -> Dict[str, any]:
        """
        Comprehensive system scan for keyloggers
        
        Returns:
            Dictionary with complete scan results
        """
        result = {
            'scan_time': datetime.now().isoformat(),
            'keyloggers_detected': False,
            'scan_results': {},
            'overall_risk': 'low',
            'recommendations': []
        }
        
        # Scan processes
        process_scan = self.detect_keylogger_processes()
        result['scan_results']['processes'] = process_scan
        if process_scan.get('keyloggers_detected'):
            result['keyloggers_detected'] = True
        
        # Scan startup programs
        if self.os_type == 'windows':
            startup_scan = self.check_startup_programs()
            result['scan_results']['startup'] = startup_scan
            if startup_scan.get('suspicious_startup_programs'):
                result['keyloggers_detected'] = True
        
        # Determine overall risk
        if result['keyloggers_detected']:
            result['overall_risk'] = 'high'
            result['recommendations'].append('IMMEDIATE ACTION REQUIRED')
            result['recommendations'].append('Disconnect from network')
            result['recommendations'].append('Run full antivirus scan')
            result['recommendations'].append('Change all passwords from secure device')
        else:
            result['recommendations'].append('No keyloggers detected')
            result['recommendations'].append('Continue regular security monitoring')
        
        return result
    
    def generate_report(self) -> str:
        """
        Generate keylogger detection report
        
        Returns:
            Formatted report string
        """
        scan_results = self.scan_system()
        
        report = f"""
Keylogger Detection Report
{'='*60}
Scan Time: {scan_results['scan_time']}
{'='*60}

Overall Risk: {scan_results['overall_risk'].upper()}
Keyloggers Detected: {'⚠ YES' if scan_results['keyloggers_detected'] else '✓ NO'}

Process Scan:
"""
        
        process_results = scan_results['scan_results'].get('processes', {})
        if process_results.get('suspicious_processes'):
            report += f"  Suspicious Processes: {len(process_results['suspicious_processes'])}\n"
            for proc in process_results['suspicious_processes'][:10]:
                report += f"    ⚠ {proc['name']} (PID: {proc['pid']}) - {proc['reason']}\n"
        else:
            report += "  ✓ No suspicious processes detected\n"
        
        if 'startup' in scan_results['scan_results']:
            startup_results = scan_results['scan_results']['startup']
            report += f"\nStartup Programs:\n"
            if startup_results.get('suspicious_startup_programs'):
                report += f"  Suspicious Programs: {len(startup_results['suspicious_startup_programs'])}\n"
                for prog in startup_results['suspicious_startup_programs']:
                    report += f"    ⚠ {prog['file']} - {prog['reason']}\n"
            else:
                report += "  ✓ No suspicious startup programs\n"
        
        if scan_results.get('recommendations'):
            report += f"\nRecommendations:\n"
            for rec in scan_results['recommendations']:
                report += f"  → {rec}\n"
        
        return report
