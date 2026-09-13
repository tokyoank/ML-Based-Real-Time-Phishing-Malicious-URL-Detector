"""
Backup Verification Module
Provides backup integrity and verification tools
"""

import os
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime
from security_utilities import SecurityUtilities


class BackupVerification:
    """Handles backup verification and integrity checking"""
    
    def __init__(self):
        self.security_utilities = SecurityUtilities()
    
    def verify_backup_integrity(self, backup_file: str, original_hash: str = None,
                                algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Verify backup file integrity
        
        Args:
            backup_file: Path to backup file
            original_hash: Expected hash value (optional)
            algorithm: Hash algorithm to use
        
        Returns:
            Dictionary with verification results
        """
        result = {
            'backup_file': backup_file,
            'exists': False,
            'size': 0,
            'hash': None,
            'integrity': 'unknown',
            'matches_original': None,
            'error': None
        }
        
        try:
            if not os.path.exists(backup_file):
                result['error'] = 'Backup file not found'
                return result
            
            result['exists'] = True
            result['size'] = os.path.getsize(backup_file)
            
            # Calculate hash
            backup_hash = self.security_utilities.hash_file(backup_file, algorithm)
            result['hash'] = backup_hash
            
            if backup_hash:
                result['integrity'] = 'valid'
            else:
                result['integrity'] = 'invalid'
                result['error'] = 'Could not calculate hash'
            
            # Compare with original if provided
            if original_hash:
                if backup_hash and backup_hash.lower() == original_hash.lower():
                    result['matches_original'] = True
                    result['integrity'] = 'verified'
                else:
                    result['matches_original'] = False
                    result['integrity'] = 'mismatch'
                    result['error'] = 'Hash mismatch - backup may be corrupted'
        
        except Exception as e:
            result['error'] = str(e)
            result['integrity'] = 'error'
        
        return result
    
    def compare_backups(self, backup1: str, backup2: str, algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Compare two backup files
        
        Args:
            backup1: Path to first backup
            backup2: Path to second backup
            algorithm: Hash algorithm to use
        
        Returns:
            Dictionary with comparison results
        """
        result = {
            'backup1': backup1,
            'backup2': backup2,
            'identical': False,
            'backup1_hash': None,
            'backup2_hash': None,
            'error': None
        }
        
        try:
            hash1 = self.security_utilities.hash_file(backup1, algorithm)
            hash2 = self.security_utilities.hash_file(backup2, algorithm)
            
            result['backup1_hash'] = hash1
            result['backup2_hash'] = hash2
            
            if hash1 and hash2:
                result['identical'] = (hash1 == hash2)
            else:
                result['error'] = 'Could not calculate hashes'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def create_backup_manifest(self, directory: str, output_file: str = None,
                               algorithm: str = 'sha256') -> Dict[str, any]:
        """
        Create a manifest file for directory backup
        
        Args:
            directory: Directory to create manifest for
            output_file: Path to save manifest file (optional)
            algorithm: Hash algorithm to use
        
        Returns:
            Dictionary with manifest information
        """
        manifest = {
            'directory': directory,
            'created': datetime.now().isoformat(),
            'algorithm': algorithm,
            'files': {},
            'total_files': 0,
            'total_size': 0
        }
        
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, directory)
                    
                    try:
                        file_size = os.path.getsize(file_path)
                        file_hash = self.security_utilities.hash_file(file_path, algorithm)
                        
                        manifest['files'][relative_path] = {
                            'size': file_size,
                            'hash': file_hash,
                            'path': file_path
                        }
                        
                        manifest['total_files'] += 1
                        manifest['total_size'] += file_size
                    except Exception as e:
                        manifest['files'][relative_path] = {
                            'error': str(e)
                        }
            
            # Save manifest if output file specified
            if output_file:
                import json
                with open(output_file, 'w') as f:
                    json.dump(manifest, f, indent=2)
                manifest['manifest_file'] = output_file
        
        except Exception as e:
            manifest['error'] = str(e)
        
        return manifest
    
    def verify_backup_against_manifest(self, directory: str, manifest_file: str) -> Dict[str, any]:
        """
        Verify backup directory against manifest
        
        Args:
            directory: Directory to verify
            manifest_file: Path to manifest file
        
        Returns:
            Dictionary with verification results
        """
        result = {
            'verified': False,
            'matches': 0,
            'mismatches': 0,
            'missing_files': [],
            'extra_files': [],
            'errors': []
        }
        
        try:
            import json
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)
            
            algorithm = manifest.get('algorithm', 'sha256')
            manifest_files = manifest.get('files', {})
            
            # Check files in directory
            actual_files = set()
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, directory)
                    actual_files.add(relative_path)
                    
                    if relative_path in manifest_files:
                        expected_hash = manifest_files[relative_path].get('hash')
                        if expected_hash:
                            actual_hash = self.security_utilities.hash_file(file_path, algorithm)
                            if actual_hash == expected_hash:
                                result['matches'] += 1
                            else:
                                result['mismatches'] += 1
                                result['errors'].append(f'Mismatch: {relative_path}')
            
            # Find missing files
            manifest_file_set = set(manifest_files.keys())
            result['missing_files'] = list(manifest_file_set - actual_files)
            result['extra_files'] = list(actual_files - manifest_file_set)
            
            result['verified'] = (result['mismatches'] == 0 and 
                                len(result['missing_files']) == 0)
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def check_backup_age(self, backup_file: str) -> Dict[str, any]:
        """
        Check backup file age and freshness
        
        Args:
            backup_file: Path to backup file
        
        Returns:
            Dictionary with age information
        """
        result = {
            'backup_file': backup_file,
            'exists': False,
            'age_days': None,
            'last_modified': None,
            'is_fresh': False,
            'recommendation': None
        }
        
        try:
            if not os.path.exists(backup_file):
                result['error'] = 'Backup file not found'
                return result
            
            result['exists'] = True
            
            # Get modification time
            mod_time = os.path.getmtime(backup_file)
            result['last_modified'] = datetime.fromtimestamp(mod_time).isoformat()
            
            # Calculate age
            now = datetime.now()
            backup_date = datetime.fromtimestamp(mod_time)
            age_delta = now - backup_date
            result['age_days'] = age_delta.days
            
            # Determine if fresh (less than 7 days)
            result['is_fresh'] = result['age_days'] < 7
            
            # Generate recommendation
            if result['age_days'] > 30:
                result['recommendation'] = 'Backup is old - consider creating a new backup'
            elif result['age_days'] > 14:
                result['recommendation'] = 'Backup is getting old - consider updating'
            else:
                result['recommendation'] = 'Backup is fresh'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def verify_multiple_backups(self, backup_files: List[str],
                               algorithm: str = 'sha256') -> Dict[str, Dict]:
        """
        Verify multiple backup files
        
        Args:
            backup_files: List of backup file paths
            algorithm: Hash algorithm to use
        
        Returns:
            Dictionary mapping file paths to verification results
        """
        results = {}
        
        for backup_file in backup_files:
            results[backup_file] = self.verify_backup_integrity(backup_file, algorithm=algorithm)
        
        return results
    
    def generate_backup_report(self, backup_file: str, original_hash: str = None) -> str:
        """
        Generate human-readable backup verification report
        
        Args:
            backup_file: Path to backup file
            original_hash: Expected hash (optional)
        
        Returns:
            Formatted report string
        """
        verification = self.verify_backup_integrity(backup_file, original_hash)
        age_check = self.check_backup_age(backup_file)
        
        report = f"""
Backup Verification Report
{'='*60}
Backup File: {backup_file}
Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

File Status:
  Exists: {'✓ Yes' if verification['exists'] else '✗ No'}
  Size: {verification.get('size', 0):,} bytes
  Integrity: {verification['integrity'].upper()}

Hash Information:
  Hash ({verification.get('algorithm', 'sha256')}): {verification.get('hash', 'N/A')}
"""
        
        if verification.get('matches_original') is not None:
            status = '✓ Matches' if verification['matches_original'] else '✗ Mismatch'
            report += f"  Matches Original: {status}\n"
        
        if age_check.get('last_modified'):
            report += f"\nBackup Age:\n"
            report += f"  Last Modified: {age_check['last_modified']}\n"
            report += f"  Age: {age_check.get('age_days', 'N/A')} days\n"
            report += f"  Fresh: {'✓ Yes' if age_check.get('is_fresh') else '✗ No'}\n"
            if age_check.get('recommendation'):
                report += f"  Recommendation: {age_check['recommendation']}\n"
        
        if verification.get('error'):
            report += f"\nError: {verification['error']}\n"
        
        return report
