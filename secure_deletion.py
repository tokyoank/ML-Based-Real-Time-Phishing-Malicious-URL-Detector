"""
Secure File Deletion Module
Provides secure file deletion (shredding) that makes recovery difficult
"""

import os
import random
import secrets
from typing import Optional


class SecureDeletion:
    """Handles secure file deletion operations"""
    
    def __init__(self):
        self.default_passes = 3  # Default number of overwrite passes
    
    def shred_file(self, file_path: str, passes: int = None, verbose: bool = False) -> bool:
        """
        Securely delete a file by overwriting it multiple times
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes (default: 3)
            verbose: Print progress messages
        
        Returns:
            True if successful, False otherwise
        """
        if passes is None:
            passes = self.default_passes
        
        try:
            if not os.path.exists(file_path):
                if verbose:
                    print(f"File not found: {file_path}")
                return False
            
            file_size = os.path.getsize(file_path)
            
            if verbose:
                print(f"Securely deleting {file_path} ({file_size} bytes)...")
            
            with open(file_path, 'rb+') as f:
                for pass_num in range(passes):
                    if verbose:
                        print(f"  Pass {pass_num + 1}/{passes}...")
                    
                    # Move to beginning of file
                    f.seek(0)
                    
                    # Overwrite with random data
                    if pass_num == 0:
                        # First pass: random data
                        random_data = secrets.token_bytes(file_size)
                    elif pass_num == passes - 1:
                        # Last pass: all zeros
                        random_data = b'\x00' * file_size
                    else:
                        # Middle passes: random data
                        random_data = secrets.token_bytes(file_size)
                    
                    f.write(random_data)
                    f.flush()
                    os.fsync(f.fileno())
            
            # Close file and delete
            f.close()
            os.remove(file_path)
            
            if verbose:
                print(f"File securely deleted: {file_path}")
            
            return True
        
        except PermissionError:
            if verbose:
                print(f"Permission denied: {file_path}")
            return False
        except Exception as e:
            if verbose:
                print(f"Error deleting file: {str(e)}")
            return False
    
    def shred_file_gutmann(self, file_path: str, verbose: bool = False) -> bool:
        """
        Securely delete file using Gutmann method (35 passes)
        
        Args:
            file_path: Path to file to delete
            verbose: Print progress messages
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                if verbose:
                    print(f"File not found: {file_path}")
                return False
            
            file_size = os.path.getsize(file_path)
            
            if verbose:
                print(f"Gutmann method: Deleting {file_path} ({file_size} bytes, 35 passes)...")
            
            # Gutmann patterns (35 passes)
            patterns = [
                b'\x55', b'\xAA',  # Patterns 1-2
                b'\x92', b'\x49', b'\x24',  # Patterns 3-5
                b'\x00', b'\x11', b'\x22', b'\x33', b'\x44', b'\x55',
                b'\x66', b'\x77', b'\x88', b'\x99', b'\xAA', b'\xBB',
                b'\xCC', b'\xDD', b'\xEE', b'\xFF',  # Patterns 6-21
            ]
            
            # Fill remaining patterns with random
            while len(patterns) < 35:
                patterns.append(secrets.token_bytes(1))
            
            with open(file_path, 'rb+') as f:
                for pass_num in range(35):
                    if verbose and (pass_num + 1) % 5 == 0:
                        print(f"  Pass {pass_num + 1}/35...")
                    
                    f.seek(0)
                    
                    if pass_num < len(patterns):
                        pattern = patterns[pass_num]
                        data = pattern * file_size
                    else:
                        data = secrets.token_bytes(file_size)
                    
                    f.write(data[:file_size])
                    f.flush()
                    os.fsync(f.fileno())
            
            f.close()
            os.remove(file_path)
            
            if verbose:
                print(f"File securely deleted (Gutmann method): {file_path}")
            
            return True
        
        except Exception as e:
            if verbose:
                print(f"Error deleting file: {str(e)}")
            return False
    
    def shred_directory(self, dir_path: str, passes: int = None, verbose: bool = False) -> bool:
        """
        Securely delete all files in a directory
        
        Args:
            dir_path: Path to directory
            passes: Number of overwrite passes per file
            verbose: Print progress messages
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isdir(dir_path):
                if verbose:
                    print(f"Directory not found: {dir_path}")
                return False
            
            files_deleted = 0
            
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if self.shred_file(file_path, passes, verbose):
                        files_deleted += 1
            
            if verbose:
                print(f"Deleted {files_deleted} files from {dir_path}")
            
            # Remove empty directories
            try:
                os.rmdir(dir_path)
            except OSError:
                pass  # Directory not empty or error
            
            return True
        
        except Exception as e:
            if verbose:
                print(f"Error deleting directory: {str(e)}")
            return False
    
    def overwrite_file(self, file_path: str, data: bytes) -> bool:
        """
        Overwrite file with specific data (for secure writing)
        
        Args:
            file_path: Path to file
            data: Data to write
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(file_path, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            return True
        except Exception as e:
            print(f"Error overwriting file: {str(e)}")
            return False
