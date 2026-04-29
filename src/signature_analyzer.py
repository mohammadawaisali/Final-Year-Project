"""
File Signature Analyzer Module
Detects file type mismatches using magic number analysis
"""

import magic
import os
from pathlib import Path

class SignatureAnalyzer:
    """Analyzes files to detect extension-content mismatches"""
    
    def __init__(self):
        """Initialize the signature analyzer"""
        self.magic_detector = magic.Magic(mime=True)
        self.results = []
        
    def analyze_file(self, filepath):
        """
        Analyze a single file for signature mismatch
        
        Args:
            filepath: Path to the file to analyze
            
        Returns:
            dict: Analysis results containing file info and mismatch status
        """
        try:
            # Get file information
            file_path = Path(filepath)
            
            if not file_path.exists():
                return {
                    'filename': str(filepath),
                    'status': 'error',
                    'message': 'File not found'
                }
            
            # Detect actual file type using magic bytes
            detected_type = self.magic_detector.from_file(str(file_path))
            
            # Get file extension
            file_extension = file_path.suffix.lower()
            
            # Check for mismatch
            is_mismatch = self._check_mismatch(detected_type, file_extension)
            
            result = {
                'filename': file_path.name,
                'filepath': str(file_path),
                'extension': file_extension,
                'detected_type': detected_type,
                'mismatch': is_mismatch,
                'status': 'suspicious' if is_mismatch else 'normal',
                'size_bytes': file_path.stat().st_size
            }
            
            self.results.append(result)
            return result
            
        except Exception as e:
            return {
                'filename': str(filepath),
                'status': 'error',
                'message': str(e)
            }
    
    def _check_mismatch(self, detected_type, extension):
        """
        Check if detected type matches the file extension
        
        Args:
            detected_type: MIME type detected from file content
            extension: File extension from filename
            
        Returns:
            bool: True if mismatch detected, False otherwise
        """
        # Common extension to MIME type mappings
        extension_mapping = {
            '.jpg': ['image/jpeg'],
            '.jpeg': ['image/jpeg'],
            '.png': ['image/png'],
            '.gif': ['image/gif'],
            '.pdf': ['application/pdf'],
            '.txt': ['text/plain'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.xls': ['application/vnd.ms-excel'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.zip': ['application/zip'],
            '.exe': ['application/x-executable', 'application/x-mach-binary', 'application/octet-stream'],
            '.py': ['text/x-python', 'text/plain'],
            '.html': ['text/html'],
            '.mp4': ['video/mp4'],
            '.mp3': ['audio/mpeg'],
        }
        
        # If extension not in our mapping, we can't verify
        if extension not in extension_mapping:
            return False
        
        # Check if detected type matches expected types for this extension
        expected_types = extension_mapping[extension]
        
        # Check for match
        for expected in expected_types:
            if expected in detected_type:
                return False  # Match found - no mismatch
        
        return True  # No match found - mismatch detected
    
    def analyze_directory(self, directory_path):
        """
        Analyze all files in a directory
        
        Args:
            directory_path: Path to directory to analyze
            
        Returns:
            list: List of analysis results for all files
        """
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            print(f"Error: {directory_path} is not a valid directory")
            return []
        
        # Get all files (not subdirectories)
        files = [f for f in directory.rglob('*') if f.is_file()]
        
        print(f"\nAnalyzing {len(files)} files...")
        
        for file_path in files:
            self.analyze_file(file_path)
        
        return self.results
    
    def get_suspicious_files(self):
        """
        Get list of files with detected mismatches
        
        Returns:
            list: Files flagged as suspicious
        """
        return [r for r in self.results if r.get('mismatch', False)]
    
    def print_report(self):
        """Print a formatted analysis report"""
        print("\n" + "="*70)
        print("FILE SIGNATURE ANALYSIS REPORT")
        print("="*70)
        
        total_files = len(self.results)
        suspicious_files = len(self.get_suspicious_files())
        normal_files = total_files - suspicious_files
        
        print(f"\nTotal Files Analyzed: {total_files}")
        print(f"Normal Files: {normal_files}")
        print(f"Suspicious Files (Mismatches): {suspicious_files}")
        
        if suspicious_files > 0:
            print("\n" + "-"*70)
            print("SUSPICIOUS FILES DETECTED:")
            print("-"*70)
            
            for result in self.get_suspicious_files():
                print(f"\n⚠️  {result['filename']}")
                print(f"   Extension: {result['extension']}")
                print(f"   Detected Type: {result['detected_type']}")
                print(f"   Location: {result['filepath']}")
        
        print("\n" + "="*70)