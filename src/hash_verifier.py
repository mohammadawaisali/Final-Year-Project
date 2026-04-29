"""
Hash Verification Module
Calculates cryptographic hashes for file integrity verification
"""

import hashlib
from pathlib import Path
from collections import defaultdict

class HashVerifier:
    """Calculates and verifies file hashes"""
    
    def __init__(self):
        """Initialize hash verifier"""
        self.results = []
        self.hash_database = defaultdict(list)  # Store hash -> [files] mapping
        
    def calculate_hashes(self, filepath, algorithms=None):
        """
        Calculate multiple hash algorithms for a file
        
        Args:
            filepath: Path to file
            algorithms: List of hash algorithms (default: ['md5', 'sha256'])
            
        Returns:
            dict: Hash values for each algorithm
        """
        if algorithms is None:
            algorithms = ['md5', 'sha256']
        
        hashes = {}
        
        try:
            # Create hash objects
            hash_objects = {alg: hashlib.new(alg) for alg in algorithms}
            
            # Read file in chunks for efficiency
            with open(filepath, 'rb') as f:
                chunk_size = 4096
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    # Update all hash objects
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
            
            # Get hexadecimal hash values
            hashes = {alg: hash_objects[alg].hexdigest() 
                     for alg in algorithms}
            
            return hashes
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_file(self, filepath):
        """
        Analyze a file and calculate its hashes
        
        Args:
            filepath: Path to file
            
        Returns:
            dict: Analysis results with hash values
        """
        try:
            file_path = Path(filepath)
            
            if not file_path.exists():
                return {
                    'filename': str(filepath),
                    'status': 'error',
                    'message': 'File not found'
                }
            
            # Calculate hashes
            hashes = self.calculate_hashes(file_path)
            
            if 'error' in hashes:
                return {
                    'filename': file_path.name,
                    'status': 'error',
                    'message': hashes['error']
                }
            
            result = {
                'filename': file_path.name,
                'filepath': str(file_path),
                'md5': hashes.get('md5', 'N/A'),
                'sha256': hashes.get('sha256', 'N/A'),
                'size_bytes': file_path.stat().st_size,
                'status': 'success'
            }
            
            self.results.append(result)
            
            # Store in hash database for duplicate detection
            md5_hash = hashes.get('md5')
            if md5_hash:
                self.hash_database[md5_hash].append(result)
            
            return result
            
        except Exception as e:
            return {
                'filename': str(filepath),
                'status': 'error',
                'message': str(e)
            }
    
    def analyze_directory(self, directory_path):
        """
        Analyze all files in a directory
        
        Args:
            directory_path: Path to directory
            
        Returns:
            list: Analysis results for all files
        """
        directory = Path(directory_path)
        
        if not directory.exists() or not directory.is_dir():
            print(f"Error: {directory_path} is not a valid directory")
            return []
        
        files = [f for f in directory.rglob('*') if f.is_file()]
        
        print(f"\nCalculating hashes for {len(files)} files...")
        
        for file_path in files:
            self.analyze_file(file_path)
        
        return self.results
    
    def find_duplicates(self):
        """
        Find duplicate files based on MD5 hash
        
        Returns:
            dict: Hash values with multiple files (duplicates)
        """
        duplicates = {}
        
        for hash_value, files in self.hash_database.items():
            if len(files) > 1:
                duplicates[hash_value] = files
        
        return duplicates
    
    def verify_against_database(self, known_hashes_file=None):
        """
        Verify files against a known hash database
        
        Args:
            known_hashes_file: Path to file containing known hashes
            
        Returns:
            dict: Matched files
        """
        # This is a placeholder for NSRL or custom hash database
        # In production, you would load from a file
        
        known_hashes = {}
        
        if known_hashes_file and Path(known_hashes_file).exists():
            with open(known_hashes_file, 'r') as f:
                for line in f:
                    parts = line.strip().split(',')
                    if len(parts) >= 2:
                        known_hashes[parts[0]] = parts[1]
        
        matches = []
        for result in self.results:
            md5_hash = result.get('md5')
            if md5_hash in known_hashes:
                matches.append({
                    'file': result['filename'],
                    'hash': md5_hash,
                    'description': known_hashes[md5_hash]
                })
        
        return matches
    
    def print_report(self):
        """Print formatted hash verification report"""
        print("\n" + "="*70)
        print("HASH VERIFICATION REPORT")
        print("="*70)
        
        total_files = len(self.results)
        print(f"\nTotal Files Analyzed: {total_files}")
        
        if self.results:
            print("\n" + "-"*70)
            print("FILE HASHES:")
            print("-"*70)
            
            for result in self.results:
                print(f"\n📄 {result['filename']}")
                print(f"   MD5:    {result['md5']}")
                print(f"   SHA256: {result['sha256']}")
                print(f"   Size:   {result['size_bytes']} bytes")
        
        # Check for duplicates
        duplicates = self.find_duplicates()
        
        if duplicates:
            print("\n" + "="*70)
            print("DUPLICATE FILES DETECTED:")
            print("="*70)
            
            for hash_value, files in duplicates.items():
                print(f"\n🔄 Duplicate Set (MD5: {hash_value[:16]}...)")
                for file_info in files:
                    print(f"   - {file_info['filename']}")
        else:
            print("\n✓ No duplicate files detected")
        
        print("\n" + "="*70)
    
    def export_hashes(self, output_file):
        """
        Export hashes to a CSV file
        
        Args:
            output_file: Path to output file
        """
        try:
            with open(output_file, 'w') as f:
                # Write header
                f.write("Filename,MD5,SHA256,Size\n")
                
                # Write results
                for result in self.results:
                    f.write(f"{result['filename']},{result['md5']},"
                           f"{result['sha256']},{result['size_bytes']}\n")
            
            print(f"\n✓ Hashes exported to: {output_file}")
            
        except Exception as e:
            print(f"\n✗ Error exporting hashes: {e}")