"""
Entropy Calculator Module
Calculates Shannon entropy to detect encrypted/steganographic files
"""

import math
import os
from pathlib import Path
from collections import Counter

class EntropyCalculator:
    """Calculates Shannon entropy for files"""
    
    def __init__(self, threshold=7.5):
        """
        Initialize entropy calculator
        
        Args:
            threshold: Entropy threshold for flagging files (default: 7.5)
        """
        self.threshold = threshold
        self.results = []
    
    def calculate_entropy(self, data):
        """
        Calculate Shannon entropy of data
        
        Formula: H(X) = -Σ P(xi) * log2(P(xi))
        
        Args:
            data: Bytes to analyze
            
        Returns:
            float: Entropy value (0-8)
        """
        if not data:
            return 0.0
        
        # Count frequency of each byte value
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_counts.values():
            # Calculate probability of this byte
            probability = count / total_bytes
            # Add to entropy sum
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def analyze_file(self, filepath, chunk_size=4096):
        """
        Analyze a file's entropy
        
        Args:
            filepath: Path to file
            chunk_size: Size of chunks to read (default: 4KB)
            
        Returns:
            dict: Analysis results
        """
        try:
            file_path = Path(filepath)
            
            if not file_path.exists():
                return {
                    'filename': str(filepath),
                    'status': 'error',
                    'message': 'File not found'
                }
            
            # Read file in chunks for efficiency
            file_size = file_path.stat().st_size
            
            # For small files, read all at once
            if file_size < chunk_size:
                with open(file_path, 'rb') as f:
                    data = f.read()
                entropy = self.calculate_entropy(data)
            else:
                # For large files, sample multiple chunks
                entropies = []
                with open(file_path, 'rb') as f:
                    # Read first chunk
                    data = f.read(chunk_size)
                    if data:
                        entropies.append(self.calculate_entropy(data))
                    
                    # Read middle chunk
                    if file_size > chunk_size * 2:
                        f.seek(file_size // 2)
                        data = f.read(chunk_size)
                        if data:
                            entropies.append(self.calculate_entropy(data))
                    
                    # Read last chunk
                    f.seek(max(0, file_size - chunk_size))
                    data = f.read(chunk_size)
                    if data:
                        entropies.append(self.calculate_entropy(data))
                
                # Average entropy across chunks
                entropy = sum(entropies) / len(entropies) if entropies else 0.0
            
            # Determine if file is suspicious
            is_high_entropy = entropy >= self.threshold
            
            # Categorize the entropy level
            if entropy < 4.0:
                category = "Very Low (Plain text/Repetitive)"
            elif entropy < 6.0:
                category = "Low (Normal files)"
            elif entropy < 7.0:
                category = "Medium (Compressed)"
            elif entropy < 7.5:
                category = "High (Likely compressed)"
            else:
                category = "Very High (Encrypted/Steganographic)"
            
            result = {
                'filename': file_path.name,
                'filepath': str(file_path),
                'entropy': round(entropy, 3),
                'threshold': self.threshold,
                'high_entropy': is_high_entropy,
                'category': category,
                'status': 'suspicious' if is_high_entropy else 'normal',
                'size_bytes': file_size
            }
            
            self.results.append(result)
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
        
        # Get all files
        files = [f for f in directory.rglob('*') if f.is_file()]
        
        print(f"\nCalculating entropy for {len(files)} files...")
        
        for file_path in files:
            self.analyze_file(file_path)
        
        return self.results
    
    def get_high_entropy_files(self):
        """
        Get files with high entropy (potentially encrypted/steganographic)
        
        Returns:
            list: High entropy files
        """
        return [r for r in self.results if r.get('high_entropy', False)]
    
    def print_report(self):
        """Print formatted entropy analysis report"""
        print("\n" + "="*70)
        print("ENTROPY ANALYSIS REPORT")
        print("="*70)
        
        total_files = len(self.results)
        high_entropy = len(self.get_high_entropy_files())
        normal_entropy = total_files - high_entropy
        
        print(f"\nTotal Files Analyzed: {total_files}")
        print(f"Normal Entropy Files: {normal_entropy}")
        print(f"High Entropy Files: {high_entropy}")
        print(f"Threshold: {self.threshold}")
        
        if self.results:
            print("\n" + "-"*70)
            print("DETAILED RESULTS:")
            print("-"*70)
            
            # Sort by entropy (highest first)
            sorted_results = sorted(self.results, 
                                   key=lambda x: x.get('entropy', 0), 
                                   reverse=True)
            
            for result in sorted_results:
                symbol = "⚠️ " if result.get('high_entropy') else "✓ "
                print(f"\n{symbol} {result['filename']}")
                print(f"   Entropy: {result['entropy']:.3f}")
                print(f"   Category: {result['category']}")
                
                if result.get('high_entropy'):
                    print(f"   ⚠️  HIGH ENTROPY - Possible encryption/steganography")
        
        print("\n" + "="*70)
    
    def get_statistics(self):
        """
        Get statistical summary of entropy values
        
        Returns:
            dict: Statistics including min, max, average entropy
        """
        if not self.results:
            return {}
        
        entropies = [r['entropy'] for r in self.results if 'entropy' in r]
        
        if not entropies:
            return {}
        
        return {
            'min_entropy': min(entropies),
            'max_entropy': max(entropies),
            'avg_entropy': sum(entropies) / len(entropies),
            'total_files': len(entropies)
        }