"""
Forensic File Analyzer - Main Entry Point
Student: Muhammad Awais Ali
University of Roehampton London
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent))

from signature_analyzer import SignatureAnalyzer
from entropy_calculator import EntropyCalculator
from hash_verifier import HashVerifier
from metadata_parser import MetadataParser

def main():
    """Main function to start the forensic analyzer"""
    print("=" * 70)
    print("FORENSIC FILE ANALYZER")
    print("Automated Anti-Forensic Detection Tool")
    print("=" * 70)
    
    # Allow custom directory from command line
    if len(sys.argv) > 1:
        test_directory = sys.argv[1]
    else:
        test_directory = "tests/test_files"
    
    print(f"Analyzing directory: {test_directory}")
    
    # Module 1: File Signature Analysis
    print("\n[MODULE 1: FILE SIGNATURE ANALYSIS]")
    print("-" * 70)
    analyzer = SignatureAnalyzer()
    analyzer.analyze_directory(test_directory)
    analyzer.print_report()
    
    # Module 2: Entropy Analysis
    print("\n[MODULE 2: ENTROPY ANALYSIS]")
    print("-" * 70)
    entropy_calc = EntropyCalculator(threshold=7.5)
    entropy_calc.analyze_directory(test_directory)
    entropy_calc.print_report()
    
    # Print entropy statistics
    stats = entropy_calc.get_statistics()
    if stats:
        print("\n" + "="*70)
        print("ENTROPY STATISTICS")
        print("="*70)
        print(f"Minimum Entropy: {stats['min_entropy']:.3f}")
        print(f"Maximum Entropy: {stats['max_entropy']:.3f}")
        print(f"Average Entropy: {stats['avg_entropy']:.3f}")
        print("="*70)
    
    #Module 3: Hash verification
    print("\n[Module 3: Hash Verification]")
    print("-" * 70)
    hash_verifier = HashVerifier()
    hash_verifier.analyze_directory(test_directory)
    hash_verifier.print_report()
    #Export Hashes to CSV
    hash_verifier.export_hashes("reports/file_hashes.csv")

    #Module 4: Metadata Analysis
    print("\n[Module 4: Metadata Analysis]")
    print("-" * 70)
    metadata_parser = MetadataParser()
    metadata_parser.analyze_directory(test_directory)
    metadata_parser.print_report()

    #Final Summary
    print("\n" + "-"*70)
    print("Analysis Complete")
    print("="*70)
    print(f" Files Analyzed: {len(hash_verifier.results)}")
    print(f" Reports generated in: reports/")
    print("="*70)


if __name__ == "__main__":
    main()