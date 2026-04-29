"""
Test the visualizer and report generator modules
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from signature_analyzer import SignatureAnalyzer
from entropy_calculator import EntropyCalculator
from hash_verifier import HashVerifier
from metadata_parser import MetadataParser
from visualizer import ForensicVisualizer
from report_generator import ReportGenerator

def test_complete_analysis():
    """Test complete analysis with PDF generation"""
    
    print("="*70)
    print("TESTING COMPLETE FORENSIC ANALYSIS SYSTEM")
    print("="*70)
    
    # Analyze test files
    test_dir = "tests/advanced_scenarios"
    
    print("\n[1/5] Running File Signature Analysis...")
    sig_analyzer = SignatureAnalyzer()
    sig_analyzer.analyze_directory(test_dir)
    
    print("\n[2/5] Running Entropy Analysis...")
    entropy_calc = EntropyCalculator()
    entropy_calc.analyze_directory(test_dir)
    
    print("\n[3/5] Running Hash Verification...")
    hash_verifier = HashVerifier()
    hash_verifier.analyze_directory(test_dir)
    
    print("\n[4/5] Running Metadata Analysis...")
    metadata_parser = MetadataParser()
    metadata_parser.analyze_directory(test_dir)
    
    # Generate visualizations
    print("\n[5/5] Generating Visualizations...")
    visualizer = ForensicVisualizer()
    graphs = visualizer.generate_all_visualizations(
        sig_analyzer.results,
        entropy_calc.results,
        hash_verifier.results,
        metadata_parser.results
    )
    
    # Generate PDF report
    print("\n" + "="*70)
    print("GENERATING PDF REPORT")
    print("="*70)
    
    report_gen = ReportGenerator()
    pdf_path = report_gen.generate_pdf_report(
        sig_analyzer.results,
        entropy_calc.results,
        hash_verifier.results,
        metadata_parser.results,
        graph_paths=graphs,
        output_filename="forensic_analysis_complete.pdf"
    )
    
    print("\n" + "="*70)
    print("✓ ANALYSIS COMPLETE!")
    print("="*70)
    print(f"\n📊 Graphs saved in: reports/graphs/")
    print(f"📄 PDF Report: {pdf_path}")
    print("\n✓ Open the PDF to see the complete forensic report!")

if __name__ == "__main__":
    test_complete_analysis()