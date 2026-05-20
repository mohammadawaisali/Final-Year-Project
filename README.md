# Automated File Analysis Tool for Windows Digital Forensics

**Student:** Muhammad Awais Ali  
**Supervisor:** Mastaneh Davis  
**Institution:** University of Roehampton, London  
**Year:** 2025–2026  

## Project Overview
An automated digital forensics tool for detecting anti-forensic techniques
and hidden data artifacts. Analyses files using four independent detection
methods and produces professional PDF reports suitable for legal submission.

## Detection Modules
| Module | Method | What it Detects |
|--------|--------|-----------------|
| `signature_analyzer.py` | Magic byte inspection | File type obfuscation |
| `entropy_calculator.py` | Shannon entropy (threshold 7.5) | Encryption / steganography |
| `hash_verifier.py` | MD5, SHA1, SHA256 fingerprinting | Duplicates / data staging / VirusTotal|
| `metadata_parser.py` | EXIF / Office XML / PDF metadata | Timestamp manipulation |

## Installation
```bash
git clone https://github.com/mohammadawaisali/Final-Year-Project.git
cd Final-Year-Project
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
python3 main.py
```

## Usage
1. Launch the GUI with `python3 main.py`
2. Navigate to **Run Analysis** and select a target directory
3. Click **Run Full Analysis**
4. View findings in the **Results** tab
5. Export a full PDF report from **Export Report**

## Project Structure
```text
ForensicFileAnalyzer/
├── reports/
│   ├── graphs/
│   │   ├── detection_summary.png
│   │   ├── entropy_histogram.png
│   │   └── timeline_chart.png
│   ├── file_hashes.csv
│   ├── forensic_analysis_complete.pdf
│   └── forensic_analysis_report.pdf
│
├── src/
│   ├── __pycache__/
│   ├── gui/
|   |    ├── panels/
│   |    |      ├── __init__.py
│   |    |      ├── analysis_panel.py
│   |    |      ├── home_panel.py
│   |    |      ├── report_panel.py
│   |    |      └── results_panel.py
│   |    |
|   |    ├── widgets/
│   |    |      ├── __init__.py
│   |    |      ├── file_table.py
│   |    |      ├── progress_bar.py
│   |    |      └── stat_card.py
│   |    |
|   |    ├── __init__.py
|   |    ├── app.py
|   |    ├── sidebar.py
|   |    └── theme.py
│   ├── __init__.py
│   ├── entropy_calculator.py
│   ├── forensic_intelligence.py
│   ├── hash_verifier.py
│   ├── main.py
│   ├── metadata_parser.py
│   ├── report_generator.py
│   ├── signature_analyzer.py
│   └── visualizer.py
│
├── tests/
│   ├── advanced_scenarios/
│   ├── realistic_dataset/
│   └── test_files/
│
├── .gitignore
├── create_advanced_tests.py
├── create_test_files.py
├── generate_realistic_dataset.py
├── main.py
└── README.md
```
