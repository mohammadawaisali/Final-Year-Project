cat > README.md << 'EOF'
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
| `hash_verifier.py` | MD5 fingerprinting | Duplicates / data staging |
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
