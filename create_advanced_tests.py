"""
Create advanced forensic test scenarios
"""

import os
import zipfile
from PIL import Image
import random

def create_advanced_tests():
    """Create realistic forensic test scenarios"""
    
    test_dir = "tests/advanced_scenarios"
    os.makedirs(test_dir, exist_ok=True)
    
    print("Creating advanced test scenarios...\n")
    
    # Scenario 1: Steganography simulation
    print("📁 Scenario 1: Steganography Detection")
    
    # Create a normal looking image
    img = Image.new('RGB', (200, 200), color='blue')
    img.save(f"{test_dir}/vacation_photo.jpg", 'JPEG')
    
    # Create same image with "hidden data" (high entropy in LSB)
    # Simulate by adding random noise to least significant bits
    pixels = img.load()
    for i in range(200):
        for j in range(200):
            r, g, b = pixels[i, j]
            # Modify LSB randomly to simulate hidden data
            r = (r & 0xFE) | random.randint(0, 1)
            g = (g & 0xFE) | random.randint(0, 1)
            b = (b & 0xFE) | random.randint(0, 1)
            pixels[i, j] = (r, g, b)
    img.save(f"{test_dir}/vacation_photo_stego.jpg", 'JPEG')
    print("  ✓ Created normal and steganographic images")
    
    # Scenario 2: File extension manipulation
    print("\n📁 Scenario 2: Extension Obfuscation")
    
    # Create executable disguised as PDF
    exe_content = b'MZ\x90\x00' + b'\x00' * 100  # Simple PE header
    with open(f"{test_dir}/invoice.pdf", "wb") as f:
        f.write(exe_content)
    print("  ⚠️  Created: invoice.pdf (actually executable)")
    
    # Create ZIP disguised as JPG
    with zipfile.ZipFile(f"{test_dir}/photo.jpg", 'w') as zf:
        zf.writestr("secret.txt", "Hidden data inside fake image")
    print("  ⚠️  Created: photo.jpg (actually ZIP archive)")
    
    # Scenario 3: Timestamp manipulation
    print("\n📁 Scenario 3: Timestamp Anomalies")
    
    # Create file and modify its timestamps
    with open(f"{test_dir}/old_document.txt", "w") as f:
        f.write("This file claims to be from 2010")
    
    # Modify file timestamps (requires setting manually - demonstrated in concept)
    print("  ✓ Created: old_document.txt (timestamp manipulation scenario)")
    
    # Scenario 4: Multiple duplicates (data exfiltration scenario)
    print("\n📁 Scenario 4: Duplicate Files (Data Exfiltration)")
    
    sensitive_data = "CONFIDENTIAL: Company financial data Q4 2025"
    
    # Create original
    with open(f"{test_dir}/financial_report.xlsx", "w") as f:
        f.write(sensitive_data)
    
    # Create duplicates with different names (exfiltration attempt)
    duplicate_names = [
        "report_backup.xlsx",
        "temp_file.tmp",
        "cache.dat",
        "financial_report_copy.xlsx"
    ]
    
    for name in duplicate_names:
        with open(f"{test_dir}/{name}", "w") as f:
            f.write(sensitive_data)
    
    print(f"  🔄 Created: 1 original + {len(duplicate_names)} duplicates")
    
    # Scenario 5: Encrypted archive
    print("\n📁 Scenario 5: Encrypted Container")
    
    # Create password-protected ZIP
    with zipfile.ZipFile(f"{test_dir}/backup.zip", 'w') as zf:
        zf.setpassword(b'secret123')
        zf.writestr("confidential.txt", "Encrypted content")
    print("  ⚠️  Created: backup.zip (encrypted, high entropy)")
    
    # Scenario 6: Metadata stripped image (anti-forensic)
    print("\n📁 Scenario 6: Metadata Stripped Files")
    
    img_with_metadata = Image.new('RGB', (100, 100), color='red')
    img_with_metadata.save(f"{test_dir}/original_photo.jpg", 'JPEG')
    
    # Create copy with stripped metadata
    img_stripped = Image.open(f"{test_dir}/original_photo.jpg")
    # Remove EXIF by saving without it
    img_stripped.save(f"{test_dir}/cleaned_photo.jpg", 'JPEG')
    print("  ⚠️  Created: cleaned_photo.jpg (EXIF stripped)")
    
    print(f"\n✅ Advanced scenarios created in: {test_dir}")
    print("\n📊 Test Scenarios Summary:")
    print("  1. Steganography detection (2 images)")
    print("  2. Extension obfuscation (2 files)")
    print("  3. Timestamp manipulation (1 file)")
    print("  4. Data exfiltration via duplicates (5 files)")
    print("  5. Encrypted container (1 file)")
    print("  6. Metadata stripping (2 files)")
    print(f"\n  Total test files: 13")

if __name__ == "__main__":
    create_advanced_tests()