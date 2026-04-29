"""
Create test files for signature and entropy analysis testing
"""

import os
import random
import shutil
from PIL import Image
from datetime import datetime

def create_test_files():
    """Create sample files for testing"""
    
    test_dir = "tests/test_files"
    os.makedirs(test_dir, exist_ok=True)
    
    print("Creating test files...\n")
    
    # 1. Normal text file (LOW ENTROPY)
    with open(f"{test_dir}/normal_document.txt", "w") as f:
        f.write("This is a normal text file.\n" * 50)
    print("✓ Created: normal_document.txt (Low entropy)")
    
    # 2. PNG file (MEDIUM-HIGH ENTROPY)
    png_data = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
        0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41,
        0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
        0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00,
        0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
        0x42, 0x60, 0x82
    ])
    with open(f"{test_dir}/normal_image.png", "wb") as f:
        f.write(png_data)
    print("✓ Created: normal_image.png (Medium entropy)")

    ## 2b. JPEG with EXIF metadata
    img = Image.new('RGB', (100, 100), color='red')
    img.save(f"{test_dir}/photo_with_exif.jpg", 'JPEG', quality=95)
    print("✓ Created: photo_with_exif.jpg (With basic metadata)")
    
    # 3. Suspicious: PNG data with .txt extension (SIGNATURE MISMATCH)
    with open(f"{test_dir}/suspicious_renamed.txt", "wb") as f:
        f.write(png_data)
    print("⚠️  Created: suspicious_renamed.txt (Signature mismatch)")
    
    # 4. Suspicious: text file with .png extension (SIGNATURE MISMATCH)
    with open(f"{test_dir}/fake_image.png", "w") as f:
        f.write("This is actually a text file pretending to be an image!")
    print("⚠️  Created: fake_image.png (Signature mismatch)")
    
    # 5. Simulated encrypted file (VERY HIGH ENTROPY)
    random_data = bytes([random.randint(0, 255) for _ in range(5000)])
    with open(f"{test_dir}/encrypted_file.dat", "wb") as f:
        f.write(random_data)
    print("⚠️  Created: encrypted_file.dat (High entropy - simulated encryption)")
    
    # 6. Repetitive file (VERY LOW ENTROPY)
    with open(f"{test_dir}/repetitive.txt", "w") as f:
        f.write("A" * 5000)
    print("✓ Created: repetitive.txt (Very low entropy)")
    
    # 7. Normal PDF header
    with open(f"{test_dir}/document.pdf", "w") as f:
        f.write("%PDF-1.4\n")
        f.write("This is a simple PDF file for testing.\n" * 20)
    print("✓ Created: document.pdf (Normal entropy)")
    
    # 8. DUPLICATE FILE - copy of normal_document.txt with different name
    shutil.copy(f"{test_dir}/normal_document.txt", 
                f"{test_dir}/document_copy.txt")
    print("🔄 Created: document_copy.txt (Duplicate of normal_document.txt)")
    
    print(f"\n✓ All test files created in: {test_dir}")
    print("\nFile Summary:")
    print("  Total files: 9")
    print("  Image files: 3 (2 PNG, 1 JPEG)")
    print("  Signature mismatches: 2")
    print("  High entropy: 1")
    print("  Duplicates: 1 pair")

if __name__ == "__main__":
    create_test_files()