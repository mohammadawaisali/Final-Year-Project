"""
Generate realistic file dataset for testing
"""

import os
import random
from PIL import Image

def generate_dataset():
    """Generate 50+ realistic files"""
    
    output_dir = "tests/realistic_dataset"
    os.makedirs(output_dir, exist_ok=True)
    
    print("Generating realistic dataset...")
    
    # 1. Normal documents (20 files)
    for i in range(20):
        with open(f"{output_dir}/document_{i:03d}.txt", "w") as f:
            f.write(f"Normal document #{i}\n" * random.randint(10, 100))
    
    # 2. Normal images (15 files)
    for i in range(15):
        color = (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        img = Image.new('RGB', (100, 100), color=color)
        img.save(f"{output_dir}/image_{i:03d}.jpg", 'JPEG')
    
    # 3. Suspicious files (10 files)
    for i in range(5):
        # High entropy files
        random_data = bytes([random.randint(0, 255) for _ in range(1000)])
        with open(f"{output_dir}/encrypted_{i:03d}.dat", "wb") as f:
            f.write(random_data)
    
    for i in range(5):
        # Extension mismatches
        img = Image.new('RGB', (50, 50), color='red')
        img.save(f"{output_dir}/suspicious_{i:03d}.txt", 'JPEG')  # JPEG saved as .txt
    
    # 4. Duplicate files (5 files)
    original = "DUPLICATE CONTENT FOR TESTING"
    for i in range(5):
        with open(f"{output_dir}/copy_{i:03d}.doc", "w") as f:
            f.write(original)
    
    print(f"✅ Generated 50 files in {output_dir}")
    print("  - 20 normal documents")
    print("  - 15 normal images")
    print("  - 10 suspicious files")
    print("  - 5 duplicates")

if __name__ == "__main__":
    generate_dataset()