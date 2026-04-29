# main.py  (in ForensicFileAnalyzer/ root)
import sys
from pathlib import Path

# Make src/ importable
sys.path.insert(0, str(Path(__file__).parent / "src"))

from gui.app import ForensicApp

if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()