"""
tests/conftest.py
Ensures the project root is on sys.path so 'core', 'modules', 'vuln', etc.
are importable when running `pytest` from the project root.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))