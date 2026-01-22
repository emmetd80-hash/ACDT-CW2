import sys
from pathlib import Path

# Add project root to import path so "main.py" can be imported in CI
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from main import is_valid_email


def test_valid_email():
    assert is_valid_email("test@example.com")


def test_invalid_email():
    assert not is_valid_email("not-an-email")
