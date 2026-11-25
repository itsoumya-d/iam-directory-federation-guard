"""Smoke tests for IAM Directory Federation Guard."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from iam_guard import __version__


def test_version():
    assert __version__ == "0.1.0"
