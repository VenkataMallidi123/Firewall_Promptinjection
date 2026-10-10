import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "testing" / "samples"


@pytest.fixture(scope="session")
def fw():
    from firewall import Firewall
    return Firewall()


@pytest.fixture(scope="session")
def samples() -> Path:
    if not (SAMPLES / "attacks").exists():
        sys.path.insert(0, str(SAMPLES))
        import make_samples
        make_samples.main()
    return SAMPLES
