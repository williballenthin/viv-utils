from pathlib import Path

import pytest

import viv_utils


CD = Path(__file__).parent
DATA = CD / "data"


@pytest.fixture
def pma01():
    return viv_utils.getWorkspace(str(DATA / "Practical Malware Analysis Lab 01-01.dll_"), should_save=False)
