from pathlib import Path

import pytest

import viv_utils

CD = Path(__file__).parent
DATA = CD / "data"


@pytest.fixture
def pma01():
    return viv_utils.getWorkspace(str(DATA / "Practical Malware Analysis Lab 01-01.dll_"), should_save=False)


@pytest.fixture
def sample_038476():
    return viv_utils.getWorkspace(
        str(DATA / "038476f1705f3ac1237ac57f4c1753e0aa085dd7cda5669d4e93399cf7a565af.exe_"), should_save=False
    )
