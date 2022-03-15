from fixtures import *


def test_md5(pma01):
    assert viv_utils.getVwSampleMd5(pma01) == "290934c61de9176ad682ffdd65f0a669"