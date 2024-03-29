from fixtures import *


def test_md5(pma01):
    assert viv_utils.getVwSampleMd5(pma01) == "290934c61de9176ad682ffdd65f0a669"


def test_name(pma01):
    viv_utils.set_function_name(pma01, 0x10001010, "DllMain")
    assert viv_utils.get_function_name(pma01, 0x10001010)


def test_function(pma01):
    f = viv_utils.Function(pma01, 0x10001010)

    assert f.id == "290934c61de9176ad682ffdd65f0a669:0x10001010"
    assert int(f) == 0x10001010

    assert f.name is None
    f.name = "DllMain"
    assert f.name == "DllMain"

    assert len(list(f.basic_blocks)) == 19
    assert list(sorted(map(int, f.basic_blocks))) == [
        0x10001010,
        0x1000102E,
        0x10001067,
        0x1000108C,
        0x100010A3,
        0x100010DD,
        0x100010E9,
        0x10001110,
        0x10001122,
        0x1000113C,
        0x10001154,
        0x10001161,
        0x10001179,
        0x100011B6,
        0x100011C0,
        0x100011D0,
        0x100011DB,
        0x100011E2,
        0x100011E8,
    ]

    bb = list(f.basic_blocks)[0]
    assert int(bb) == 0x10001010
    assert len(bb) == 0x1E

    assert len(list(bb.instructions)) == 9
    insn = list(bb.instructions)[0]

    assert insn.mnem == "mov"


def test_function_name(pma01):
    assert viv_utils.getFunctionName(pma01, 0x10001398) == "msvcrt._initterm"


def test_function_cconv(pma01):
    assert viv_utils.getFunctionCallingConvention(pma01, 0x10001398) == "cdecl"


def test_function_args(pma01):
    assert len(viv_utils.getFunctionArgs(pma01, 0x10001398)) == 2
