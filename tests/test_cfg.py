from fixtures import *


def test_prev_loc(pma01):
    # start of insn
    assert viv_utils.get_prev_loc(pma01, 0x10001015)[0] == 0x10001010
    # middle of insn
    assert viv_utils.get_prev_loc(pma01, 0x10001016)[0] == 0x10001010
    # undefined location, directly after loc
    assert viv_utils.get_prev_loc(pma01, 0x100011FA)[0] == 0x100011F7


def test_prev_opcode(pma01):
    assert viv_utils.get_prev_opcode(pma01, 0x10001015).va == 0x10001010
    assert viv_utils.get_prev_opcode(pma01, 0x10001016).va == 0x10001010


def test_all_xrefs_from(pma01):
    # mov     eax, 11F8h
    # single xref: fallthrough
    assert len(list(viv_utils.get_all_xrefs_from(pma01, 0x10001010))) == 1

    # jnz     loc_100011E8
    # two xrefs: fallthrough and conditional jump
    assert len(list(viv_utils.get_all_xrefs_from(pma01, 0x10001028))) == 2


def test_all_xrefs_to(pma01):
    # single xref: fallthrough
    assert len(list(viv_utils.get_all_xrefs_to(pma01, 0x10001015))) == 1

    # four xrefs: fallthrough and three jumps
    assert len(list(viv_utils.get_all_xrefs_to(pma01, 0x100011E8))) == 4


def test_cfg(pma01):
    f = viv_utils.Function(pma01, 0x10001010)
    cfg = viv_utils.CFG(f)

    assert int(cfg.get_root_basic_block()) == 0x10001010

    tails = list(cfg.get_leaf_basic_blocks())
    assert len(tails) == 1

    tail = tails[0]
    assert int(tail) == 0x100011E8

    assert len(list(cfg.get_predecessor_basic_blocks(tail))) == 4
