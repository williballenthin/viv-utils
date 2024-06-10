import vivisect.const
from fixtures import sample_038476

from viv_utils.flirt import *


def test_invalid_function(sample_038476):
    # this is an address that is not a function
    func_addr = 0x400000
    assert sample_038476.isFunction(func_addr) is False
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False


def test_function_not_called(sample_038476):
    # this is a function that is not called by any other function
    # 0x4010b0 is not called by any other function
    func_addr = 0x4010B0
    caller_fvas = set(
        sample_038476.getFunction(xref[vivisect.const.XR_FROM])
        for xref in sample_038476.getXrefsTo(func_addr, rtype=vivisect.const.REF_CODE)
    )
    assert caller_fvas == set()
    assert is_only_called_from_library_functions(sample_038476, 0x408155) is False


def test_only_called_from_library_functions(sample_038476):
    # this is a function whose top level callers are *all* library functions

    # call graph of 0x40CAA3:
    #
    # Note:
    #   - recognized library functions are denoted by "(lib)"
    #   - non-library functions have no designation
    #
    #      entry (0x4081155) <<< (lib)
    #              |
    #              v
    #       FUN_407660   FUN_403520 <<< (lib)
    #              |        |
    #              v        v
    #       FUN_4027D0   FUN_404980
    #              \        /
    #               \      /
    #                v    v
    #              FUN_40CA76
    #                  |
    #                  v
    #              FUN_40CAA3

    func_addr = 0x40CAA3
    top_level_func_addr1 = 0x408155
    top_level_func_addr2 = 0x403520

    assert is_library_function(sample_038476, func_addr) is False

    make_library_function(sample_038476, top_level_func_addr1)
    make_library_function(sample_038476, top_level_func_addr2)

    assert is_library_function(sample_038476, top_level_func_addr1) is True
    assert is_library_function(sample_038476, top_level_func_addr2) is True

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_called_from_mixed_functions(sample_038476):
    # this is a function whose top level callers are both library and non-library functions

    # call graph of 0x40CAA3:
    #
    # Note:
    #   - recognized library functions are denoted by "(lib)"
    #   - non-library functions have no designation
    #
    #       entry (0x4081155) <<< (lib)
    #              |
    #              v
    #       FUN_407660   FUN_403520
    #              |        |
    #              v        v
    #       FUN_4027D0   FUN_404980
    #              \        /
    #               \      /
    #                v    v
    #              FUN_40CA76
    #                  |
    #                  v
    #              FUN_40CAA3

    func_addr = 0x40CAA3
    top_level_func_addr = 0x408155  # parent caller of 0x40CAA3

    make_library_function(sample_038476, top_level_func_addr)

    assert is_library_function(sample_038476, func_addr) is False
    assert is_library_function(sample_038476, top_level_func_addr) is True

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_function_circular_call_graph(sample_038476):
    # this is a function whose call graph contains a cycle

    # call graph of 0x40B06C:
    #
    # Note:
    #   - recognized library functions are denoted by "(lib)"
    #   - non-library functions have no designation
    #
    #       FUN_407BF0 <--- FUN_407B3C
    #           |              ^
    #           v              |
    #       FUN_408294         |
    #           |              |
    #           v              |
    #       FUN_40832F ---> FUN_4084D6
    #                 \     /
    #                  \   /
    #                   v v
    #              FUN_40868F
    #                    |
    #                    v
    #               FUN_408840
    #                    |
    #                    v
    #               FUN_40B06C

    assert is_only_called_from_library_functions(sample_038476, 0x40B06C) is False
