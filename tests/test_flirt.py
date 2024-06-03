import vivisect.const as v_const
from viv_utils.flirt import *

from fixtures import sample_038476


def test_invalid_function(sample_038476):
    # this is an address that is not a function
    assert is_only_called_from_library_functions(sample_038476, 0x400000) is False


def test_function_not_called(sample_038476):
    # this is a function that is not called by any other function
    assert is_only_called_from_library_functions(sample_038476, 0x408155) is False


def test_library_function(sample_038476):
    # this is an existing library function
    func_addr = 0x407660
    make_library_function(sample_038476, func_addr)
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False


def test_only_called_from_library_functions(sample_038476):
    # this is a function whose top level callers are *all* library functions
    func_addr = 0x40CAA3
    top_level_func_addr1 = 0x408155
    top_level_func_addr2 = 0x403520

    make_library_function(sample_038476, top_level_func_addr1)
    make_library_function(sample_038476, top_level_func_addr2)

    assert is_library_function(sample_038476, top_level_func_addr1) is True
    assert is_library_function(sample_038476, top_level_func_addr2) is True

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_called_from_mixed_functions(sample_038476):
    # this is a function where the top level callers are both library and non-library functions
    func_addr = 0x40CAA3
    top_level_func_addr = 0x408155  # parent caller of 0x40CAA3

    make_library_function(sample_038476, top_level_func_addr)

    assert is_library_function(sample_038476, func_addr) is False
    assert is_library_function(sample_038476, top_level_func_addr) is True

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_function_circular_call_graph(sample_038476):
    # this is a function whose call graph contains a cycle
    assert is_only_called_from_library_functions(sample_038476, 0x40B06C) is False
