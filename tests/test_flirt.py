import vivisect.const as v_const
from fixtures import sample_038476

from viv_utils.flirt import *


def test_invalid_function(sample_038476):
    """
    test an invalid function address
    """
    # this is an address that is not a function
    func_addr = 0x400000
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False


def test_function_not_called(sample_038476):
    """
    test a function that is not called by any another function
    """
    # this is a function that is not called by any other function
    func_addr = 0x408155
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False


def test_library_function(sample_038476):
    """
    test a library function
    """
    # this is an existing library function
    func_addr = 0x407660
    make_library_function(sample_038476, func_addr)
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False


def test_function_with_only_top_level_library_functions(sample_038476):
    """
    test a function whose top level callers are all library functions
    """
    # this is a function where all the top level references are library functions
    func_addr = 0x40CAA3
    top_level_func_addr1 = 0x408155
    top_level_func_addr2 = 0x403520

    make_library_function(sample_038476, top_level_func_addr1)
    make_library_function(sample_038476, top_level_func_addr2)

    assert is_library_function(sample_038476, top_level_func_addr1) is True
    assert is_library_function(sample_038476, top_level_func_addr2) is True

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_function_with_mixed_top_level_callers(sample_038476):
    """
    test a function whose top level callers are both library functions and non-library functions
    """
    # this is a function where all the top level references are library functions
    func_addr = 0x40CAA3
    top_level_func_addr1 = 0x408155
    top_level_func_addr2 = 0x403520

    make_library_function(sample_038476, top_level_func_addr1)

    assert is_library_function(sample_038476, top_level_func_addr1) is True
    assert is_library_function(sample_038476, top_level_func_addr2) is False

    assert is_only_called_from_library_functions(sample_038476, func_addr) is True


def test_function_circular_call_graph(sample_038476):
    """
    test a function with a circular function call graph
    """
    # this is a function whose call graph contains a cycle
    func_addr = 0x40B06C
    assert is_only_called_from_library_functions(sample_038476, func_addr) is False
