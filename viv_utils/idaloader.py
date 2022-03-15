#!/usr/bin/env python
"""
load the module currently open in IDA Pro into a vivisect workspace.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
website: https://gist.github.com/williballenthin/f88c5c95f3e41157de3806dfbeef4bd4
"""
import logging
import functools

import vivisect
import vivisect.const

logger = logging.getLogger(__name__)

try:
    import idc
    import idaapi
    import ida_ida
    import ida_nalt
    import idautils
except ImportError:
    logger.debug("failed to import IDA Pro modules")


def requires_ida(f):
    """
    declare that the wrapped function requires the IDA Pro scripting API.
    calling the function will raise `RuntimeError` if the API cannot be imported.
    """

    @functools.wraps(f)
    def inner(*args, **kwargs):
        if not ("idc" in locals() or "idc" in globals()):
            raise RuntimeError("IDA Pro not present")
        return f(*args, **kwargs)

    return f


@requires_ida
def is_x86():
    """
    is the currently loaded module 32-bit x86?
    """
    inf = idaapi.get_inf_structure()
    return inf.procName == "metapc" and inf.is_32bit() and not inf.is_64bit()


@requires_ida
def is_x64():
    """
    is the currently loaded module 64-bit x86?
    """
    inf = idaapi.get_inf_structure()
    return inf.procName == "metapc" and inf.is_32bit() and inf.is_64bit()


@requires_ida
def is_exe():
    """
    is the currently loaded module a PE file?
    you can *probably* assume its for windows, if so.
    """
    return "Portable executable" in idaapi.get_file_type_name()


@requires_ida
def get_data(start, size):
    """
    read the given amount of data from the given start address.
    better than `idc.GetManyBytes` as it fills in missing bytes with NULLs.

    Args:
      start (int): start address.
      size (int): number of bytes to read.

    Returns:
      bytes: `size` bytes, filled with NULL when byte not available from database.
    """
    # best case, works pretty often.
    buf = idc.get_bytes(start, size)
    if buf:
        return buf

    # but may fail, when there's no byte defined.
    buf = []
    for ea in range(start, start + size):
        b = idc.get_bytes(ea, 1)
        if b:
            buf.append(b)
        else:
            buf.append(b"\x00")
    return b"".join(buf)


PAGE_SIZE = 0x1000


@requires_ida
def get_segment_data(segstart):
    """
    read the contents of the segment containing the given address.

    Args:
      segstart (int): start address of a segment.

    Returns:
      bytes: the bytes of the segment, filled with NULL when byte not available from database.
    """
    bufs = []

    segend = idc.get_segm_end(segstart)
    segsize = segend - segstart
    pagecount = segsize // PAGE_SIZE
    remainder = segsize - (pagecount * PAGE_SIZE)

    # read in page-sized chunks, since these should ususally be accessible together.
    for i in range(pagecount):
        bufs.append(get_data(segstart + i * PAGE_SIZE, PAGE_SIZE))

    # in a real PE, these *should* be page- or sector-aligned, but its not guaranteed, esp in IDA.
    if remainder != 0:
        bufs.append(get_data(segstart + pagecount * PAGE_SIZE, remainder))

    return b"".join(bufs)


@requires_ida
def get_exports():
    """
    enumerate the exports of the currently loaded module.

    Yields:
      Tuple[int, int, str]:
        - address of exported function
        - export ordinal
        - name of exported function
    """
    for index, ordinal, ea, name in idautils.Entries():
        yield ea, ordinal, name


@requires_ida
def get_imports():
    """
    enumerate the imports of the currently loaded module.

    Yields:
      Tuple[int, str, str, int]:
        - address of import table pointer
        - name of imported library
        - name of imported function
        - ordinal of import
    """
    for i in range(idaapi.get_import_module_qty()):
        dllname = idaapi.get_import_module_name(i)
        if not dllname:
            continue

        entries = []

        def cb(ea, name, ordinal):
            entries.append((ea, name, ordinal))
            return True  # continue enumeration

        idaapi.enum_import_names(i, cb)

        for ea, name, ordinal in entries:
            yield ea, dllname, name, ordinal


@requires_ida
def get_import_thunk(import_addr):
    """
    find import thunk for the given import pointer.
    this is a function that simply jumps to the external implementation of the routine.

    Args:
      import_addr (int): address of import table pointer.

    Returns:
      int: address of function thunk.

    Raises:
      ValueError: when the thunk does not exist.
    """
    for xref in idautils.XrefsTo(import_addr):
        if xref.type != 3:  # XrefTypeName(3) == 'Data_Read'
            continue

        if idc.print_insn_mnem(xref.frm) != "jmp":
            continue

        return xref.frm

    raise ValueError("thunk does not exist")


@requires_ida
def get_functions():
    """
    enumerate the functions in the currently loaded module.

    Yields:
      int: address of the function.
    """
    startea = ida_ida.inf_get_min_ea()
    for fva in idautils.Functions(idc.get_segm_start(startea), idc.get_segm_end(startea)):
        yield fva


@requires_ida
def loadWorkspaceFromIdb():
    """
    from IDA Pro, load the currently loaded module into a vivisect workspace.
    currently only supports windows PE files.

    Returns:
      vivisect.Workspace: the loaded and analyzed vivisect workspace.
    """
    vw = vivisect.VivWorkspace()

    if is_x86():
        vw.setMeta("Architecture", "i386")
    elif is_x64():
        vw.setMeta("Architecture", "amd64")
    else:
        raise NotImplementedError("unsupported architecture")

    if not is_exe():
        raise NotImplementedError("unsupported file format")

    vw.setMeta("Platform", "windows")
    vw.setMeta("Format", "pe")
    vw._snapInAnalysisModules()

    filename = vw.addFile(ida_nalt.get_root_filename(), idaapi.get_imagebase(), idautils.GetInputFileMD5())

    for segstart in idautils.Segments():
        segname = idc.get_segm_name(segstart)
        segbuf = get_segment_data(segstart)

        if segbuf is None:
            raise RuntimeError("failed to read segment data")

        logger.debug("mapping section %s with %x bytes", segname, len(segbuf))
        vw.addMemoryMap(segstart, idautils.ida_segment.get_segm_by_name(segname).perm, filename, segbuf)
        vw.addSegment(segstart, len(segbuf), segname, filename)

    for ea, ordinal, name in get_exports():
        logger.debug("marking export %s at %x", name, ea)
        vw.addEntryPoint(ea)
        vw.addExport(ea, vivisect.const.EXP_FUNCTION, name, filename)

    for ea, dllname, name, ordinal in get_imports():
        logger.debug("marking import %s!%s at %x", dllname, name, ea)
        vw.makeImport(ea, dllname, name)

    logger.debug("running vivisect auto-analysis")
    vw.analyze()

    for fva in get_functions():
        logger.debug("marking function %s at %x", idc.get_func_name(fva), fva)
        vw.makeFunction(fva)
        vw.makeName(fva, idc.get_func_name(fva))

    # can only set thunk-ness after a function is defined.
    for ea, dllname, name, ordinal in get_imports():
        try:
            thunk = get_import_thunk(ea)
        except ValueError:
            pass
        else:
            logger.debug("found thunk for %s.%s at %x", dllname, name, thunk)
            vw.makeFunction(thunk)
            vw.makeFunctionThunk(thunk, "%s.%s" % (dllname, name))

    return vw
