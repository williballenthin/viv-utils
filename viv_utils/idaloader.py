#!/usr/bin/env python
'''
load the module currently open in IDA Pro into a vivisect workspace.

author: Willi Ballenthin
email: willi.ballenthin@gmail.com
website: https://gist.github.com/williballenthin/f88c5c95f3e41157de3806dfbeef4bd4
'''
import logging
import functools

import envi
import vivisect
import vivisect.const

logger = logging.getLogger(__name__)

try:
    import idc
    import idaapi
    import idautils
except ImportError:
    logger.info('failed to import IDA Pro modules')


def requires_ida(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        if not ('idc' in locals() or 'idc' in globals()):
            raise RuntimeError('IDA Pro not present')
        return f(*args, **kwargs)
    return f


@requires_ida
def is_x86():
    inf = idaapi.get_inf_structure()
    return inf.procName == 'metapc' and inf.is_32bit()


@requires_ida
def is_x64():
    inf = idaapi.get_inf_structure()
    return inf.procName == 'metapc' and inf.is_64bit()


@requires_ida
def is_exe():
    return 'Portable executable' in idaapi.get_file_type_name()


@requires_ida
def get_page(pagestart):
    buf = idc.GetManyBytes(pagestart, 0x1000)
    if buf:
        return buf

    buf = []
    for ea in range(pagestart, pagestart+0x1000):
        b = idc.GetManyBytes(ea, 1)
        if b:
            buf.append(b)
        else:
            buf.append(b'\x00')
    return b''.join(buf)


@requires_ida
def get_segment_data(segstart):
    bufs = []

    pagestart = segstart
    segend = idc.SegEnd(segstart)
    while pagestart < segend:
        bufs.append(get_page(pagestart))
        pagestart += 0x1000

    return b''.join(bufs)


@requires_ida
def get_exports():
    for index, ordinal, ea, name in idautils.Entries():
        yield ea, ordinal, name


@requires_ida
def get_imports():
    for i in range(idaapi.get_import_module_qty()):
        dllname = idaapi.get_import_module_name(i)
        if not dllname:
            continue

        entries = []
        def cb(ea, name, ordinal):
            entries.append((ea, name, ordinal))

        idaapi.enum_import_names(i, cb)

        for ea, name, ordinal in entries:
            yield ea, dllname, name, ordinal


@requires_ida
def get_functions():
    startea = idc.BeginEA()
    for fva in idautils.Functions(idc.SegStart(startea), idc.SegEnd(startea)):
        yield fva


@requires_ida
def loadVivFromIdb():
    vw = vivisect.VivWorkspace()

    if is_x86():
        vw.setMeta('Architecture', 'i386')
    elif is_x64():
        vw.setMeta('Architecture', 'amd64')
    else:
        raise NotImplementedError('unsupported architecture')

    if not is_exe():
        raise NotImplementedError('unsupported file format')

    vw.setMeta('Platform', 'windows')
    vw.setMeta('Format', 'pe')
    vw._snapInAnalysisModules()

    filename = idc.GetInputFile()

    for segstart in idautils.Segments():
        segname = idc.SegName(segstart)
        segbuf = get_segment_data(segstart)

        if segbuf is None:
            raise RuntimeError('failed to read segment data')

        logger.debug('mapping section %s with %x bytes', segname, len(segbuf))
        vw.addMemoryMap(segstart, envi.memory.MM_RWX, segname, segbuf)
        vw.addSegment(segstart, len(segbuf), segname, filename)

    for ea, ordinal, name in get_exports():
        logger.debug('marking export %s at %x', name, ea)
        vw.addEntryPoint(ea)
        vw.addExport(ea, vivisect.const.EXP_FUNCTION, name, filename)

    for ea, dllname, name, ordinal in get_imports():
        logger.debug('marking import %s!%s at %x', dllname, name, ea)
        vw.makeImport(ea, dllname, name)

    logger.debug('running vivisect auto-analysis')
    vw.analyze()

    for fva in get_functions():
        logger.debug('marking function %s at %x', idc.GetFunctionName(fva), fva)
        vw.makeFunction(fva)
        vw.makeName(fva, idc.GetFunctionName(fva))

    return vw
