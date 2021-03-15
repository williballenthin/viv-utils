import os
import struct
import logging
import inspect
import hashlib
import tempfile
import pkg_resources
import sys

import envi
import funcy
import vivisect
import vivisect.const
import intervaltree

from viv_utils.idaloader import loadWorkspaceFromIdb


logger = logging.getLogger(__name__)


class IncompatibleVivVersion(ValueError):
    pass

def getVwSampleMd5(vw):
    return vw.filemeta.values()[0]["md5sum"]


# while building and testing capa,
# we found that upstream changes to vivisect did not play well with existing serialized vivisect analysis results.
# this manifested as confusing or incorrect .viv file contents - and our tests would suddenly fail.
# so,
# we embed the installed vivisect library version in vivisect workspaces created by viv-utils.
# when we load a .viv, then we assert that the versions match.
# if they don't, emit a warning.
# ideally, we'd bail, but the vivisect distribution situation is already a mess, so let's not further touch that.
# to minimize unexpected dependencies this check is ignored if a package does not embed the vivisect version

def getVivisectLibraryVersion():
    # ref: https://stackoverflow.com/questions/710609/checking-a-python-module-version-at-runtime
    try:
        return pkg_resources.get_distribution("vivisect").version
    except pkg_resources.DistributionNotFound:
        logger.debug("package does not include vivisect distribution")
    return 'N/A'


def setVwVivisectLibraryVersion(vw):
    vw.setMeta("version", getVivisectLibraryVersion())


def getVwVivisectLibraryVersion(vw):
    return vw.getMeta("version")


def assertVwMatchesVivisectLibrary(vw):
    wanted = getVivisectLibraryVersion()
    found = getVwVivisectLibraryVersion(vw)
    if wanted != found:
        logger.warning("vivisect version mismatch! wanted: %s, found: %s", wanted, found)
    else:
        logger.debug("vivisect version match: %s", wanted)


def loadWorkspaceFromViv(vw, viv_file):
    if sys.version_info >= (3, 0):
        try:
            vw.loadWorkspace(viv_file)
        except UnicodeDecodeError as e:
            raise IncompatibleVivVersion("'%s' is an invalid .viv file. It may have been generated with Python 2 (incompatible with Python 3)." % viv_file)
    else:
        vw.loadWorkspace(viv_file)


def getWorkspace(fp, analyze=True, reanalyze=False, verbose=False, should_save=True):
    '''
    For a file path return a workspace, it will create one if the extension
    is not .viv, otherwise it will load the existing one. Reanalyze will cause
    it to create and save a new one.
    '''
    vw = vivisect.VivWorkspace()
    vw.verbose = verbose
    # this is pretty insane, but simply prop assignment doesn't work.
    vw.config.getSubConfig('viv').getSubConfig('parsers').getSubConfig('pe')['loadresources'] = True
    vw.config.getSubConfig('viv').getSubConfig('parsers').getSubConfig('pe')['nx'] = True
    if fp.endswith('.viv'):
        loadWorkspaceFromViv(vw, fp)
        assertVwMatchesVivisectLibrary(vw)
        if reanalyze:
            setVwVivisectLibraryVersion(vw)
            vw.analyze()
    else:
        viv_file = fp + ".viv"
        if os.path.exists(viv_file):
            loadWorkspaceFromViv(vw, viv_file)
            assertVwMatchesVivisectLibrary(vw)
            if reanalyze:
                setVwVivisectLibraryVersion(vw)
                vw.analyze()
        else:
            vw.loadFromFile(fp)
            if analyze:
                setVwVivisectLibraryVersion(vw)
                vw.analyze()

    if should_save:
        vw.saveWorkspace()

    return vw


class LoggingObject(object):
    def __init__(self):
        self._logger = logging.getLogger("{:s}.{:s}".format(
            self.__module__, self.__class__.__name__))

    def _getCallerFunction(self):
        FUNCTION_NAME_INDEX = 3
        return inspect.stack()[3][FUNCTION_NAME_INDEX]

    def _formatFormatString(self, args):
        return [self._getCallerFunction() + ": " + args[0]] + [a for a in args[1:]]

    def d(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.DEBUG):
            self._logger.debug(*self._formatFormatString(args), **kwargs)

    def i(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.INFO):
            self._logger.info(*self._formatFormatString(args), **kwargs)

    def w(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.WARN):
            self._logger.warn(*self._formatFormatString(args), **kwargs)

    def e(self, *args, **kwargs):
        if self._logger.isEnabledFor(logging.ERROR):
            self._logger.error(*self._formatFormatString(args), **kwargs)


def set_function_name(vw, va, new_name):
    # vivgui seems to override function_name with symbol names, but this is correct
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(va)
    vw.setFunctionApi(va, (ret_type, ret_name, call_conv, new_name, args))


def get_function_name(vw, va):
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(va)
    return func_name


class Function(LoggingObject):
    def __init__(self, vw, va):
        super(Function, self).__init__()
        self.vw = vw
        self.va = va

    @funcy.cached_property
    def basic_blocks(self):
        bb = map(lambda b: BasicBlock(self.vw, *b), self.vw.getFunctionBlocks(self.va))
        return sorted(bb, key=lambda b: b.va)

    @funcy.cached_property
    def id(self):
        return self.vw.filemeta.values()[0]["md5sum"] + ":" + hex(self.va)

    def __repr__(self):
        return "Function(va: {:s})".format(hex(self.va))

    @property
    def name(self):
        return get_function_name(self.vw, self.va)

    @name.setter
    def name(self, new_name):
        return set_function_name(self.vw, self.va, new_name)


class BasicBlock(LoggingObject):
    def __init__(self, vw, va, size, fva):
        super(BasicBlock, self).__init__()
        self.vw = vw
        self.va = va
        self.size = size
        self.fva = fva

    @funcy.cached_property
    def instructions(self):
        """
        from envi/__init__.py:class Opcode
        391         opcode   - An architecture specific numerical value for the opcode
        392         mnem     - A humon readable mnemonic for the opcode
        393         prefixes - a bitmask of architecture specific instruction prefixes
        394         size     - The size of the opcode in bytes
        395         operands - A list of Operand objects for this opcode
        396         iflags   - A list of Envi (architecture independant) instruction flags (see IF_FOO)
        397         va       - The virtual address the instruction lives at (used for PC relative im mediates etc...)
        """
        ret = []
        va = self.va
        while va < self.va + self.size:
            try:
                o = self.vw.parseOpcode(va)
            except Exception as e:
                self.d("Failed to disassemble: %s: %s", hex(va), e)
                break
            ret.append(o)
            va += len(o)
        return ret

    def __repr__(self):
        return "BasicBlock(va: {:s}, size: {:s}, fva: {:s})".format(
                hex(self.va), hex(self.size), hex(self.fva))


def one(s):
    for i in s:
        return i


class InstructionFunctionIndex(LoggingObject):
    """ Index from VA to containing function VA """
    def __init__(self, vw):
        super(InstructionFunctionIndex, self).__init__()
        self.vw = vw
        self._index = intervaltree.IntervalTree()
        self._do_index()

    def _do_index(self):
        for funcva in self.vw.getFunctions():
            f = Function(self.vw, funcva)
            for bb in f.basic_blocks:
                if bb.size == 0:
                    continue
                self._index[bb.va:bb.va + bb.size] = funcva

    def __getitem__(self, key):
        v = one(self._index[key])
        if v is None:
            raise KeyError()
        return v.data


def getFunctionName(vw, fva):
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(fva)
    return func_name


def getFunctionCallingConvention(vw, fva):
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(fva)
    return call_conv


def getFunctionArgs(vw, fva):
    return vw.getFunctionArgs(fva)


def getShellcodeWorkspace(buf, arch="i386", base=0, entry_point=0, analyze=True, should_save=False, save_path=None):
    """
    Load shellcode into memory object and generate vivisect workspace.
    Thanks to Tom for most of the code.
    :param buf: shellcode buffer bytes
    :param arch: architecture string
    :param base: base address where shellcode will be loaded
    :param entry_point: entry point of shellcode, relative to base
    :param should_save: save workspace to disk
    :param save_path: path to save workspace to
    :return: vivisect workspace
    """
    md5 = hashlib.md5()
    md5.update(buf)

    vw = vivisect.VivWorkspace()
    vw.addFile('shellcode', base, md5.hexdigest())
    vw.setMeta('Architecture', arch)
    vw.setMeta('Platform', 'windows')
    # blob gives weaker results in some cases
    # so we will update this below
    vw.setMeta('Format', 'pe')
    vw._snapInAnalysisModules()

    vw.addMemoryMap(base, envi.memory.MM_RWX, 'shellcode', buf)
    vw.addSegment(base, len(buf), 'shellcode_0x%x' % base, 'blob')

    vw.addEntryPoint(base + entry_point)  # defaults to start of shellcode

    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()

    vw.setMeta('Format', 'blob')

    if should_save:
        if save_path is None:
            raise Exception("Failed to save workspace, destination save path cannot be empty")
        vw.setMeta("StorageName", "%s.viv" % save_path)
        vw.saveWorkspace()

    return vw


def saveWorkspaceToBytes(vw):
    """
    serialize a vivisect workspace to a Python string/bytes.

    note, this creates and deletes a temporary file on the
      local filesystem.
    """
    orig_storage = vw.getMeta("StorageName")
    try:
        _, temp_path = tempfile.mkstemp(suffix="viv")
        try:
            vw.setMeta("StorageName", temp_path)
            vw.saveWorkspace()
            with open(temp_path, "rb") as f:
                # note: here's the exit point.
                return f.read()
        finally:
            try:
                os.rm(temp_path)
            except Exception:
                pass
    finally:
        vw.setMeta("StorageName", orig_storage)


def loadWorkspaceFromBytes(vw, buf):
    """
    deserialize a vivisect workspace from a Python string/bytes.
    """
    _, temp_path = tempfile.mkstemp(suffix="viv")
    try:
        with open(temp_path, "wb") as f:
            f.write(buf)
        vw.loadWorkspace(temp_path)
        assertVwMatchesVivisectLibrary(vw)
        # note: here's the exit point.
        return vw
    finally:
        try:
            os.rm(temp_path)
        except Exception:
            pass


def getWorkspaceFromBytes(buf, analyze=True):
    """
    create a new vivisect workspace and load it from a
      Python string/bytes.
    """
    vw = vivisect.VivWorkspace()
    vw.verbose = True
    vw.config.viv.parsers.pe.nx = True
    loadWorkspaceFromBytes(vw, buf)
    assertVwMatchesVivisectLibrary(vw)
    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()
    return vw


def getWorkspaceFromFile(filepath, analyze=True):
    """
    deserialize a file into a new vivisect workspace.
    """
    vw = vivisect.VivWorkspace()
    vw.verbose = True
    vw.config.viv.parsers.pe.nx = True
    vw.loadFromFile(filepath)
    setVwVivisectLibraryVersion(vw)
    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()
    return vw


def get_prev_opcode(vw, va):
    prev_item = vw.getPrevLocation(va)
    if prev_item is None:
        raise RuntimeError('failed to find prev instruction for va: %x', va)

    lva, lsize, ltype, linfo = prev_item
    if ltype != vivisect.const.LOC_OP:
        raise RuntimeError('failed to find prev instruction for va: %x', va)

    try:
        op = vw.parseOpcode(lva)
    except Exception:
        logger.warning('failed to parse prev instruction for va: %x', va)
        raise

    return op


def get_all_xrefs_from(vw, va):
    '''
    get all xrefs, including fallthrough instructions, from this address.

    vivisect doesn't consider fallthroughs as xrefs.
    see: https://github.com/fireeye/flare-ida/blob/7207a46c18a81ad801720ce0595a151b777ef5d8/python/flare/jayutils.py#L311
    '''
    op = vw.parseOpcode(va)
    for tova, bflags in op.getBranches():
        if bflags & envi.BR_PROC:
            continue
        yield (va, tova, vivisect.const.REF_CODE, bflags)


def get_all_xrefs_to(vw, va):
    '''
    get all xrefs, including fallthrough instructions, to this address.

    vivisect doesn't consider fallthroughs as xrefs.
    see: https://github.com/fireeye/flare-ida/blob/7207a46c18a81ad801720ce0595a151b777ef5d8/python/flare/jayutils.py#L311
    '''
    for xref in vw.getXrefsTo(va):
        yield xref

    op = get_prev_opcode(vw, va)

    for tova, bflags in op.getBranches():
        if tova == va:
            yield (op.va, va, vivisect.const.REF_CODE, bflags)


def empty(s):
    for c in s:
        return False
    return True


class CFG(object):
    def __init__(self, func):
        self.vw = func.vw
        self.func = func
        self.bb_by_start = {bb.va: bb for bb in self.func.basic_blocks}
        self.bb_by_end = {get_prev_opcode(self.vw, bb.va + bb.size).va: bb
                          for bb in self.func.basic_blocks}
        self._succ_cache = {}
        self._pred_cache = {}

    def get_successor_basic_blocks(self, bb):
        if bb.va in self._succ_cache:
            for nbb in self._succ_cache[bb.va]:
                yield nbb
            return

        successors = []
        next_va = bb.va + bb.size
        op = get_prev_opcode(self.vw, next_va)
        for xref in get_all_xrefs_from(self.vw, op.va):
            try:
                succ = self.bb_by_start[xref[vivisect.const.XR_TO]]
                yield succ
                successors.append(succ)
            except KeyError:
                # if we have a jump to the import table,
                # the target of the jump is not a basic block in the function.
                continue

        self._succ_cache[bb.va] = successors

    def get_predecessor_basic_blocks(self, bb):
        if bb.va in self._pred_cache:
            for nbb in self._pred_cache[bb.va]:
                yield nbb
            return

        predecessors = []
        for xref in get_all_xrefs_to(self.vw, bb.va):
            try:
                pred = self.bb_by_end[xref[vivisect.const.XR_FROM]]
                yield pred
                predecessors.append(pred)
            except KeyError:
                # if we have a jump to the import table,
                # the target of the jump is not a basic block in the function.
                continue

        self._pred_cache[bb.va] = predecessors

    def get_root_basic_block(self):
        return self.bb_by_start[self.func.va]

    def get_leaf_basic_blocks(self):
        for bb in self.func.basic_blocks:
            if empty(self.get_successor_basic_blocks(bb)):
                yield bb


def get_strings(vw):
    '''
    enumerate the strings in the given vivisect workspace.

    Args:
      vw (vivisect.Workspace): the workspace.

    Yields:
      Tuple[int, str]: the address, string pair.
    '''
    for loc in vw.getLocations(ltype=vivisect.const.LOC_STRING):
        va = loc[vivisect.const.L_VA]
        size = loc[vivisect.const.L_SIZE]
        yield va, vw.readMemory(va, size).decode('ascii')

    for loc in vw.getLocations(ltype=vivisect.const.LOC_UNI):
        va = loc[vivisect.const.L_VA]
        size = loc[vivisect.const.L_SIZE]
        try:
            yield va, vw.readMemory(va, size).decode('utf-16le')
        except UnicodeDecodeError:
            continue


def is_valid_address(vw, va):
    '''
    test if the given address is valid in the given vivisect workspace.

    Args:
      vw (vivisect.Workspace): the workspace.
      va (int): a possible memory address.

    Returns:
      bool: True if the given address is valid in the given workspace.
    '''
    return vw.probeMemory(va, 1, envi.memory.MM_READ)


def get_function_constants(vw, fva):
    '''
    enumerate the immediate constants referenced by instructions in the given function.
    does not yield valid addresses in the given workspace.

    Args:
      vw (vivisect.Workspace): the workspace.
      fva (int): the address of a function in the workspace.

    Yields:
      int: immediate constant referenced by an instruction.
    '''
    f = Function(vw, fva)
    for bb in f.basic_blocks:
        for i in bb.instructions:
            for o in i.getOperands():
                if not o.isImmed():
                    continue

                c = o.getOperValue(i)
                if is_valid_address(vw, c):
                    continue

                yield c


def get_section_data(pe, section):
    '''
    fetch the raw data of the given section.

    Args:
      pe (PE.PE): the parsed PE file.
      section (vstruct.VStruct): pe.IMAGE_SECTION_HEADER instance.

    Returns:
      bytes: the raw bytes of the section.
    '''
    return pe.readAtOffset(section.PointerToRawData, section.SizeOfRawData)


class Debugger(object):
    REGISTERS = {
        "eax",
        "ebx",
        "ecx",
        "edx",
        "esi",
        "edi",
        "esp",
        "ebp",
        "eip",
    }

    def __init__(self, v):
        super(Debugger, self).__init__()
        self.v = v

    def __getattr__(self, k):
        '''
        support reg access shortcut, like::
            print(hex(dbg.pc))
            print(hex(dbg.rax))
        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        '''
        if k == 'v':
            return super(object, self).__getattr__(k)
        elif k == 'pc' or k == 'program_counter':
            return self.v.getTrace().getRegisterByName("eip")
        elif k == 'stack_pointer':
            return self.v.getTrace().getRegisterByName("esp")
        elif k == 'base_pointer':
            return self.v.getTrace().getRegisterByName("ebp")
        elif k in self.REGISTERS:
            return self.v.getTrace().getRegisterByName(k)
        else:
            return self.v.__getattribute__(k)

    def __setattr__(self, k, v):
        '''
        set reg shortcut, like::
            dbg.pc  = 0x401000
            dbg.rax = 0xAABBCCDD
        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        '''
        if k == 'v':
            object.__setattr__(self, k, v)
        elif k == 'pc' or k == 'program_counter':
            return self.v.getTrace().setRegisterByName("eip", v)
        elif k == 'stack_pointer':
            return self.v.getTrace().setRegisterByName("esp", v)
        elif k == 'base_pointer':
            return self.v.getTrace().setRegisterByName("ebp", v)
        elif k in self.REGISTERS:
            return self.v.getTrace().setRegisterByName(k, v)
        else:
            return self.v.__setattribute__(k, v)

    def write_memory(self, va, buf):
        self.v.memobj.writeMemory(va, buf)

    def read_memory(self, va, size):
        return self.v.trace.readMemory(va, size)

    def read_dword(self, va):
        return struct.unpack("<I", self.read_memory(va, 4))[0]

    def write_dword(self, va, v):
        self.write_memory(va, struct.pack("<I", v))

    def read_ascii(self, va):
        buf = self.read_memory(va, 1024)
        return buf.partition(b'\x00')[0].decode('ascii')

    def pop(self):
        v = self.read_dword(self.esp)
        self.esp = self.esp + 4
        return v

    def push(self, v):
        self.esp = self.esp - 4
        self.write_dword(self.esp, v)
