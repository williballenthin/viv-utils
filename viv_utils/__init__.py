import os
import sys
import struct
import hashlib
import logging
import tempfile
from typing import Any, Dict, List, Tuple, Iterator

import envi
import funcy
import vivisect
import intervaltree
import pkg_resources
import vivisect.const

from viv_utils.types import *
from viv_utils.idaloader import loadWorkspaceFromIdb

logger = logging.getLogger(__name__)


SHELLCODE_BASE = 0x690000


class IncompatibleVivVersion(ValueError):
    pass


def getVwFirstMeta(vw: Workspace) -> Dict[str, Any]:
    # return the first set of metadata from the vw.
    # this is for the first loaded file.
    # if other files have been added to the vw,
    # then this may not do what you want.
    return list(vw.filemeta.values())[0]


def getVwSampleMd5(vw: Workspace) -> str:
    return getVwFirstMeta(vw)["md5sum"]


# while building and testing capa,
# we found that upstream changes to vivisect did not play well with existing serialized vivisect analysis results.
# this manifested as confusing or incorrect .viv file contents - and our tests would suddenly fail.
# so,
# we embed the installed vivisect library version in vivisect workspaces created by viv-utils.
# when we load a .viv, then we assert that the versions match.
# if they don't, emit a warning.
# ideally, we'd bail, but the vivisect distribution situation is already a mess, so let's not further touch that.
# to minimize unexpected dependencies this check is ignored if a package does not embed the vivisect version


def getVivisectLibraryVersion() -> str:
    # ref: https://stackoverflow.com/questions/710609/checking-a-python-module-version-at-runtime
    try:
        return pkg_resources.get_distribution("vivisect").version
    except pkg_resources.DistributionNotFound:
        logger.debug("package does not include vivisect distribution")
    return "N/A"


def setVwVivisectLibraryVersion(vw: Workspace):
    vw.setMeta("version", getVivisectLibraryVersion())


def getVwVivisectLibraryVersion(vw) -> str:
    return vw.getMeta("version")


def assertVwMatchesVivisectLibrary(vw):
    wanted = getVivisectLibraryVersion()
    found = getVwVivisectLibraryVersion(vw)
    if wanted != found:
        logger.warning("vivisect version mismatch! wanted: %s, found: %s", wanted, found)
    else:
        logger.debug("vivisect version match: %s", wanted)


def loadWorkspaceFromViv(vw: Workspace, viv_file):
    if sys.version_info >= (3, 0):
        try:
            vw.loadWorkspace(viv_file)
        except UnicodeDecodeError as e:
            raise IncompatibleVivVersion(
                "'%s' is an invalid .viv file. It may have been generated with Python 2 (incompatible with Python 3)."
                % viv_file
            )
    else:
        vw.loadWorkspace(viv_file)


def getWorkspace(fp: str, analyze=True, reanalyze=False, verbose=False, should_save=True) -> Workspace:
    """
    For a file path return a workspace, it will create one if the extension
    is not .viv, otherwise it will load the existing one. Reanalyze will cause
    it to create and save a new one.
    """
    vw = Workspace()
    vw.verbose = verbose
    # this is pretty insane, but simply prop assignment doesn't work.
    vw.config.getSubConfig("viv").getSubConfig("parsers").getSubConfig("pe")["loadresources"] = True
    vw.config.getSubConfig("viv").getSubConfig("parsers").getSubConfig("pe")["nx"] = True
    if fp.endswith(".viv"):
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
            setVwVivisectLibraryVersion(vw)
            if analyze:
                vw.analyze()

    if should_save:
        vw.saveWorkspace()

    return vw


def set_function_name(vw, va: int, new_name: str):
    # vivgui seems to override function_name with symbol names, but this is correct
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(va)
    vw.setFunctionApi(va, (ret_type, ret_name, call_conv, new_name, args))


def get_function_name(vw, va: int) -> str:
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(va)
    return func_name


class Function:
    def __init__(self, vw: Workspace, va: int):
        super(Function, self).__init__()
        self.vw = vw
        self.va = va

    @funcy.cached_property
    def basic_blocks(self) -> List["BasicBlock"]:
        bb = map(lambda b: BasicBlock(self.vw, *b), self.vw.getFunctionBlocks(self.va))
        return list(sorted(bb, key=lambda b: b.va))

    @funcy.cached_property
    def id(self):
        return getVwFirstMeta(self.vw)["md5sum"] + ":" + hex(self.va)

    def __repr__(self):
        return "Function(va: {:s})".format(hex(self.va))

    def __int__(self):
        return self.va

    @property
    def name(self):
        return get_function_name(self.vw, self.va)

    @name.setter
    def name(self, new_name):
        return set_function_name(self.vw, self.va, new_name)


class BasicBlock:
    def __init__(self, vw: Workspace, va: int, size: int, fva: int):
        super(BasicBlock, self).__init__()
        self.vw = vw
        self.va = va
        self.size = size
        self.fva = fva

    @funcy.cached_property
    def instructions(self) -> List[envi.Opcode]:
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
                logger.debug("failed to disassemble: %s: %s", hex(va), e)
                break
            ret.append(o)
            va += len(o)
        return ret

    def __repr__(self):
        return "BasicBlock(va: {:s}, size: {:s}, fva: {:s})".format(hex(self.va), hex(self.size), hex(self.fva))

    def __int__(self):
        return self.va

    def __len__(self):
        return self.size


def one(s):
    for i in s:
        return i


class InstructionFunctionIndex:
    """Index from VA to containing function VA"""

    def __init__(self, vw: Workspace):
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
                self._index[bb.va : bb.va + bb.size] = funcva

    def __getitem__(self, key):
        v = one(self._index[key])
        if v is None:
            raise KeyError()
        return v.data


def getFunctionName(vw: Workspace, fva: Address):
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(fva)
    return func_name


def getFunctionCallingConvention(vw: Workspace, fva: Address):
    ret_type, ret_name, call_conv, func_name, args = vw.getFunctionApi(fva)
    return call_conv


def getFunctionArgs(vw: Workspace, fva: Address):
    return vw.getFunctionArgs(fva)


def getShellcodeWorkspaceFromFile(
    filepath: str, arch: str, base: Address = SHELLCODE_BASE, entry_point: Address = 0, analyze=True, should_save=False
) -> Workspace:
    with open(filepath, "rb") as f:
        sample_bytes = f.read()

    vw = getShellcodeWorkspace(
        sample_bytes, arch, base=base, entry_point=entry_point, analyze=analyze, should_save=should_save
    )

    vw.setMeta("StorageName", "%s.viv" % filepath)

    return vw


def getShellcodeWorkspace(
    buf: bytes,
    arch: str,
    base: Address = SHELLCODE_BASE,
    entry_point: Address = 0,
    analyze=True,
    should_save=False,
    save_path=None,
) -> Workspace:
    """
    Load shellcode into memory object and generate vivisect workspace.
    Thanks to Tom for most of the code.

    Arguments:
      buf: shellcode buffer bytes
      arch: architecture string
      base: base address where shellcode will be loaded
      entry_point: entry point of shellcode, relative to base
      analyze: analyze workspace or otherwise leave it to caller
      should_save: save workspace to disk
      save_path: path to save workspace to

    Returns: vivisect workspace
    """
    md5 = hashlib.md5()
    md5.update(buf)

    vw = Workspace()
    vw.addFile("shellcode", base, md5.hexdigest())
    vw.setMeta("Architecture", arch)
    vw.setMeta("Platform", "windows")
    # blob gives weaker results in some cases
    # so we will update this below
    vw.setMeta("Format", "pe")
    vw._snapInAnalysisModules()

    vw.addMemoryMap(base, envi.memory.MM_RWX, "shellcode", buf)
    vw.addSegment(base, len(buf), "shellcode_0x%x" % base, "shellcode")

    vw.addEntryPoint(base + entry_point)  # defaults to start of shellcode

    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()

    vw.setMeta("Format", "blob")

    if should_save:
        if save_path is None:
            raise Exception("Failed to save workspace, destination save path cannot be empty")
        vw.setMeta("StorageName", "%s.viv" % save_path)
        vw.saveWorkspace()

    return vw


def saveWorkspaceToBytes(vw: Workspace) -> bytes:
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
                os.rmdir(temp_path)
            except Exception:
                pass
    finally:
        vw.setMeta("StorageName", orig_storage)


def loadWorkspaceFromBytes(vw: Workspace, buf: bytes):
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
            os.rmdir(temp_path)
        except Exception:
            pass


def getWorkspaceFromBytes(buf: bytes, analyze=True) -> Workspace:
    """
    create a new vivisect workspace and load it from a
      Python string/bytes.
    """
    vw = Workspace()
    vw.verbose = True
    vw.config.viv.parsers.pe.nx = True
    loadWorkspaceFromBytes(vw, buf)
    assertVwMatchesVivisectLibrary(vw)
    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()
    return vw


def getWorkspaceFromFile(filepath: str, analyze=True) -> Workspace:
    """
    deserialize a file into a new vivisect workspace.
    """
    vw = Workspace()
    vw.verbose = True
    vw.config.viv.parsers.pe.nx = True
    vw.loadFromFile(filepath)
    setVwVivisectLibraryVersion(vw)
    if analyze:
        setVwVivisectLibraryVersion(vw)
        vw.analyze()
    return vw


def get_prev_loc(vw: Workspace, va: Address):
    this_item = vw.getLocation(va)
    if this_item is None:
        # no location at the given address,
        # probe for a location directly before this one.
        prev_item = vw.getLocation(va - 1)
    else:
        this_va, _, _, _ = this_item
        prev_item = vw.getLocation(this_va - 1)

    if prev_item is None:
        raise ValueError("failed to find prev location for va: %x" % va)

    return prev_item


def get_prev_opcode(vw: Workspace, va: Address):
    lva, lsize, ltype, linfo = get_prev_loc(vw, va)
    if ltype != vivisect.const.LOC_OP:
        raise ValueError("failed to find prev instruction for va: %x" % va)

    try:
        op = vw.parseOpcode(lva)
    except Exception:
        raise ValueError("failed to parse prev instruction for va: %x" % va)

    return op


def get_all_xrefs_from(vw: Workspace, va: Address):
    """
    get all xrefs, including fallthrough instructions, from this address.

    vivisect doesn't consider fallthroughs as xrefs.
    see: https://github.com/fireeye/flare-ida/blob/7207a46c18a81ad801720ce0595a151b777ef5d8/python/flare/jayutils.py#L311
    """
    op = vw.parseOpcode(va)
    for tova, bflags in op.getBranches():
        if bflags & envi.BR_PROC:
            continue
        yield (va, tova, vivisect.const.REF_CODE, bflags)


def get_all_xrefs_to(vw: Workspace, va: Address):
    """
    get all xrefs, including fallthrough instructions, to this address.

    vivisect doesn't consider fallthroughs as xrefs.
    see: https://github.com/fireeye/flare-ida/blob/7207a46c18a81ad801720ce0595a151b777ef5d8/python/flare/jayutils.py#L311
    """
    for xref in vw.getXrefsTo(va):
        yield xref

    try:
        op = get_prev_opcode(vw, va)
    except ValueError:
        return

    for tova, bflags in op.getBranches():
        if tova == va:
            yield (op.va, va, vivisect.const.REF_CODE, bflags)


def empty(s) -> bool:
    for c in s:
        return False
    return True


class CFG(object):
    def __init__(self, func: Function):
        self.vw = func.vw
        self.func = func
        self.bb_by_start = {bb.va: bb for bb in self.func.basic_blocks}
        if self.func.va not in self.bb_by_start:
            # particularly when dealing with junk code,
            # the address that we think starts a function may not,
            # such as when the given address falls in the middle of a basic block.
            raise ValueError("function at 0x%x not recognized" % (self.func.va))

        self.bb_by_end = {}
        for bb in self.func.basic_blocks:
            try:
                lva, _, ltype, _ = get_prev_loc(self.vw, bb.va + bb.size)
                if ltype != vivisect.const.LOC_OP:
                    raise RuntimeError("failed to find prev instruction for va: %x" % (bb.va + bb.size))
                self.bb_by_end[lva] = bb
            except RuntimeError as e:
                # viv detects "function blocks" that we interpret as "basic blocks".
                # viv may have incorrect analysis, such that a block may not be made up of contiguous instructions.
                # if we can't find an instruction at the end of a basic block,
                # we're dealing with junk. don't index that BB.
                continue

        if len(self.bb_by_start) != len(self.bb_by_end):
            # there's probably junk code encountered
            logger.warning("cfg: incomplete control flow graph")

        self._succ_cache: Dict[Address, List[BasicBlock]] = {}
        self._pred_cache: Dict[Address, List[BasicBlock]] = {}

    def get_successor_basic_blocks(self, bb: BasicBlock) -> Iterator[BasicBlock]:
        if bb.va in self._succ_cache:
            for nbb in self._succ_cache[bb.va]:
                yield nbb
            return

        next_va = bb.va + bb.size
        try:
            op = get_prev_opcode(self.vw, next_va)
        except RuntimeError:
            # like above, if there's not an insn at the end of the BB,
            # we're dealing with junk, and there's not much point.
            self._succ_cache[bb.va] = []
            return

        successors = []
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

    def get_predecessor_basic_blocks(self, bb: BasicBlock) -> Iterator[BasicBlock]:
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
                continue

        self._pred_cache[bb.va] = predecessors

    def get_root_basic_blocks(self) -> Iterator[BasicBlock]:
        for bb in self.func.basic_blocks:
            if empty(self.get_predecessor_basic_blocks(bb)):
                yield bb

    def get_leaf_basic_blocks(self) -> Iterator[BasicBlock]:
        for bb in self.func.basic_blocks:
            if empty(self.get_successor_basic_blocks(bb)):
                yield bb


def get_strings(vw: Workspace) -> Iterator[Tuple[Address, str]]:
    """
    enumerate the strings in the given vivisect workspace.

    Args:
      vw (vivisect.Workspace): the workspace.

    Yields:
      Tuple[int, str]: the address, string pair.
    """
    for loc in vw.getLocations(ltype=vivisect.const.LOC_STRING):
        va = loc[vivisect.const.L_VA]
        size = loc[vivisect.const.L_SIZE]
        yield va, vw.readMemory(va, size).decode("ascii")

    for loc in vw.getLocations(ltype=vivisect.const.LOC_UNI):
        va = loc[vivisect.const.L_VA]
        size = loc[vivisect.const.L_SIZE]
        try:
            yield va, vw.readMemory(va, size).decode("utf-16le")
        except UnicodeDecodeError:
            continue


def is_valid_address(vw: Workspace, va: Address) -> bool:
    """
    test if the given address is valid in the given vivisect workspace.

    Args:
      vw (vivisect.Workspace): the workspace.
      va (int): a possible memory address.

    Returns:
      bool: True if the given address is valid in the given workspace.
    """
    return vw.probeMemory(va, 1, envi.memory.MM_READ)


def get_function_constants(vw: Workspace, fva: Address) -> Iterator[int]:
    """
    enumerate the immediate constants referenced by instructions in the given function.
    does not yield valid addresses in the given workspace.

    Args:
      vw (vivisect.Workspace): the workspace.
      fva (int): the address of a function in the workspace.

    Yields:
      int: immediate constant referenced by an instruction.
    """
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


def get_section_data(pe, section) -> bytes:
    """
    fetch the raw data of the given section.

    Args:
      pe (PE.PE): the parsed PE file.
      section (vstruct.VStruct): pe.IMAGE_SECTION_HEADER instance.

    Returns:
      bytes: the raw bytes of the section.
    """
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
        """
        support reg access shortcut, like::
            print(hex(dbg.pc))
            print(hex(dbg.rax))
        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        """
        if k == "v":
            return super(object, self).__getattr__(k)
        elif k == "pc" or k == "program_counter":
            return self.v.getTrace().getRegisterByName("eip")
        elif k == "stack_pointer":
            return self.v.getTrace().getRegisterByName("esp")
        elif k == "base_pointer":
            return self.v.getTrace().getRegisterByName("ebp")
        elif k in self.REGISTERS:
            return self.v.getTrace().getRegisterByName(k)
        else:
            return self.v.__getattribute__(k)

    def __setattr__(self, k, v):
        """
        set reg shortcut, like::
            dbg.pc  = 0x401000
            dbg.rax = 0xAABBCCDD
        register names are lowercase.
        `pc` is a shortcut for the platform program counter.
        """
        if k == "v":
            object.__setattr__(self, k, v)
        elif k == "pc" or k == "program_counter":
            return self.v.getTrace().setRegisterByName("eip", v)
        elif k == "stack_pointer":
            return self.v.getTrace().setRegisterByName("esp", v)
        elif k == "base_pointer":
            return self.v.getTrace().setRegisterByName("ebp", v)
        elif k in self.REGISTERS:
            return self.v.getTrace().setRegisterByName(k, v)
        else:
            return self.v.__setattribute__(k, v)

    def write_memory(self, va: Address, buf: bytes):
        self.v.memobj.writeMemory(va, buf)

    def read_memory(self, va: Address, size: int):
        return self.v.trace.readMemory(va, size)

    def read_dword(self, va: Address) -> int:
        return struct.unpack("<I", self.read_memory(va, 4))[0]

    def write_dword(self, va: Address, v: int):
        self.write_memory(va, struct.pack("<I", v))

    def read_ascii(self, va: Address) -> str:
        buf = self.read_memory(va, 1024)
        return buf.partition(b"\x00")[0].decode("ascii")

    def pop(self) -> int:
        v = self.read_dword(self.esp)  # type: ignore
        self.esp = self.esp + 4  # type: ignore
        return v

    def push(self, v: int):
        self.esp = self.esp - 4
        self.write_dword(self.esp, v)


def readMemoryCurrentSection(vw: Workspace, va: Address, size: int) -> bytes:
    """
    only read memory up to current section end
    """
    mva, msize, mperms, mfname = vw.getMemoryMap(va)
    offset = va - mva
    maxreadlen = msize - offset
    if size > maxreadlen:
        size = maxreadlen
    return vw.readMemory(va, size)
