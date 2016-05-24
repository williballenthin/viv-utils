import os
import logging
import inspect

import funcy
import vivisect
import intervaltree


def getVwSampleMd5(vw):
    return vw.filemeta.values()[0]["md5sum"]

def getWorkspace(fp, reanalyze=False, verbose=False, should_save=True):
    '''
    For a file path return a workspace, it will create one if the extension
    is not .viv, otherwise it will load the existing one. Reanalyze will cause
    it to create and save a new one.
    '''
    vw = vivisect.VivWorkspace()
    vw.verbose = verbose
    vw.config.viv.parsers.pe.nx = True
    if fp.endswith('.viv'):
        vw.loadWorkspace(fp)
        if reanalyze:
            vw.analyze()
    else:
        if os.path.exists(fp + ".viv"):
            vw.loadWorkspace(fp + ".viv")
            if reanalyze:
                vw.analyze()
        else:
            vw.loadFromFile(fp)
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
                self.d("Failed to disassemble: %s: %s", hex(va), e.message)
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


def loadShellcode(baseaddr, buf):
    vw = vivisect.VivWorkspace()
    vw.setMeta('Architecture', 'i386')
    vw.setMeta('Platform', 'windows')
    vw.setMeta('Format','pe')
    vw._snapInAnalysisModules()

    if typ == "R":
        perm = envi.memory.MM_READ
    elif typ == "RW":
        perm = envi.memory.MM_READ_WRITE
    elif typ == "RE":
        perm = envi.memory.MM_READ_EXEC
    elif typ == "RWE" or typ == "IMAGE" or typ == "WINSOCK":
        perm = envi.memory.MM_RWX
    else:
        perm = envi.memory.MM_NONE
        
    vw.addMemoryMap(baseaddr,envi.memory.MM_RWX, 'raw', buf)
    vw.addSegment(baseaddr, len(buf), '%.8x-%s' % (baseaddr, "RWE"), 'blob' )
    return vw
