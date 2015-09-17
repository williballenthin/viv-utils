import os
import logging
import inspect

import funcy
import vivisect
import intervaltree


def getWorkspace(fp, reanalyze=False, verbose=False):
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
            vw.saveWorkspace()
    else:
        if os.path.exists(fp + ".viv"):
            vw.loadWorkspace(fp + ".viv")
            if reanalyze:
                vw.analyze()
                vw.saveWorkspace()
        else:
            vw.loadFromFile(fp)
            vw.analyze()
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


class Function(LoggingObject):
    def __init__(self, vw, va):
        super(Function, self).__init__()
        self._vw = vw
        self.va = va

    @funcy.cached_property
    def basic_blocks(self):
        bb = map(lambda b: BasicBlock(self._vw, *b), self._vw.getFunctionBlocks(self.va))
        return sorted(bb, key=lambda b: b.va)

    @funcy.cached_property
    def id(self):
        return self._vw.filemeta.values()[0]["md5sum"] + ":" + hex(self.va)

    def __repr__(self):
        return "Function(va: {:s})".format(hex(self.va))


class BasicBlock(LoggingObject):
    def __init__(self, vw, va, size, fva):
        super(BasicBlock, self).__init__()
        self._vw = vw
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
            o = self._vw.parseOpcode(va)
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
        self._vw = vw
        self._index = intervaltree.IntervalTree()
        self._do_index()

    def _do_index(self):
        for funcva in self._vw.getFunctions():
            f = Function(self._vw, funcva)
            for bb in f.basic_blocks:
                self._index[bb.va:bb.va + bb.size] = funcva

    def __getitem__(self, key):
        return one(self._index[key]).data

