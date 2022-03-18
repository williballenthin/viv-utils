import logging
from typing import List, Tuple, Callable

import envi as v_envi
import vivisect
import envi.memory as v_mem
import visgraph.pathcore as vg_path
from typing_extensions import TypeAlias
from envi.archs.i386.disasm import PREFIX_REP

logger = logging.getLogger(__name__)


class StopEmulation(Exception):
    pass


class BreakpointHit(Exception):
    pass


class InstructionRangeExceededError(Exception):
    def __init__(self, pc):
        super(InstructionRangeExceededError, self).__init__()
        self.pc = pc

    def __str__(self):
        return "InstructionRangeExceededError(ended at instruction 0x%08X)" % self.pc


DataType: TypeAlias = str
SymbolName: TypeAlias = str

CallingConvention: TypeAlias = str
ReturnType: TypeAlias = DataType
ReturnName: TypeAlias = str
FunctionName: TypeAlias = SymbolName
ArgType: TypeAlias = DataType
ArgName: TypeAlias = SymbolName
FunctionArg: TypeAlias = Tuple[ArgType, ArgName]
# type returned by `vw.getImpApi`
API: TypeAlias = Tuple[ReturnType, ReturnName, CallingConvention, FunctionName, List[FunctionArg]]
# shortcut
Emulator: TypeAlias = vivisect.impemu.emulator.WorkspaceEmulator

# a hook overrides an API encountered by an emulator.
#
# returning True indicates the hook handled the function.
# this should include returning from the function and cleaning up the stack, if appropriate.
# a hook can also raise `StopEmulation` to ...stop the emulator.
#
# hooks can fetch the current $PC, registers, mem, etc. via the provided emulator parameter.
#
# a hook is a callable, such as a function or class with `__call__`,
# if the hook is "stateless", use a simple function:
#
#     hook_OutputDebugString(emu, api, argv):
#         _, _, cconv, name, _ = api
#         if name != "kernel32.OutputDebugString": return False
#         logger.debug("OutputDebugString: %s", emu.readString(argv[0]))
#         cconv.execCallReturn(emu, 0, len(argv))
#         return True
#
# if the hook is "stateful", such as a hook that records arguments, use a class:
#
#     class CreateFileAHook:
#         def __init__(self):
#             self.paths = set()
#
#         def __call__(self, emu, api, argv):
#             _, _, cconv, name, _ = api
#             if name != "kernel32.CreateFileA": return False
#             self.paths.add(emu.readString(argv[0]))
#             cconv.execCallReturn(emu, 0, len(argv))
#             return True
#
Hook = Callable[[Emulator, API, List[int]], bool]


class Monitor(vivisect.impemu.monitor.EmulationMonitor):
    def prehook(self, emu, op, startpc):
        pass

    def posthook(self, emu, op, endpc):
        pass

    def apicall(self, emu, api, argv):
        # returning True signals that the API call was handled.
        return False

    def logAnomaly(self, emu, pc, e):
        logger.warning("monitor: anomaly: %s", e)


class EmuHelperMixin:
    def readString(self, va, maxlength=0x100):
        """naively read ascii string"""
        return self.readMemory(va, maxlength).partition(b"\x00")[0].decode("ascii")

    def getStackValue(self, offset):
        return self.readMemoryFormat(self._emu.getStackCounter() + offset, "<P")[0]

    def readStackMemory(self, offset, length):
        return self.readMemory(self._emu.getStackCounter() + offset, length)

    def readStackString(self, offset, maxlength=0x1000):
        """naively read ascii string"""
        return self.readMemory(self._emu.getStackCounter() + offset, maxlength).partition(b"\x00")[0].decode("ascii")


class EmulatorDriver(EmuHelperMixin):
    """
    this is a superclass for strategies for controlling viv emulator instances.

    you can also treat it as an emulator instance, e.g.:

        emu = vw.getEmulator()
        drv = EmulatorDriver(emu)
        drv.getProgramCounter()

    note it also inherits from EmuHelperMixin, so there are convenience routines:

        emu = vw.getEmulator()
        drv = EmulatorDriver(emu)
        drv.readString(0x401000)
    """

    def __init__(self, emu):
        super(EmulatorDriver, self).__init__()
        self._emu = emu
        self._monitors = set([])
        self._hooks = set([])

    def __getattr__(self, name):
        # look just like an emulator
        return getattr(self._emu, name)

    def add_monitor(self, mon):
        """
        monitors are collections of callbacks that are invoked at various places:

          - pre instruction emulation
          - post instruction emulation
          - during API call

        see the `Monitor` superclass.

        install monitors using this routine `add_monitor`.
        there can be multiple monitors added.
        """
        self._monitors.add(mon)

    def remove_monitor(self, mon):
        self._monitors.remove(mon)

    def add_hook(self, hook):
        """
        hooks are functions that can override APIs encountered during emumation.
        see the `Hook` superclass.

        there can be multiple hooks added, even for the same API.
        hooks are invoked in the order that they were added.
        """
        self._hooks.add(hook)

    def remove_hook(self, hook):
        self._hooks.remove(hook)

    def isCall(self, op):
        return bool(op.iflags & v_envi.IF_CALL)

    def isIndirectMemJump(self, op):
        # jmp/call via thunk on x86
        # jmp/call via import on x64
        return op.mnem == "jmp" and isinstance(
            op.opers[0], (v_envi.archs.i386.disasm.i386ImmMemOper, v_envi.archs.amd64.disasm.Amd64RipRelOper)
        )

    def isRet(self, op):
        return bool(op.iflags & v_envi.IF_RET)

    def isHooked(self, pc, op):
        if not self.isCall(op):
            raise RuntimeError("not a call")

        emu = self._emu
        api = emu.getCallApi(pc)
        rtype, rname, convname, callname, funcargs = api

        return callname in emu.hooks

    def doHook(self, pc, op):
        """
        op should be the instruction that calls this function.
        pc should be at the start of a function.

        return True if a hook handled the call, False otherwise.
        if hook handled, then pc will be back at the call site,
        otherwise, pc remains where it was.
        """
        emu = self._emu

        api = emu.getCallApi(pc)
        _, _, convname, callname, funcargs = api

        if convname:
            callconv = emu.getCallingConvention(convname)
        else:
            logger.debug("driver: no call convention available at 0x%x. Using stdcall as default.", pc)
            callconv = emu.getCallingConvention("stdcall")

        argv = []
        if callconv:
            argv = callconv.getCallArgs(emu, len(funcargs))

        # attempt to invoke hooks to handle function calls.
        # priority:
        #   - monitor.apicall handler
        #   - driver.hooks
        #   - emu.hooks (default vivisect hooks)

        for mon in self._monitors:
            try:
                r = mon.apicall(self, api, argv)
            except StopEmulation:
                raise
            except Exception as e:
                logger.debug("driver: %s.apicall failed: %s", mon.__class__.__name__, e)
                continue
            else:
                if r:
                    # note: short circuit
                    logger.debug("driver: %s.apicall: handled call: %s", mon.__class__.__name__, callname)
                    return True

        for hook in self._hooks:
            try:
                ret = hook(self, api, argv)
            except StopEmulation:
                raise
            except Exception as e:
                logger.debug("driver: hook: %r failed: %s", hook, e)
                continue
            else:
                if ret:
                    # note: short circuit
                    logger.debug("driver: hook handled call: %s", callname)
                    return True

        if callname in emu.hooks:
            # this is where vivisect-internal hooks are stored,
            # such as those provided by impapi.
            # note that we prefer locally configured hooks, first.
            hook = emu.hooks.get(callname)
            try:
                hook(self, api, argv)
            except StopEmulation:
                raise
            except Exception as e:
                logger.debug("driver: emu.hook.%s failed: %s", callname, e)
            else:
                # note: short circuit
                logger.debug("driver: emu hook handled call: %s", callname)
                return True

        if callname and callname not in ("UnknownApi", "?"):
            logger.debug("driver: API call NOT hooked: %s", callname)

        return False

    def handleCall(self, pc, op, avoid_calls=False):
        """
        pc should be at a call instruction.
        if its an indirect call, like `call [0x401000]`, resolve the pointer first
        (if its a direct call, like `call 0x401000`, then deal with 0x401000)

        check to see if the function is hooked.
          if its hooked, do the hook, and pc goes to next instruction after the call.
          else,
            if avoid_calls is false, step into the call, and pc is at first instruction of function.
            if avoid_calls is true, step over the call, as best as possible.
              this means attempting to clean up the stack if its a cdecl call.
              also returning 0.

        return True if stepped into the function, False if the function is completely handled
        """
        if not (self.isCall(op) or self.isIndirectMemJump(op)):
            raise RuntimeError("not a call or jmp call")

        emu = self._emu
        is_call = self.isCall(op)

        emu.executeOpcode(op)
        target = emu.getProgramCounter()

        api = emu.getCallApi(target)
        rtype, rname, convname, callname, funcargs = api
        if convname:
            callconv = emu.getCallingConvention(convname)
        else:
            logger.debug("driver: no call convention available at 0x%x. Using stdcall as default.", target)
            callconv = emu.getCallingConvention("stdcall")

        if self.doHook(target, op):
            if is_call:
                # some hook handled the call,
                # so make sure PC is at the next instruction
                emu.setProgramCounter(pc + len(op))
            # otherwise next PC is on stack
            return False

        elif avoid_calls or emu.getVivTaint(target):
            # jump over the call instruction
            # return value --> 0
            callconv.execCallReturn(emu, 0, len(funcargs))
            if is_call:
                emu.setProgramCounter(pc + len(op))
            return False

        elif not avoid_calls:
            if emu.probeMemory(target, 0x1, v_mem.MM_EXEC):
                # this is executable memory, so we're good
                # op already emulated, just return
                return True
            else:
                # this is some unknown region of memory, try to return
                callconv.execCallReturn(emu, 0, len(funcargs))
                if is_call:
                    emu.setProgramCounter(pc + len(op))
                return False


class DebuggerEmulatorDriver(EmulatorDriver):
    """
    this is a EmulatorDriver that supports debugger-like operations,
      such as stepi, stepo, call, etc.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bps = set([])

    def step(self, avoid_calls):
        emu = self._emu
        startpc = emu.getProgramCounter()
        op = emu.parseOpcode(startpc)
        for mon in self._monitors:
            mon.prehook(emu, op, startpc)

        if self.isCall(op) or self.isIndirectMemJump(op):
            self.handleCall(startpc, op, avoid_calls=avoid_calls)
        else:
            emu.executeOpcode(op)

        endpc = emu.getProgramCounter()

        for mon in self._monitors:
            mon.posthook(emu, op, endpc)

    def stepo(self):
        return self.step(True)

    def stepi(self):
        return self.step(False)

    def runToCall(self, max_instruction_count=1000):
        """stepi until call instruction"""
        emu = self._emu
        for _ in range(max_instruction_count):
            pc = emu.getProgramCounter()
            if pc in self._bps:
                raise BreakpointHit()
            op = emu.parseOpcode(pc)
            if self.isCall(op):
                return
            else:
                self.stepi()
        raise InstructionRangeExceededError(pc)

    def runToReturn(self, max_instruction_count=1000):
        """stepo until ret instruction"""
        emu = self._emu
        for _ in range(max_instruction_count):
            pc = emu.getProgramCounter()
            if pc in self._bps:
                raise BreakpointHit()
            op = emu.parseOpcode(pc)
            if self.isRet(op):
                return
            else:
                self.stepo()
        raise InstructionRangeExceededError(pc)

    def runToVa(self, va, max_instruction_count=1000):
        """stepi until given address"""
        emu = self._emu
        for _ in range(max_instruction_count):
            pc = emu.getProgramCounter()
            if pc in self._bps:
                raise BreakpointHit()
            if pc == va:
                return
            else:
                self.stepi()
        raise InstructionRangeExceededError(pc)

    def addBreakpoint(self, va):
        self._bps.add(va)

    def removeBreakpoint(self, va):
        self._bps.remove(va)

    def getBreakpoints(self):
        return list(self._bps)


class FunctionRunnerEmulatorDriver(EmulatorDriver):
    """
    this is a EmulatorDriver that supports emulating all the instructions
      in a function.
    it explores all code paths by taking both branches.

    the .runFunction() implementation is essentially the same as emu.runFunction()
    """

    def __init__(self, emu):
        super(FunctionRunnerEmulatorDriver, self).__init__(emu)
        self.path = self.newCodePathNode()
        self.curpath = self.path

    def newCodePathNode(self, parent=None, bva=None):
        """
        NOTE: Right now, this is only called from the actual branch state which
        needs it.  it must stay that way for now (register context is being copied
        for symbolic emulator...)
        """
        props = {
            "bva": bva,  # the entry virtual address for this branch
            "valist": [],  # the virtual addresses in this node in order
            "calllog": [],  # FIXME is this even used?
            "readlog": [],  # a log of all memory reads from this block
            "writelog": [],  # a log of all memory writes from this block
        }
        return vg_path.newPathNode(parent=parent, **props)

    def _runFunction(self, funcva, stopva=None, maxhit=None, maxloop=None, maxrep=None, strictops=True, func_only=True):
        """
        :param func_only: is this emulator meant to stay in one function scope?
        :param strictops: should we bail on emulation if unsupported instruction encountered
        """
        vg_path.setNodeProp(self.curpath, "bva", funcva)

        hits = {}
        rephits = {}
        todo = [
            (funcva, self.getEmuSnap(), self.path),
        ]
        emu = self._emu
        vw = self._emu.vw  # Save a dereference many many times
        depth = 0
        op = None

        while len(todo) > 0:
            va, esnap, self.curpath = todo.pop()
            self.setEmuSnap(esnap)
            emu.setProgramCounter(va)

            # Check if we are beyond our loop max...
            if maxloop != None:
                lcount = vg_path.getPathLoopCount(self.curpath, "bva", va)
                if lcount > maxloop:
                    continue

            while True:
                startpc = emu.getProgramCounter()

                if not vw.isValidPointer(startpc):
                    break

                if startpc == stopva:
                    return

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow?
                if self.curpath == None:
                    break

                try:
                    op = emu.parseOpcode(startpc)

                    if op.prefixes & PREFIX_REP and maxrep != None:
                        # execute same instruction with `rep` prefix up to maxrep times
                        h = rephits.get(startpc, 0)
                        h += 1
                        if h > maxrep:
                            break
                        rephits[startpc] = h
                    elif maxhit != None:
                        # Check straight hit count for all other instructions...
                        h = hits.get(startpc, 0)
                        h += 1
                        if h > maxhit:
                            break
                        hits[startpc] = h

                    nextpc = startpc + len(op)
                    self.op = op

                    for mon in self._monitors:
                        mon.prehook(emu, op, startpc)

                    iscall = bool(op.iflags & v_envi.IF_CALL)
                    if iscall:
                        wentInto = self.handleCall(startpc, op, avoid_calls=func_only)
                        if wentInto:
                            depth += 1
                    else:
                        emu.executeOpcode(op)

                    vg_path.getNodeProp(self.curpath, "valist").append(startpc)
                    endpc = emu.getProgramCounter()

                    for mon in self._monitors:
                        mon.posthook(emu, op, endpc)

                    if not iscall:
                        # If it wasn't a call, check for branches, if so, add them to
                        # the todo list and go around again...
                        blist = emu.checkBranches(startpc, endpc, op)
                        if len(blist) > 0:
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.getEmuSnap()
                            for bva, bpath in blist:
                                todo.append((bva, esnap, bpath))
                            break

                    if op.iflags & v_envi.IF_RET:
                        vg_path.setNodeProp(self.curpath, "cleanret", True)
                        if depth == 0:
                            break
                        else:
                            depth -= 1

                # If we enounter a procedure exit, it doesn't
                # matter what PC is, we're done here.
                except v_envi.UnsupportedInstruction as e:
                    if strictops:
                        break
                    else:
                        logger.debug(
                            "driver: runFunction continuing after unsupported instruction: 0x%08x %s",
                            e.op.va,
                            e.op.mnem,
                        )
                        emu.setProgramCounter(e.op.va + e.op.size)
                except StopEmulation:
                    raise
                except Exception as e:
                    logger.warning("driver: error during emulation of function: %s", e)
                    for mon in self._monitors:
                        mon.logAnomaly(emu, startpc, str(e))
                    break  # If we exc during execution, this branch is dead.

    def runFunction(self, funcva, stopva=None, maxhit=None, maxloop=None, maxrep=None, strictops=True, func_only=True):
        try:
            self._runFunction(funcva, stopva, maxhit, maxloop, maxrep, strictops, func_only)
        except StopEmulation:
            return
