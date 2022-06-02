import sys
import logging
import collections
from typing import List, Callable, Optional

import envi as v_envi
import envi.exc
import vivisect
import envi.memory as v_mem
import vivisect.const
import envi.archs.i386.disasm

from viv_utils.types import *

logger = logging.getLogger(__name__)


class StopEmulation(Exception):
    pass


class BreakpointHit(Exception):
    def __init__(self, va: int, reason=None):
        self.va = va
        self.reason = reason


# a hook overrides an API encountered by an emulator.
#
# returning True indicates the hook handled the function.
# this should include returning from the function and cleaning up the stack, if appropriate.
# a hook can also raise `StopEmulation` to ...stop the emulator.
#
# hooks can fetch the current $PC, registers, mem, etc. via the provided emulator parameter.
#
# a hook is a callable, such as a function or class with `__call__`,
# if the hook is "stateless", use a simple function (note that the
# hook API and vivisect's imphook API differ slightly):
#
#     hook_OutputDebugString(emu, api, argv):
#         _, _, cconv, name, _ = api
#         if name != "kernel32.OutputDebugString": return False
#         logger.debug("OutputDebugString: %s", emu.readString(argv[0]))
#         cconv = emu.getCallingConvention(cconv)
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
#             cconv = emu.getCallingConvention(cconv)
#             cconv.execCallReturn(emu, 0, len(argv))
#             return True
#
Hook = Callable[[Emulator, API, List[int]], bool]


class Monitor(vivisect.impemu.monitor.EmulationMonitor):
    def prehook(self, emu, op, startpc):
        pass

    def posthook(self, emu, op, endpc):
        pass

    def preblock(self, emu, blockstart):
        # called when entering a newly recognized basic block.
        # the block analysis here is not guaranteed to be perfect,
        # but should work fairly well during FullCoverage emulation.
        pass

    def postblock(self, emu, blockstart, blockend):
        # called when entering a leaving recognized basic block.
        pass

    def apicall(self, emu, api, argv):
        # returning True signals that the API call was handled.
        return False

    def logAnomaly(self, emu, pc, e):
        logger.warning("monitor: anomaly: %s", e)


class UntilVAMonitor(Monitor):
    def __init__(self, va: int):
        super().__init__()
        self.va = va

    def prehook(self, emu, op, pc):
        if pc == self.va:
            raise BreakpointHit(pc, reason="va")


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
        hooks are functions that can override APIs encountered during emulation.
        see the `Hook` superclass.

        there can be multiple hooks added, even for the same API.
        hooks are invoked in the order that they were added.
        """
        self._hooks.add(hook)

    def remove_hook(self, hook):
        self._hooks.remove(hook)

    @staticmethod
    def is_call(op):
        return bool(op.iflags & v_envi.IF_CALL)

    @staticmethod
    def is_jmp(op):
        return op.mnem == "jmp"

    @staticmethod
    def is_ret(op):
        return bool(op.iflags & v_envi.IF_RET)

    def is_function_or_tainted(self, va):
        emu = self._emu
        return emu.vw.isFunction(va) or emu.getVivTaint(va)

    def get_calling_convention(self, convname: Optional[str]):
        if convname:
            return self._emu.getCallingConvention(convname)
        else:
            return self._emu.getCallingConvention("stdcall")

    def _handle_hook(self):
        """
        return True if a hook handled the call, False otherwise.
        if hook handled, then pc will be back at the call site,
        otherwise, pc remains where it was.
        """
        emu = self._emu
        pc = emu.getProgramCounter()

        api = emu.getCallApi(pc)
        _, _, convname, callname, funcargs = api

        callconv = self.get_calling_convention(convname)

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
                # the vivisect imphook API differs from the viv-utils hooks
                hook(self, callconv, api, argv)
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

    def handle_call(self, op, avoid_calls=False):
        """
        emulate a call instruction (pc should be at a the call instruction).
        if the target is hooked, do the hook instead of executing it.

        pending `avoid_calls`, try to step into or over the function.

        general algorithm:

            check to see if the function is hooked.
            if its hooked, do the hook, and pc goes to next instruction after the call.
            else,
                if avoid_calls is false, step into the call, and pc is at first instruction of function.
                if avoid_calls is true, step over the call, as best as possible.
                this means attempting to clean up the stack if its a cdecl call.
                also returning 0.

        return True if stepped into the function, False if the function is completely handled.
        """
        emu = self._emu

        pc = emu.getProgramCounter()
        emu.executeOpcode(op)
        target = emu.getProgramCounter()

        if self._handle_hook():
            # some hook handled the call,
            # so make sure PC is at the next instruction
            # this may fail during emulation, e.g. if the stack gets corrupted during emulation or by a function hook
            if emu.getProgramCounter() != pc + len(op):
                logger.warning(
                    "hook failed to restore PC correctly after call, from: 0x%x, expected: 0x%x, found: 0x%x",
                    pc,
                    pc + len(op),
                    emu.getProgramCounter(),
                )
                # pc is undefined (emulation error)
                raise StopEmulation

            # hook handled it
            # pc is at instruction after call
            return False

        elif avoid_calls or emu.getVivTaint(target) or not emu.probeMemory(target, 0x1, v_mem.MM_EXEC):
            # either:
            #  - we don't to emulate into functions, or
            #  - the target is unavailable/unresolved
            #  - the target is not executable
            #
            # jump over the call instruction.
            #
            # attempt to clean up stack, as necessary.
            # assume return value is 0
            _, _, convname, _, funcargs = emu.getCallApi(target)
            callconv = self.get_calling_convention(convname)
            # this will jump to the return address from the stack.
            callconv.execCallReturn(emu, 0, len(funcargs))
            if emu.getProgramCounter() != pc + len(op):
                logger.warning(
                    "hook failed to restore PC correctly after call, from: 0x%x, expected: 0x%x, found: 0x%x",
                    pc,
                    pc + len(op),
                    emu.getProgramCounter(),
                )
                # pc is undefined (emulation error)
                raise StopEmulation

            # pc is at instruction after call
            return False

        else:
            # we want to emulate into the function,
            # and its available and executable.

            # pc is at first instruction in the call.
            return True

    def handle_jmp(self, op, avoid_calls=False):
        """
        emulate a jmp instruction.

        most of the time, this is to implement loops and such.
        however, occasionally we may encounter a "tail call";
        that is, a jmp to the start of a function.
        in these cases, we want to treat the transition like a call.

        this function is like `handle_call` when the target of the
         jump is the start of a recognized function/API.

        returns True when the emulator followed the jmp and is now at the target.
        returns False when the emulator handled a tail call and is now after the call.
        """
        emu = self._emu

        pc = emu.getProgramCounter()

        # if the target address has an associated API
        # then this was a tail call (jump to function entry).
        # otherwise, its just a normal jmp and our handling is done.
        # careful to raise the segmentation violation for normal jmps.
        try:
            emu.executeOpcode(op)
        except envi.exc.SegmentationViolation as e:
            target = e.va
            if not self.is_function_or_tainted(target):
                # normal jump, but to invalid location
                # let caller handle the exception
                raise
        else:
            target = emu.getProgramCounter()
            # before this we verified that emu.getCallApi() returns a value, however
            # this returns a default API tuple for most addresses
            if not self.is_function_or_tainted(target):
                # normal jump, to valid location.
                # emulation is complete.
                # pc is at the destination of the jump.
                return True

        # if we reach here, we're in a tail call,
        # because the target address is a function or tainted.

        if self._handle_hook():
            if emu.getProgramCounter() != pc + len(op):
                logger.warning(
                    "hook failed to restore PC correctly after call, from: 0x%x, expected: 0x%x, found: 0x%x",
                    pc,
                    pc + len(op),
                    emu.getProgramCounter(),
                )
                # pc is undefined (emulation error)
                raise StopEmulation

            # some hook handled the tail call,
            # pc is at call's return address.
            return False

        elif avoid_calls or emu.getVivTaint(target) or not emu.probeMemory(target, 0x1, v_mem.MM_EXEC):
            # either:
            #  - we don't to emulate into functions, or
            #  - the target is unavailable/unresolved
            #  - the target is not executable
            #
            # jump over the call instruction.
            #
            # attempt to clean up stack, as necessary.
            # assume return value is 0
            _, _, convname, _, funcargs = emu.getCallApi(target)
            callconv = self.get_calling_convention(convname)
            # this will jump to the return address from the stack.
            callconv.execCallReturn(emu, 0, len(funcargs))

            # pc is at the return address.
            return False

        else:
            # we want to emulate into the function,
            # and its available and executable.

            # pc is at first instruction in the function.
            return True


class DebuggerEmulatorDriver(EmulatorDriver):
    """
    this is a EmulatorDriver that supports debugger-like operations,
      such as stepi, stepo, call, etc.
    these operations are implemented as monitors, and serve as good examples.

    it also supports "breakpoints": a set of addresses such that,
     when encountering the address, a `BreakpointHit` exception is raised.
    """

    class MaxInsnMonitor(Monitor):
        def __init__(self, max_insn):
            super().__init__()
            self.max_insn = max_insn
            self.counter = 0

        def prehook(self, emu, op, pc):
            if self.counter >= self.max_insn:
                raise BreakpointHit(pc, reason="max_insn")

            self.counter += 1

        def reset(self):
            self.counter = 0

    class MaxHitMonitor(Monitor):
        def __init__(self, max_hit):
            super().__init__()
            self.max_hit = max_hit
            self.counter = collections.Counter()

        def prehook(self, emu, op, pc):
            if self.counter.get(pc, 0) >= self.max_hit:
                raise BreakpointHit(pc, reason="max_hit")

            self.counter[pc] += 1

        def reset(self):
            self.counter = collections.Counter()

    class BreakpointMonitor(Monitor):
        def __init__(self):
            super().__init__()
            self.breakpoints = set()

        def prehook(self, emu, op, pc):
            if pc in self.breakpoints:
                raise BreakpointHit(pc, reason="breakpoint")

    def __init__(self, *args, repmax=None, max_insn=None, max_hit=None, **kwargs):
        super().__init__(*args, **kwargs)
        if repmax is not None:
            self.setEmuOpt("i386:repmax", repmax)

        self.max_insn_mon = self.MaxInsnMonitor(max_insn or sys.maxsize)
        self.max_hit_mon = self.MaxHitMonitor(max_hit or sys.maxsize)
        self.bp_mon = self.BreakpointMonitor()

        self.add_monitor(self.max_insn_mon)
        self.add_monitor(self.max_hit_mon)
        self.add_monitor(self.bp_mon)

        # this is a public member.
        # add and remove breakpoints by manipulating this set.
        #
        # implementation: note that we're sharing the set() instance here.
        self.breakpoints = self.bp_mon.breakpoints

    def step(self, avoid_calls):
        emu = self._emu

        startpc = emu.getProgramCounter()
        op = emu.parseOpcode(startpc)

        for mon in self._monitors:
            mon.prehook(emu, op, startpc)

        if self.is_call(op):
            self.handle_call(op, avoid_calls=avoid_calls)
        elif self.is_jmp(op):
            self.handle_jmp(op, avoid_calls=avoid_calls)
        else:
            emu.executeOpcode(op)

        endpc = emu.getProgramCounter()

        for mon in self._monitors:
            mon.posthook(emu, op, endpc)

    def stepo(self):
        return self.step(True)

    def stepi(self):
        return self.step(False)

    def run(self):
        """
        stepi until breakpoint is hit or max_instruction_count reached.
        raises the exception in either case.
        """
        self.max_hit_mon.reset()
        self.max_insn_mon.reset()

        while True:
            self.stepi()

    class UntilMnemonicMonitor(Monitor):
        def __init__(self, mnems: List[str]):
            super().__init__()
            self.mnems = mnems

        def prehook(self, emu, op, pc):
            if op.mnem in self.mnems:
                raise BreakpointHit(pc, reason="mnemonic")

    def run_to_mnem(self, mnems: List[str]):
        """
        stepi until:
          - breakpoint is hit, or
          - max_instruction_count reached, or
          - given mnemonic reached (but not executed).
        raises the exception in any case.
        """
        mon = self.UntilMnemonicMonitor(mnems)
        self.add_monitor(mon)

        try:
            self.run()
        finally:
            self.remove_monitor(mon)

    def run_to_va(self, va: int):
        """
        stepi until:
          - breakpoint is hit, or
          - max_instruction_count reached, or
          - given address reached (but not executed).
        raises the exception in any case.
        """
        mon = UntilVAMonitor(va)
        self.add_monitor(mon)

        try:
            self.run()
        except BreakpointHit as e:
            if e.va != va:
                raise
        finally:
            self.remove_monitor(mon)


class FullCoverageEmulatorDriver(EmulatorDriver):
    """
    an emulator that attempts to explore all code paths from a given entry.
    that is, it explores all branches encountered (though it doesn't follow calls).
    it should emulate each instruction once (unless REP prefix, and limited to repmax iterations).

    use a monitor to receive callbacks describing the found instructions and blocks.
    """

    def __init__(self, *args, repmax=None, **kwargs):
        super().__init__(*args, **kwargs)
        if repmax is not None:
            self.setEmuOpt("i386:repmax", repmax)

    def is_table(self, op, xrefs):
        if not self.vw.getLocation(op.va):
            return False
        if not xrefs:
            return False

        for bto, bflags in op.getBranches(emu=None):
            if bflags & envi.BR_TABLE:
                return True

        return False

    @staticmethod
    def is_conditional(op):
        if not (op.iflags & envi.IF_BRANCH):
            return False
        return op.iflags & envi.IF_COND

    def get_branches(self, op):
        emu = self._emu
        vw = emu.vw
        ret = []

        if not (op.iflags & envi.IF_BRANCH):
            return []

        xrefs = vw.getXrefsFrom(op.va, rtype=vivisect.const.REF_CODE)
        if self.is_table(op, xrefs):
            for xrfrom, xrto, xrtype, xrflags in xrefs:
                ret.append(xrto)
            return ret

        xrefs = op.getBranches(emu=emu)
        if not xrefs:
            return []

        if self.is_conditional(op):
            for bto, bflags in xrefs:
                if not bto:
                    continue
                ret.append(bto)
            return ret

        # we've hit a branch that doesn't go anywhere.
        # probably a switchcase we don't handle well.
        for bto, bflags in xrefs:
            if bflags & envi.BR_DEREF:
                continue

            ret.append(bto)

        return ret

    def step(self):
        """
        emulate one instruction.
        return :
          - whether the instruction falls through, and
          - the list of branch target to which execution may flow from this instruction.
        """
        emu = self._emu

        startpc = emu.getProgramCounter()
        op = emu.parseOpcode(startpc)

        for mon in self._monitors:
            mon.prehook(emu, op, startpc)

        branches = self.get_branches(op)

        if self.is_call(op):
            skipped = not self.handle_call(op, avoid_calls=True)
        elif self.is_jmp(op):
            skipped = not self.handle_jmp(op, avoid_calls=True)
        else:
            emu.executeOpcode(op)
            skipped = False

        endpc = emu.getProgramCounter()

        for mon in self._monitors:
            mon.posthook(emu, op, endpc)

        does_fallthrough = not (op.iflags & envi.IF_NOFALL)

        if skipped:
            return does_fallthrough, []
        else:
            return does_fallthrough, branches

    def run(self, va: int):
        # explore from the given address, emulating all encountered instructions once.
        #
        # use a queue of emulator snaps, one for each block that still needs to be explored.
        # use a set to track the instructions already emulated.
        #
        # when emulating an instruction, here are the cases:
        #  - instruction not supported: skip to next one
        #  - invalid instruction: stop emulation
        #  - branching instruction: stop emulation, add snap for each branch
        #  - fallthrough to new instruction: step to next instruction
        #  - fallthrough to seen instruction: stop emulation
        #  - no fallthrough (like ret): stop emulation
        emu = self._emu
        emu.setProgramCounter(va)

        # queue of emulator snapshots to explore
        q = collections.deque([emu.getEmuSnap()])

        # set of branch targets that have already been explored.
        seen = set()

        while q:
            snap = q.popleft()

            emu.setEmuSnap(snap)
            blockstart = emu.getProgramCounter()

            if blockstart in seen:
                # this block has already been explored,
                # don't do duplicate work.
                continue

            seen.add(blockstart)

            for mon in self._monitors:
                mon.preblock(self, blockstart)

            while True:
                # the address of the instruction we're about to emulate.
                lastpc = emu.getProgramCounter()
                seen.add(lastpc)

                try:
                    does_fallthrough, branches = self.step()
                except v_envi.UnsupportedInstruction:
                    # don't know how to emulate the instruction.
                    # skip it and hope we can fallthrough and keep emulating.
                    op = emu.parseOpcode(lastpc)
                    emu.setProgramCounter(lastpc + op.size)

                    logger.debug(
                        "driver: run_function: skipping unsupported instruction: 0x%x %s",
                        lastpc,
                        op.mnem,
                    )

                    continue
                except v_envi.InvalidInstruction:
                    # don't know how to decode the instruction.
                    # so we don't know its length, and there's nothing we can do.

                    logger.debug(
                        "driver: run_function: invalid instruction: 0x%x",
                        lastpc,
                    )

                    blockend = lastpc
                    for mon in self._monitors:
                        mon.postblock(self, blockstart, blockend)

                    # stop emulating, and go to next block in the queue.
                    break
                except envi.exc.BreakpointHit:
                    # emulation likely wandered off, e.g., into alignment (CC bytes)

                    # stop emulating, and go to next block in the queue.
                    break

                if branches:
                    blockend = lastpc

                    # other case: branching instruction.
                    # enqueue all the branch options for exploration.
                    for branch in branches:
                        if branch in seen:
                            continue

                        emu.setProgramCounter(branch)
                        q.append(emu.getEmuSnap())

                    for mon in self._monitors:
                        mon.postblock(self, blockstart, blockend)

                    # stop emulating this basic block,
                    # go to next block in the queue.
                    break

                elif does_fallthrough:
                    # common case: middle of BB, keep stepping.

                    nextpc = emu.getProgramCounter()
                    if nextpc in seen:

                        if nextpc == lastpc:
                            # candidates:
                            #   - jump to self
                            #   - REP instruction
                            #   - ???
                            op = emu.parseOpcode(lastpc)
                            if op.prefixes & envi.archs.i386.disasm.PREFIX_REP:
                                # its a REP instruction,
                                # do this max_rep times,
                                # then be done.
                                # TODO
                                continue

                            # other cases: like a new basic block
                            # so fallthrough and break.

                        # the next instruction has already been explored.
                        # must be an overlapping block.
                        # stop emulating and go to next block in queue.
                        blockend = lastpc

                        for mon in self._monitors:
                            mon.postblock(self, blockstart, blockend)

                        break
                    else:
                        # next instruction is not yet explored,
                        # keep stepping.
                        continue

                else:
                    # uncommon case: no fallthrough, like ret.
                    # stop emulating this basic block.
                    # go to next block in the queue.
                    blockend = lastpc

                    for mon in self._monitors:
                        mon.postblock(self, blockstart, blockend)

                    break


class SinglePathEmulatorDriver(FullCoverageEmulatorDriver):
    """
    an emulator that emulates the first path found to a target VA.
    path is brute-forced via the full coverage emulator.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def run_to_va(self, va: int, tova: int):
        """
        explore from the given address up to an address, see run function
        """
        mon = UntilVAMonitor(tova)
        self.add_monitor(mon)
        try:
            self.run(va)
        except BreakpointHit as e:
            if e.va != tova:
                raise
        finally:
            self.remove_monitor(mon)


def remove_default_viv_hooks(emu, allow_list=None):
    """
    vivisect comes with default emulation hooks (imphooks) that emulate
     - API calls, e.g. GetProcAddress
     - abstractions of library code functionality, e.g. _alloca_probe

    in our testing there are inconsistencies in the hook implementation, e.g. around function returns
    this function removes all imphooks except ones explicitly allowed
    """
    for hook_name in list(emu.hooks):
        if allow_list and hook_name in allow_list:
            continue
        del emu.hooks[hook_name]
