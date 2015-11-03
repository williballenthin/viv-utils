import logging

import vivisect
import envi as v_envi
import visgraph.pathcore as vg_path


class StopEmulation(Exception):
    pass


class UnsupportedFunction(Exception):
    pass


class InstructionRangeExceededError(Exception):

    def __init__(self, eip):
        super(InstructionRangeExceededError, self).__init__()
        self.eip = eip

    def __str__(self):
        return "InstructionRangeExceededError(ended at instruction 0x%08X)" % self.eip


class Hook(object):
    def __init__(self):
        super(Hook, self).__init__()

    def hook(self, callname, emu, callconv, api, argv):
        # must return something other than None if handled
        # raise UnsupportedFunction to pass
        raise UnsupportedFunction()


class Monitor(vivisect.impemu.monitor.EmulationMonitor):
    def __init__(self, vw):
        vivisect.impemu.monitor.EmulationMonitor.__init__(self)
        self._vw = vw
        self._logger = logging.getLogger("Monitor")

    def getStackValue(self, emu, offset):
        return emu.readMemoryFormat(emu.getStackCounter() + offset, "<P")[0]

    def dumpStack(self, emu, num):
        self._logger.debug("stack: ESP: %s", hex(emu.getStackCounter()))
        for i in xrange(num):
            self._logger.debug("stack: ESP + %s: %s", hex(4 * i), hex(self.getStackValue(emu, 4 * i)))

    def prehook(self, emu, op, starteip):
        pass
        #self._logger.debug("======================")
        #self._logger.debug("prehook: %s: %s", hex(starteip), op)
        #self._logger.debug("eflags: %s", bin(emu.getRegisterByName("eflags")))
        #self._logger.debug("PF: %s", emu.getFlag(EFLAGS_PF))
        #self.dumpStack(emu, 4)
        #self._logger.debug("----------------------")

    def posthook(self, emu, op, endeip):
        #self.dumpStack(emu, 4)
        #self._logger.debug("  EBX: %s", hex(emu.getRegisterByName("ebx")))
        pass

    def apicall(self, emu, op, pc, api, argv):
        #self._logger.debug("apicall: %s %s %s %s", op, pc, api, argv)
        # if non-None is returned, then it signals that the API call was handled
        #   and this function *must* handle cleaning up the stack
        pass

    def logAnomaly(self, *args, **kwargs):
        self._logger.warning("error: args:%s kwargs:%s", args, kwargs)


class EmulatorDriver(object):
    """
    this is a type of object that knows how to drive an emulator in various ways.
    """
    def __init__(self, emu):
        super(EmulatorDriver, self).__init__()
        self._emu = emu
        self._monitors = []
        self._hooks = []
        self._logger = logging.getLogger("EmulatorDriver")

    def add_monitor(self, mon):
        self._monitors.append(mon)

    def remove_monitor(self, mon):
        if mon in self._monitors:
            del self._monitors[self._monitors.index(mon)]

    def add_hook(self, hook):
        self._hooks.append(hook)

    def isCall(self, op):
        return bool(op.iflags & v_envi.IF_CALL)

    def isRet(self, op):
        return bool(op.iflags & v_envi.IF_RET)

    def isHooked(self, eip, op):
        if not self.isCall(op):
            raise RuntimeError("not a call")

        emu = self._emu
        api = emu.getCallApi(eip)
        rtype, rname, convname, callname, funcargs = api
        callconv = emu.getCallingConvention(convname)
        argv = callconv.getCallArgs(emu, len(funcargs))

        return callname in emu.hooks

    def readString(self, va, maxlength=0x1000):
        """ naively read ascii string """
        return self._emu.readMemory(va, maxlength).partition("\x00")[0]

    def getStackValue(self, offset):
        return self._emu.readMemoryFormat(self._emu.getStackCounter() + offset, "<P")[0]

    def readStackMemory(self, offset, length):
        return self._emu.readMemory(self._emu.getStackCounter() + offset, length)

    def readStackString(self, offset, maxlength=0x1000):
        """ naively read ascii string """
        return self._emu.readMemory(self._emu.getStackCounter() + offset, maxlength).partition("\x00")[0]

    def __getattr__(self, name):
        # look just like an emulator
        return getattr(self._emu, name)
    

class DebuggerEmulatorDriver(EmulatorDriver):
    """
    this is a EmulatorDriver that supports debugger-like operations,
      such as stepi, stepo, call, etc.
    """
    def __init__(self, emu):
        super(DebuggerEmulatorDriver, self).__init__(emu)
        self._bps = set([])

    def handleCall(self, eip, op, avoid_calls=False):
        """
        for the given call:
          if its hooked, do the hook, and pc goes to next instruction
          else, step into the call, and pc is at first instruction of function
        """
        if not self.isCall(op):
            raise RuntimeError("not a call")

        emu = self._emu
        api = emu.getCallApi(eip)
        rtype, rname, convname, callname, funcargs = api
        callconv = emu.getCallingConvention(convname)
        argv = callconv.getCallArgs(emu, len(funcargs))

        for mon in self._monitors:
            mon.apicall(emu, op, eip, api, argv)

        if self.isCall(op):
            # TODO: update hooks logic here
            if self.isHooked(eip, op):
                hook = emu.hooks.get(callname)
                hook(emu, callconv, api, argv)
                emu.setProgramCounter(eip+len(op))
            else:
                if avoid_calls:
                    # jump over the call instruction
                    # return value --> 0
                    callconv.execCallReturn(emu, 0, len(funcargs))
                    emu.setProgramCounter(eip + len(op))
                else:
                    emu.executeOpcode(op)
        else:
            emu.executeOpcode(op)

    def step(self, avoid_calls):
        emu = self._emu
        starteip = emu.getProgramCounter()
        op = emu.parseOpcode(starteip)
        for mon in self._monitors:
            mon.prehook(emu, op, starteip)

        if self.isCall(op):
            self.handleCall(starteip, op, avoid_calls=avoid_calls)
        else:
            emu.executeOpcode(op)

        endeip = emu.getProgramCounter()

        for mon in self._monitors:
            mon.posthook(emu, op, endeip)

    def stepo(self):
        return self.step(True)

    def stepi(self):
        return self.step(False)

    def runToCall(self, max_instruction_count=1000):
        """ stepi until ret instruction """
        emu = self._emu
        for _ in xrange(max_instruction_count):
            eip = emu.getProgramCounter()
            if eip in self._bps:
                raise BreakpointHit()
            op = emu.parseOpcode(eip)
            if self.isCall(op):
                return
            else:
                self.stepi()
        raise InstructionRangeExceededError(eip)

    def runToReturn(self, max_instruction_count=1000):
        """ stepo until ret instruction """
        emu = self._emu
        for _ in xrange(max_instruction_count):
            eip = emu.getProgramCounter()
            if eip in self._bps:
                raise BreakpointHit()
            op = emu.parseOpcode(eip)
            if self.isRet(op):
                return
            else:
                self.stepo()
        raise InstructionRangeExceededError(eip)

    def runToVa(self, va, max_instruction_count=1000):
        """ stepi until ret instruction """
        emu = self._emu
        for _ in xrange(max_instruction_count):
            eip = emu.getProgramCounter()
            if eip in self._bps:
                raise BreakpointHit()
            if eip == va:
                return
            else:
                self.stepi()
        raise InstructionRangeExceededError(eip)

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
        '''
        NOTE: Right now, this is only called from the actual branch state which
        needs it.  it must stay that way for now (register context is being copied
        for symbolic emulator...)
        '''
        props = {
            'bva':bva,    # the entry virtual address for this branch
            'valist':[],  # the virtual addresses in this node in order
            'calllog':[], # FIXME is this even used?
            'readlog':[], # a log of all memory reads from this block
            'writelog':[],# a log of all memory writes from this block
        }
        return vg_path.newPathNode(parent=parent, **props)

    def _runFunction(self, funcva, stopva=None, maxhit=None, maxloop=None, strictops=True, func_only=True):
        """
        :param func_only: is this emulator meant to stay in one function scope?
        :param strictops: should we bail on emulation if unsupported instruction encountered
        """
        vg_path.setNodeProp(self.curpath, 'bva', funcva)

        hits = {}
        todo = [(funcva, self.getEmuSnap(), self.path), ]
        emu = self._emu
        vw = self._emu.vw # Save a dereference many many times

        while len(todo) > 0:
            va, esnap, self.curpath = todo.pop()
            self.setEmuSnap(esnap)
            emu.setProgramCounter(va)

            # Check if we are beyond our loop max...
            if maxloop != None:
                lcount = vg_path.getPathLoopCount(self.curpath, 'bva', va)
                if lcount > maxloop:
                    continue

            while True:
                starteip = emu.getProgramCounter()

                if not vw.isValidPointer(starteip):
                    break

                if starteip == stopva:
                    return


                # Check straight hit count...
                if maxhit != None:
                    h = hits.get(starteip, 0)
                    h += 1
                    if h > maxhit:
                        break
                    hits[starteip] = h

                # If we ran out of path (branches that went
                # somewhere that we couldn't follow?
                if self.curpath == None:
                    break

                try:
                    op = emu.parseOpcode(starteip)
                    nextpc = starteip + len(op)
                    self.op = op

                    for mon in self._monitors:
                        mon.prehook(emu, op, starteip)

                    # Execute the opcode
                    emu.executeOpcode(op)
                    vg_path.getNodeProp(self.curpath, 'valist').append(starteip)

                    endeip = emu.getProgramCounter()

                    for mon in self._monitors:
                        mon.posthook(emu, op, endeip)

                    iscall = bool(op.iflags & v_envi.IF_CALL)
                    if iscall:

                        is_call_target_resolved = self.getStackValue(0x0) == nextpc 

                        api = emu.getCallApi(endeip)
                        rtype, rname, convname, callname, funcargs = api
                        callconv = emu.getCallingConvention(convname)
                        argv = callconv.getCallArgs(emu, len(funcargs))

                        # print("API call: " + callname)

                        # attempt to invoke hooks to handle function calls.
                        # priority:
                        #   - monitor.apicall handler
                        #   - driver.hooks
                        #   - emu.hooks (default vivisect hooks)
                        
                        call_handled = False
                        for mon in self._monitors:
                            try:
                                r = mon.apicall(emu, op, endeip, api, argv)
                                if r is not None:
                                    # take the first result
                                    # not ideal, but works in the common case
                                    self._logger.debug("monitor hook handled call: %s", callname)
                                    call_handled = True
                                    break
                            except Exception, e:
                                print("apicall error: %s" % (e))
                                mon.logAnomaly(emu, endeip, 
                                        "%s.apicall failed: %s" % (mon.__class__.__name__, e))

                        if not call_handled:
                            for hook in self._hooks:
                                try:
                                    ret = hook.hook(callname, emu, callconv, api, argv)
                                    # take the first result
                                    # not ideal, but works in the common case
                                    if ret is not None:
                                        self._logger.debug("driver hook handled call: %s", callname)
                                        call_handled = True
                                        break
                                except UnsupportedFunction:
                                    continue

                        if not call_handled and callname in emu.hooks:
                            hook = emu.hooks.get(callname)
                            hook(self, callconv, api, argv)
                            self._logger.debug("emu hook handled call: %s", callname)
                            call_handled = True

                        if call_handled:
                            # some hook handled the call,
                            # so make sure PC is at the next instruction
                            emu.setProgramCounter(starteip + len(op))
                        elif not is_call_target_resolved:
                            # vivisect-specific behavior: when the call instruction does not
                            #   emulate correct (like when the function target is not correctly mapped),
                            #   the return pointer is not pushed,
                            # so jump directly to next instruction
                            emu.setProgramCounter(starteip + len(op))
                        else:
                            # if no hooks handled the call, but we still want to continue...
                            if func_only:
                                # try to emulate a return
                                ret = emu.setVivTaint('apicall', (op, endeip, api, argv))
                                callconv.execCallReturn( emu, ret, len(funcargs) )
                            else:
                                # or, keep emulating into new function
                                pass

                    else:
                        # If it wasn't a call, check for branches, if so, add them to
                        # the todo list and go around again...
                        blist = emu.checkBranches(starteip, endeip, op)
                        if len(blist) > 0:
                            # pc in the snap will be wrong, but over-ridden at restore
                            esnap = self.getEmuSnap()
                            for bva, bpath in blist:
                                todo.append((bva, esnap, bpath))
                            break

                    # If we enounter a procedure exit, it doesn't
                    # matter what EIP is, we're done here.
                    if op.iflags & v_envi.IF_RET:
                        vg_path.setNodeProp(self.curpath, 'cleanret', True)
                        break

                except v_envi.UnsupportedInstruction as e:
                    if strictops:
                        break
                    else:
                        self._logger.warning('runFunction continuing after unsupported instruction: 0x%08x %s',
                               e.op.va, e.op.mnem)
                        emu.setProgramCounter(e.op.va + e.op.size)
                except Exception as e:
                    self._logger.error("error during emulation of function", exc_info=True)
                    for mon in self._monitors:
                        mon.logAnomaly(emu, starteip, str(e))
                    break # If we exc during execution, this branch is dead.

    def runFunction(self, funcva, stopva=None, maxhit=None, maxloop=None, strictops=True, func_only=True):
        try:
            self._runFunction(funcva, stopva, maxhit, maxloop, strictops, func_only)
        except StopEmulation:
            return
