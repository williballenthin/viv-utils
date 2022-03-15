import pprint
import logging

import viv_utils
import viv_utils.emulator_drivers

g_pp = pprint.PrettyPrinter()


class CallArgumentMonitor(viv_utils.emulator_drivers.Monitor):
    """collect call arguments to a target function during emulation"""

    def __init__(self, vw, target_fva):
        """:param target_fva: address of function whose arguments to monitor"""
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self._fva = target_fva
        self._calls = {}

    def apicall(self, emu, op, pc, api, argv):
        rv = self.getStackValue(emu, 0)
        if pc == self._fva:
            self._calls[rv] = argv

    def getCalls(self):
        """get map of return value of function call to arguments to function call"""
        return self._calls.copy()


def emulate_function(vw, fva, target_fva):
    """run the given function while collecting arguments to a target function"""
    emu = vw.getEmulator()
    d = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)

    m = CallArgumentMonitor(vw, target_fva)
    d.add_monitor(m)

    d.runFunction(fva, maxhit=1)

    for k, v in m.getCalls().iteritems():
        print(hex(k) + ": " + str(v))


def _main(bin_path, ofva):
    fva = int(ofva, 0x10)
    logging.basicConfig(level=logging.DEBUG)

    vw = viv_utils.getWorkspace(bin_path)

    index = viv_utils.InstructionFunctionIndex(vw)

    # optimization: avoid re-processing the same function repeatedly
    called_fvas = set([])
    for callerva in vw.getCallers(fva):
        callerfva = index[callerva]  # the address of the function that contains this instruction
        if callerfva in called_fvas:
            continue

        emulate_function(vw, index[callerva], fva)

        called_fvas.add(callerfva)

    return


def main():
    import sys

    sys.exit(_main(*sys.argv[1:]))


if __name__ == "__main__":
    main()
