import logging
import pprint

import intervaltree
import vivisect.const as v_const

import viv_utils
import viv_utils.emulator_drivers


g_pp = pprint.PrettyPrinter()


class CallArgumentMonitor(viv_utils.emulator_drivers.Monitor):
    def __init__(self, vw, target_fva):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)
        self._fva = target_fva
        self._calls = {}

    def apicall(self, emu, op, pc, api, argv):
        rv = self.getStackValue(emu, 0)
        if pc == self._fva:
            self._calls[rv] = argv

    def getCalls(self):
        return self._calls.copy()


def emulate_function(vw, fva, target_fva):
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

    called_fvas = set([])
    for callerva in vw.getCallers(fva):
        callerfva = index[callerva]
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
