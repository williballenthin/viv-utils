import logging

import viv_utils
import viv_utils.emulator_drivers


class AMonitor(viv_utils.emulator_drivers.Monitor):
    def __init__(self, vw):
        viv_utils.emulator_drivers.Monitor.__init__(self, vw)

    def prehook(self, emu, op, starteip):
        self._logger.debug("prehook: %s: %s", hex(starteip), op)

    def apicall(self, emu, op, pc, api, argv):
        self._logger.debug("apicall: %s %s %s %s", op, pc, api, argv)


def _main(bin_path, fva):
    logging.basicConfig(level=logging.DEBUG)

    vw = viv_utils.getWorkspace(bin_path)
    emu = vw.getEmulator()
    d = viv_utils.emulator_drivers.FunctionRunnerEmulatorDriver(emu)

    m = AMonitor(vw)
    d.add_monitor(m)

    logging.getLogger("trace").debug("%s %s %s %s", vw, emu, d, m)

    d.runFunction(int(fva, 0x10), maxhit=1)


def main():
    import sys

    sys.exit(_main(*sys.argv[1:]))


if __name__ == "__main__":
    main()
