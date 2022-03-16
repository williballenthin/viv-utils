import collections

from fixtures import *

import viv_utils.emulator_drivers as vudrv


class CoverageMonitor(vudrv.Monitor):
    """capture the emulated addresses"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.addresses = collections.Counter()

    def prehook(self, emu, op, startpc):
        self.addresses[startpc] += 1


def test_driver_monitor(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)
    cov = CoverageMonitor()
    drv.add_monitor(cov)

    # 10001010 B8 F8 11 00 00          mov     eax, 11F8h
    # 10001015 E8 06 02 00 00          call    __alloca_probe

    drv.setProgramCounter(0x10001010)
    drv.stepi()
    assert drv.getProgramCounter() == 0x10001015

    assert 0x10001010 in cov.addresses
    assert 0x10001015 not in cov.addresses


def test_dbg_driver_stepi(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    drv.stepi()
    drv.stepi()
    drv.stepi()
    drv.stepi()
    assert drv.getProgramCounter() == 0x10001010


def test_dbg_driver_stepo(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    drv.stepo()
    drv.stepo()
    drv.stepo()
    drv.stepo()
    assert drv.getProgramCounter() == 0x1000134A


class CreateMutexAHook(vudrv.Hook):
    """capture the mutex names passed to CreateMutexA"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mutexes = set()

    def hook(self, callname, drv: vudrv.EmulatorDriver, callconv, api, argv):
        if callname != "kernel32.CreateMutexA":
            return

        mutex = drv.readString(argv[2])
        self.mutexes.add(mutex)

        _, _, _, callname, funcargs = api
        callconv.execCallReturn(drv, 0, len(funcargs))
        return True


def test_driver_hook(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)
    hk = CreateMutexAHook()
    drv.add_hook(hk)

    # .text:10001067 68 38 60 02 10          push    offset Name     ; "SADFHUHF"
    # .text:1000106C 50                      push    eax             ; bInitialOwner
    # .text:1000106D 50                      push    eax             ; lpMutexAttributes
    # .text:1000106E FF 15 08 20 00 10       call    ds:CreateMutexA
    # .text:10001074 8D 4C 24 78             lea     ecx, [esp+1208h+var_1190]

    drv.setProgramCounter(0x10001067)
    drv.stepi()
    drv.stepi()
    drv.stepi()
    drv.stepi()
    assert drv.getProgramCounter() == 0x10001074
    assert "SADFHUHF" in hk.mutexes
