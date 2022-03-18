import collections

import envi.const
from fixtures import *

import viv_utils.emulator_drivers as vudrv


class LoggingMonitor(vudrv.Monitor):
    """log the emulated addresses"""

    def prehook(self, emu, op, startpc):
        print("emu: 0x%x %s" % (startpc, op))


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


class CreateMutexAHook:
    """capture the mutex names passed to CreateMutexA"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mutexes = set()

    def __call__(self, emu, api, argv):
        _, _, cconv, name, _ = api

        if name != "kernel32.CreateMutexA":
            return

        mutex = emu.readString(argv[2])
        self.mutexes.add(mutex)

        cconv = emu.getCallingConvention(cconv)
        cconv.execCallReturn(emu, 0, len(argv))

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


def protect_memory(imem, va, size, perms):
    # see: https://github.com/vivisect/vivisect/issues/511
    maps = imem._map_defs
    for i in range(len(maps)):
        map = maps[i]
        start, end, mmap, bytez = map
        mva, msize, mperms, mfilename = mmap

        if mva == va and msize == size:
            maps[i] = [start, end, [mva, msize, perms, mfilename], bytez]
            return

    raise KeyError("unknown memory map: 0x%x (0x%x bytes)", va, size)


def test_driver_hook_tailjump(pma01):
    # patch:
    #
    # .text:10001067 68 38 60 02 10          push    offset Name     ; "SADFHUHF"
    # .text:1000106C 50                      push    eax             ; bInitialOwner
    # .text:1000106D 50                      push    eax             ; lpMutexAttributes
    # .text:1000106E FF 15 08 20 00 10       call    ds:CreateMutexA
    # .text:10001074 8D 4C 24 78             lea     ecx, [esp+1208h+var_1190]
    #
    # to:
    #
    # .text:10001067 68 38 60 02 10          push    offset Name     ; "SADFHUHF"
    # .text:1000106C 50                      push    eax             ; bInitialOwner
    # .text:1000106D 50                      push    eax             ; lpMutexAttributes
    # .text:1000106E 68 79 10 00 10          push    offset loc_10001079
    # .text:10001073 FF 25 08 20 00 10       jmp     ds:CreateMutexA
    # .text:10001079 ...                     ...
    #
    # so that we have a tail jump to `CreateMutexA` (but with the return address on the stack).
    # the hook handler should pick up on this, and handle the transition to `CreateMutexA` as a call.
    #
    # note: we have to patch the vw, because patching emu mem doesn't work.
    # the emu instance reads opcodes from the vw not emu memory.
    # see: https://github.com/vivisect/vivisect/issues/512
    vw = pma01
    mapva, size, perms, filename = vw.getMemoryMap(0x1000106E)
    protect_memory(vw, mapva, size, envi.const.MM_RWX)
    vw.writeMemory(0x1000106E, bytes.fromhex("68 79 10 00 10 FF 25 08 20 00 10"))
    vw.clearOpcache()
    assert vw.parseOpcode(0x1000106E).mnem == "push"
    assert vw.parseOpcode(0x10001073).mnem == "jmp"
    protect_memory(vw, mapva, size, perms)

    emu = vw.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)
    hk = CreateMutexAHook()
    drv.add_hook(hk)

    drv.setProgramCounter(0x10001067)
    drv.stepi()
    drv.stepi()
    drv.stepi()
    drv.stepi()
    assert drv.parseOpcode(drv.getProgramCounter()).mnem == "jmp"
    drv.stepi()
    assert drv.getProgramCounter() == 0x10001079
    assert "SADFHUHF" in hk.mutexes


def test_dbg_driver_max_insn(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    with pytest.raises(vudrv.InstructionRangeExceededError):
        drv.run(max_instruction_count=1)
    assert drv.getProgramCounter() == 0x10001343


def test_dbg_driver_bp(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    drv.breakpoints.add(0x10001344)
    with pytest.raises(vudrv.BreakpointHit):
        drv.run()
    assert drv.getProgramCounter() == 0x10001344


def test_dbg_driver_until_mnem(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    with pytest.raises(vudrv.BreakpointHit):
        drv.run_to_mnem(["call"])
    assert drv.getProgramCounter() == 0x10001345


def test_dbg_driver_until_va(pma01):
    emu = pma01.getEmulator()
    drv = vudrv.DebuggerEmulatorDriver(emu)

    # .text:10001342 57                      push    edi
    # .text:10001343 56                      push    esi             ; fdwReason
    # .text:10001344 53                      push    ebx             ; hinstDLL
    # .text:10001345 E8 C6 FC FF FF          call    DllMain (0x10001010)
    # .text:1000134A 83 FE 01                cmp     esi, 1
    drv.setProgramCounter(0x10001342)
    with pytest.raises(vudrv.BreakpointHit):
        drv.run_to_va(0x10001344)
    assert drv.getProgramCounter() == 0x10001344
