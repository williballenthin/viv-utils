def remove_default_hooks(emu):
    # remove vivisect default emulation hooks which appear faulty/inconsistent, see e.g. vivisect issue #515
    for name in (
        "ntdll.seh3_prolog",
        "ntdll.seh4_prolog",
        "ntdll.seh4_gs_prolog",
        "ntdll.seh3_epilog",
        "ntdll.seh4_epilog",
        "ntdll.eh_prolog",
        "ntdll._alloca_probe",
        "ntdll.gs_prolog",
    ):
        if name in emu.hooks:
            del emu.hooks[name]
