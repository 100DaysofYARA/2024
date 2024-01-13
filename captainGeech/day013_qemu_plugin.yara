import "elf"

rule Hunting_qemu_plugin {
    meta:
        author = "@captainGeech42"
        description = "Hunt for QEMU plugins"
        date = "2024-01-13"
        version = "1"
        DaysofYARA = "13/100"
    condition:
        uint32be(0) == 0x7f454c46 and
        for 2 sym in elf.symtab : (
            (
                sym.name == "qemu_plugin_install" and
                sym.type == elf.STT_FUNC
            ) or (
                sym.name == "qemu_plugin_version" and
                sym.type == elf.STT_OBJECT
            )
        )
}