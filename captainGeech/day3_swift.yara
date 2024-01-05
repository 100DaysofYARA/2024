// requires yara-x or yara with mach-o module enabled

import "elf"
import "macho"

rule TTP_lang_swift {
    meta:
        author = "@captainGeech42"
        description = "Look for binaries written in Swift based on symbols or imports."
        date = "2024-01-03"
        version = "1"
        DaysofYARA = "3/100"

        hash = "f2b2a07db11a8ccc3f7431c94130a48e746c1aa2129d9e805f4d6bb4d1fc422f" // macho
        hash = "9b2c332251e660db11d6e6e6b36fa60160973700501c7c48b1739ee43a25e8d9" // elf

    condition:
        (
            uint32(0) == 0x464c457f and (
                for 2 sym in elf.dynsym : (
                    sym.name == "swift_bridgeObjectRelease" or
                    sym.name == "swift_release" or
                    sym.name == "_swift_backtrace_isThunkFunction" or
                    sym.name == "swift_retain" or
                    sym.name == "swift_allocObject"
                )
            )
        ) or (
            (
                uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
                uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
                uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
                uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
                uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
                uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
            ) and (
                (
                    for any segment in macho.segments : (
                        segment.cmd == 25 and segment.segname == "__DATA" and
                        for any section in segment.sections : (
                            section.sectname == "__swift_hooks"
                        )
                    )
                ) or
                for any dylib in macho.dylibs : (
                    dylib.name endswith "libswiftCore.dylib"
                )
            )
        )
}