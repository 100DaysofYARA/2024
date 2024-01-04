// requires yara-x or yara with mach-o module enabled

import "elf"
import "macho"

rule TTP_lang_go {
    meta:
        author = "@captainGeech42"
        description = "Look for binaries written in Go based on section/segment names or strings. Requires the `macho` module."
        date = "2024-01-02"
        version = "1"
        DaysofYARA = "2/100"

    strings:
        $s1 = " Go build ID: "
        $s2 = "CGO_ENABLED"
        $s3 = "GOOS"
        $s4 = "GOARCH"
        $s5 = "runtime.morestack_noctxt" 
        $s6 = "gopkg.in"

    condition:
        // each of these format-specific blocks looks for one of the following:
        //   - a relevant section name
        //   - a minimum number of relevant strings

        (
            uint32(0) == 0x464c457f and
            (
                for any section in elf.sections : (
                    section.name == ".gopclntab" or section.name == ".go.buildinfo"
                ) or
                4 of them
            )
        ) or (
            // PE files from golang don't have special section names
            uint16(0) == 0x5a4d and
            uint32(uint32(0x3c)) == 0x00004550 and
            4 of them
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
                        segment.cmd == 25 and segment.segname == "__TEXT" and
                        for any section in segment.sections : (
                            section.sectname == "__gosymtab" or section.sectname == "__gopclntab"
                        )
                    )
                ) or
                4 of them
            )
        )
}