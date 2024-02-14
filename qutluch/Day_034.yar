import "elf"

rule HUNT_ELF_COATHANGER_1
{
    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find samples of COATHANGER"
        reference   = "https://www.ncsc.nl/binaries/ncsc/documenten/publicaties/2024/februari/6/mivd-aivd-advisory-coathanger-tlp-clear/mivd-advisory-coathanger-tlp-clear.pdf"

        DaysofYARA  = "34/100"

        license     = "BSD-2-Clause"
        date        = "2024-02-08"
        version     = "1.0"

    condition:
        uint32(0) == 0x464c457f
        and elf.type == elf.ET_DYN
        and elf.dynsym_entries > 0
        and elf.dynsym_entries < 100
        and for 5 dynsym in elf.dynsym : (
            (
                dynsym.name == "fdopendir"
                or dynsym.name == "fstat"
                or dynsym.name == "fstat64"
                or dynsym.name == "lstat"
                or dynsym.name == "lstat64"
                or dynsym.name == "open"
                or dynsym.name == "opendir"
                or dynsym.name == "readdir"
                or dynsym.name == "readdir64"
                or dynsym.name == "rmdir"
                or dynsym.name == "stat"
                or dynsym.name == "stat64"
                or dynsym.name == "unlink"
                or dynsym.name == "unlinkat"
            )
            and dynsym.size > 0
            and dynsym.type  == 2
            and dynsym.bind  == 1
        )
}
