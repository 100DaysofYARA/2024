import "elf"

rule HUNT_ELF_FREEBSD_ARM_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find staticlly compiled FreeBSD ARM binaries."

        DaysofYARA  = "12/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"

    condition:
        uint32(0) == 0x464c457f
        and uint16(0x7) == 0x9
        and uint16(0x12) == 0x28
        and
        (
            for all i in (0..elf.number_of_segments-1):
            (
                elf.segments[i].type != elf.PT_DYNAMIC
                and
                elf.segments[i].type != elf.PT_INTERP
            )
        )
}
