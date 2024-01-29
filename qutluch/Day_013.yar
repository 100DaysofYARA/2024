import "elf"

rule HUNT_ELF_NPS_PROXY_CLIENT_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find staticlly nps ELF files."
        reference   = "https://github.com/ehang-io/nps/"

        DaysofYARA  = "13/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

    strings:
        $ = "ehang.io/nps"
        $ = "go/pkg/mod/ehang.io/nps-mux@v"
        $ = "nps_mux."
        $ = "nps/nps/lib"
        $ = "nps/nps/client"
        $ = "npc.go"

    condition:
        uint32(0) == 0x464c457f
        and 10 of them
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
