import "elf"

rule HUNT_ELF_FREEBSD_GOLANG_KERNEL_MODULE_1
{
    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to surface FreeBSD kernel modules built with Golang."

        DaysofYARA  = "30/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

    strings:
        // Thanks to captainGeech42 for his Golang rule.
        // https://github.com/100DaysofYARA/2024/blob/main/captainGeech/day002_golang.yara
        $golang1 = " Go build ID: "
        $golang2 = "CGO_ENABLED"
        $golang3 = "GOOS"
        $golang4 = "GOARCH"
        $golang5 = "runtime.morestack_noctxt"
        $golang6 = "gopkg.in"

        $f1     = "module_register_init"

    condition:
        uint32(0) == 0x464c457f
        and uint16(0x7) == 0x9
        and
        (
            for any section in elf.sections : (
                section.name == ".gopclntab" or section.name == ".go.buildinfo"
            ) or
            4 of ($golang*)
        )
        and $f1
}
