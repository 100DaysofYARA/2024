rule MAL_PE_PROXY_DLL_LOADS_TpAllocTimer_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule red team Proxy-DLL-Load."

        reference   = "https://github.com/kleiton0x00/Proxy-DLL-Loads"

        DaysofYARA  = "14/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

    strings:
        $ = {48 89 d3 48 8b 03 48 8b 4b 08 ff e0}

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and all of them
}

rule MAL_PE_PROXY_DLL_LOADS_TpAllocTimer_2
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule red team Proxy-DLL-Load."

        reference   = "https://github.com/kleiton0x00/Proxy-DLL-Loads"

        DaysofYARA  = "14/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

    strings:
        $ = {4889d3488b03488b4b08ffe0}
        $ = "LoadLibraryA"

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and all of them
}
