rule MAL_PE_Stately_Taurus_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find Stately Taurus DLL."

        DaysofYARA  = "26/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-31"
        version     = "1.0"

        hash        = "2a00d95b658e11ca71a8de532999dd33ddee7f80432653427eaa885b611ddd87"
        hash        = "954b742d875402a5715b4260e04bcc83d91a67cef3ea6e71a0f16900b818b7a7"

    strings:
        $ = {
            0f 10 [5-6]
            a1 [4]
            56
            0f 11 (44|45)
            [50-100]
            66 0f 13 (44|45)
            [20-30]
            66 85 c0 74
        }

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x10b
        and (uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000
        and all of them
}
