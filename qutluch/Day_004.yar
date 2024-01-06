rule HUNT_PEDLL_WinDivertDriverInstallMutex_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to dragnet files referencing the WinDivertFilter mutex.."
        disclaimer  = "This rule is a basis for hunting rules and does not denote a suspicious file by itself."
        reference   = "https://github.com/basil00/Divert/blob/97101072dbe31d744ca3429da389350a3df39e18/dll/windivert.c#L306"

        DaysofYARA  = "4/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-04"
        version     = "1.0"

    strings:
        $ = "WinDivertDriverInstallMutex" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and (uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000
        and all of them
        and filesize < 3MB
}
