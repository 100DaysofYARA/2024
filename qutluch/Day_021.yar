rule APT_TURLA_POWERSHELL_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find Turla Powershell."

        DaysofYARA  = "21/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-30"
        version     = "1.0"

        hash        = "ffe2d3b35631df7d7ede8cf037d503e6e0b8771105dbf96828d11d0ddd62b7f3"

    strings:
        $sa1    = "Parameter"
        $sa2    = "function"
        $sa3    = "env:ALLUSERSPROFILE"
        $sa4    = "ServiceDLL"
        $sa5    = "Get-Item"
        $sa6    = "New-Service"
        $sa7    = "[string[]]"
        $sa8    = "[string]"

    condition:
        uint16(0) != 0x5A4D
        and all of them
}
