rule MAL_PE_PROXY_DLL_LOADS_VEH_DLL_PROXY_LOAD_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule red team Proxy-DLL-Load."

        reference   = "https://github.com/kleiton0x00/Proxy-DLL-Loads"

        DaysofYARA  = "15/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

    strings:
        $ = "AddVectoredExceptionHandler"
        $ = "kernel32.dll"
        $ = "LoadLibraryA"
        $ = "VirtualProtect"
        $ = "RemoveVectoredExceptionHandler"
        $ = {488b530848894278488b4b08488b4178488981f8}

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and all of them
}
