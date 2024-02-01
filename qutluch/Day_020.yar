rule SUSP_DOCX_VBA_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find suspicious VBA documents."

        DaysofYARA  = "20/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-30"
        version     = "1.0"

    strings:
        $sa1    = "VBA6" fullword
        $sa2    = "VBA7" fullword

        $sb1    = "_VBA_PROJECT" wide
        $sb2    = "Declare"
        $sb3    = "Function"
        $sb4    = "PtrSafe"

        $sc1    = "kernel32.dll"
        $sc2    = "GetProcAddress"
        $sc3    = "LoadLibrary"
        $sc4    = "FreeLibrary"
        $sc5    = "NtWriteVirtualMemory"
        $sc6    = "NtAllocateVirtualMemory"
        $sc7    = "NtProtectVirtualMemory"
        $sc8    = "VirtualAlloc"
        $sc9    = "VirtualProtect"

    condition:
        uint32be(0) == 0xd0cf11e0
        and any of ($sa*)
        and all of ($sb*)
        and 4 of ($sc*)
}
