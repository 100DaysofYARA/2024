rule SUSP_LNK_Contains_PE_DOS_Stub
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" nocase ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}

rule SUSP_LNK_Contains_PE_DOS_Stub_b64
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" base64 base64wide
        $ = "!This Program Cannot be Run in DOS Mode" base64 base64wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}

rule SUSP_LNK_Contains_PE_DOS_Stub_xor
{
    meta:
        author = "Greg Lesnewich"
        description = "detect LNKs that contain an MS-DOS stub indicating there is likely an embedded PE file"
        reference = "https://osandamalith.com/2020/07/19/exploring-the-ms-dos-stub/"
        date = "2024-02-03"
        version = "1.0"
        DaysOfYara = "34/100"
    strings:
        $ = "!This program cannot be run in DOS mode" xor(0x01-0xff) ascii wide
        $ = "!This Program Cannot be Run in DOS Mode" xor(0x01-0xff) ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and
        1 of them
}
