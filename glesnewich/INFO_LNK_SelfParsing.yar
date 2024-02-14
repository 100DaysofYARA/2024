rule INFO_LNK_References_WildCard_LNK_FileHandle
{
    meta:
        author = "Greg Lesnewich"
        description = "identify LNK files that might look for themselves, by referencing a wildcarded LNK filename"
        date = "2024-01-30"
        version = "1.0"
        DaysOfYara = "30/100"

    strings:
        $ = "*.lnk" ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}

rule INFO_LNK_SelfParsing_Findstr_LNK_FileHandle
{
    meta:
        author = "Greg Lesnewich"
        description = "identify LNK files that likely parse themselves looking for additional files or commands"
        date = "2024-01-30"
        version = "1.0"
        DaysOfYara = "30/100"

    strings:
        $ = ".lnk" ascii wide
        $ = "findstr" ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}
