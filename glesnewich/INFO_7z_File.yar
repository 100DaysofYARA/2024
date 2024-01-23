rule INFO_7z_File
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-22"
        version = "1.0"
        DaysOfYara = "22/100"

    condition:
        uint16be(0x0) == 0x377A
}
