rule APLib_Strings
{
    meta:
        description = "String appearing in the aPLib compression library"
        author = "@larsborn"
        created_at = "2021-01-16"
        example_hash_01 = "24d07f23b496198dd1a2d41978753b71a2ed12c6c00fbc4ff4feac12664f12d5"
        reference = "https://web.archive.org/web/20220705162938/https://0xc0decafe.com/malware-analysts-guide-to-aplib-decompression/"

        DaysofYARA = "1/100"
    strings:
        $ = "aPLib v1.1.1 – the smaller the better :)"
        $ = "Copyright (c) 1998-2014 Joergen Ibsen, All Rights Reserved."
        $ = "More information: http://www.ibsensoftware.com/"
    condition:
        any of them
}
