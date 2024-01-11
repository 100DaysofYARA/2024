rule Hunting_Triangledb_Mod_Strdec {
    meta:
        author = "@captainGeech42"
        description = "Look for the string decryption routine code in TriangleDB's SMS stealing and mic listening modules."
        date = "2024-01-08"
        version = "1"
        DaysofYARA = "8/100"
        reference = "https://securelist.com/triangulation-validators-modules/110847/"
        hash = "c2393fceab76776e19848c2ca3c84bea0ed224ac53206c48f1c5fd525ef66306"
    strings: 
        $c1 = {
            // __text:00000001000099CC 08 00 80 52                 MOV             W8, #0
            08008052
            // __text:00000001000099D0 29 00 40 39                 LDRB            W9, [X1]
            29004039
            // __text:00000001000099D4 29 1D 18 33                 BFI             W9, W9, #8, #8
            291d1833
            // __text:00000001000099D8 29 29 09 0B                 ADD             W9, W9, W9,LSL#10
            2929090b
            // __text:00000001000099DC 29 19 49 4A                 EOR             W9, W9, W9,LSR#6
            2919494a
            // __text:00000001000099E0 29 0D 09 0B                 ADD             W9, W9, W9,LSL#3
            290d090b
            // __text:00000001000099E4 29 2D 49 4A                 EOR             W9, W9, W9,LSR#11
            292d494a
            // __text:00000001000099E8 29 3D 09 0B                 ADD             W9, W9, W9,LSL#15
            293d090b
            // __text:00000001000099EC 0A 05 00 11                 ADD             W10, W8, #1
            0a050011
            // __text:00000001000099F0 2B 48 6A 38                 LDRB            W11, [X1,W10,UXTW]
            2b486a38
            // __text:00000001000099F4 6B 01 09 4A                 EOR             W11, W11, W9
            6b01094a
            // __text:00000001000099F8 0B 48 28 38                 STRB            W11, [X0,W8,UXTW]
            0b482838
            // __text:00000001000099FC E8 03 0A AA                 MOV             X8, X10
            e8030aaa
            // __text:0000000100009A00 6A 1D 00 72                 ANDS            W10, W11, #0xFF
            6a1d0072
            // __text:0000000100009A04 29 01 0A 4A                 EOR             W9, W9, W10
            29010a4a
        }
        
    condition:
        (
            uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
            uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
            uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
            uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
            uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
            uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
        ) and (
            filesize < 2MB and
            all of them
        )
}