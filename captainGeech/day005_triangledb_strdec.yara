rule Hunting_Triangledb_Strdec {
    meta:
        author = "@captainGeech42"
        description = "Look for the string decryption routine code snippet leveraged in TriangleDB."
        date = "2024-01-05"
        version = "1"
        DaysofYARA = "5/100"
        reference = "https://securelist.com/triangledb-triangulation-implant/110050/"
        hash = "fd9e97cfb55f9cfb5d3e1388f712edd952d902f23a583826ebe55e9e322f730f"
    strings:
        // xor logic
        $c1 = {
            // __text:000000010000E1F4 A8 02 1B 8B                 ADD             X8, X21, X27
            A8 02 1B 8B
            // __text:000000010000E1F8 09 01 40 39                 LDRB            W9, [X8]
            09 01 40 39
            // __text:000000010000E1FC A9 C3 19 38                 STURB           W9, [X29,#__str]
            A9 C3 19 38
            // __text:000000010000E200 08 05 40 39                 LDRB            W8, [X8,#1]
            08 05 40 39
            // __text:000000010000E204 A8 D3 19 38                 STURB           W8, [X29,#__str+1]
            A8 D3 19 38
            // __text:000000010000E208 A0 93 01 D1                 SUB             X0, X29, #-__str ; __str
            A0 93 01 D1
            // __text:000000010000E20C A1 83 01 D1                 SUB             X1, X29, #-__endptr ; __endptr
            A1 83 01 D1
            // __text:000000010000E210 02 02 80 52                 MOV             W2, #0x10 ; __base
            02 02 80 52
            // __text:000000010000E214 9B 65 01 94                 BL              _strtoul
            9B 65 01 94
            // __text:000000010000E218 A8 03 5A F8                 LDUR            X8, [X29,#__endptr]
            A8 03 5A F8
            // __text:000000010000E21C 1F 01 1C EB                 CMP             X8, X28
            1F 01 1C EB
            // __text:000000010000E220 A0 02 00 54                 B.EQ            loc_10000E274
            A0 02 00 54
            // __text:000000010000E224 7B 0B 00 91                 ADD             X27, X27, #2
            7B 0B 00 91
            // __text:000000010000E228 DA FD FF B4                 CBZ             X26, loc_10000E1E0
            DA FD FF B4
            // __text:000000010000E22C 08 00 19 4A                 EOR             W8, W0, W25
            08 00 19 4A
            // __text:000000010000E230 C8 6A 3A 38                 STRB            W8, [X22,X26]
            C8 6A 3A 38
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