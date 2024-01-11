rule Hunting_Triangledb_ModKeychain_Strdec {
    meta:
        author = "@captainGeech42"
        description = "Look for the string decryption routine code in TriangleDB's keychain stealing module."
        date = "2024-01-06"
        version = "1"
        DaysofYARA = "6/100"
        reference = "https://securelist.com/triangulation-validators-modules/110847/"
        hash = "64f36b0b8ef62634a3ec15b4a21700d32b3d950a846daef5661b8bbca01789dc"
    strings: 
        // in this rule (vs day 5), im doing some insn wildcarding to try and hit more broadly
        // this is...not as easy as CISC architectures lol
        // great easy reference on how arm data processing instructions are encoded: https://alisdair.mcdiarmid.org/arm-immediate-value-encoding/
        // and the online arm instruction reference: https://developer.arm.com/documentation/ddi0602/2023-12/Base-Instructions/

        $c1 = {
            // __text:000000010000A360 A8 03 5F F8                 LDUR            X8, [X29,#var_10]
            a8 ?? ?f f8
            // __text:000000010000A364 E9 07 80 B9                 LDRSW           X9, [SP,#0x30+var_2C]
            e9 ?? ?0 b9
            // __text:000000010000A368 0A 69 69 38                 LDRB            W10, [X8,X9]
            0a 69 69 38
            // __text:000000010000A36C E8 0F 40 F9                 LDR             X8, [SP,#0x30+var_18]
            e8 0? ?0 f9
            // __text:000000010000A370 E9 07 80 B9                 LDRSW           X9, [SP,#0x30+var_2C]
            e9 ?? ?0 b9
            // __text:000000010000A374 0B 69 69 38                 LDRB            W11, [X8,X9]
            0B 69 69 38
            // __text:000000010000A378 4A 01 0B 4A                 EOR             W10, W10, W11
            4a 01 0B 4a
            // __text:000000010000A37C EB 07 40 B9                 LDR             W11, [SP,#0x30+var_2C]
            eb 0? ?0 b9
            // __text:000000010000A380 4A 01 0B 4A                 EOR             W10, W10, W11
            4a 01 0b 4a
            // __text:000000010000A384 E8 07 40 F9                 LDR             X8, [SP,#0x30+var_28]
            e8 0? ?0 f9
            // __text:000000010000A388 E9 07 80 B9                 LDRSW           X9, [SP,#0x30+var_2C]
            e9 ?? ?0 b9
            // __text:000000010000A38C 08 01 09 8B                 ADD             X8, X8, X9
            08 01 09 8b
            // __text:000000010000A390 0A 01 00 39                 STRB            W10, [X8]
            0a 01 00 39
            // __text:000000010000A394 E8 07 40 B9                 LDR             W8, [SP,#0x30+var_2C]
            e8 0? ?0 b9
            // __text:000000010000A398 08 05 00 11                 ADD             W8, W8, #1
            08 05 00 11
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