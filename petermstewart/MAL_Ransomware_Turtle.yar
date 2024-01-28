rule MAL_TurtleRansom_strings {
    meta:
        description = "Matches strings found in Windows, ELF, and MachO Turtle ransomware samples."
        last_modified = "2024-01-26"
        author = "@petermstewart"
        DaysofYara = "26/100"
        sha256 = "b384155b74845beeea0f781c9c216c69eceb018520d819dd09823cff6ef0e7de"
        sha256 = "f5b9b80f491e5779f646d2510a2c9c43f3072c45302d271798c4875544ace4f2"
        sha256 = "df5f7570bf0b1f99f33c31913ab9f25b9670286e8e2462278aea2157f8173a68"
        sha256 = "b5ab9c61c81dfcd2242b615c9af2cb018403c9a784b7610b39ed56222d669297"
        sha256 = "a4789e0b79a8bac486fbc3b0f00b6dcbaac6854e621d40fc3005d23f83d2e5ec"
        sha256 = "5f9cd91d8d1dcfe2f6cf4c6995ad746694ce57023dfb82b1cd6af5697113d1b0"
        sha256 = "a48af4a62358831fe5376aa52db1a3555b0c93c1665b242c0c1f49462f614c56"
        sha256 = "62f84afdab28727ab47b5c1e4af92b33dc2b11e55dca7b097fe94da5bcc9ec4e"
        sha256 = "f14ef1c911deb8714d1bb501064505c13237049ac51f0a657da4b0bf11f5f59e"
        sha256 = "65eea957148d75c29213dff0c5465c6dc1db266437865538cfe8744c2436f5e1"
        sha256 = "00b52a5905e042a9a9f365f7e5404f420ae26f463f24c069d6076e9094f61a8e"
        sha256 = "52337055cca751b8b2b716a1c8f3ba179ddd74b268b67641ade223d3d3cf773d"
        ref = "https://objective-see.org/blog/blog_0x76.html"

    strings:
        $a1 = "D:/VirTest/TurmiRansom/main.go"
        $a2 = "VirTest/TurmiRansom"
        $a3 = "TurmiRansom/main.go"
        $b1 = "TURTLERANSv0"
        $b2 = "wugui123"
        $b3 = "main..inittask"
        $b4 = "main.en0cr0yp0tFile"
        $b5 = "main.main"
        $b6 = "main.main.func1"

    condition:
        (uint16(0) == 0x5a4d or         //PE
        uint32(0) == 0x464c457f or      //ELF
        uint32(0) == 0xfeedface or      //MH_MAGIC
        uint32(0) == 0xcefaedfe or      //MH_CIGAM
        uint32(0) == 0xfeedfacf or      //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or      //MH_CIGAM_64
        uint32(0) == 0xcafebabe or      //FAT_MAGIC
        uint32(0) == 0xbebafeca) and    //FAT_CIGAM
        2 of ($a*) and
        all of ($b*)
}
