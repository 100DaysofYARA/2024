rule MAL_Lckmac_strings {
    meta:
        description = "Matches function name strings found in MachO ransomware sample uploaded to VirusTotal with filename 'lckmac'."
        last_modified = "2024-03-16"
        author = "@petermstewart"
        DaysofYara = "76/100"
        sha256 = "e02b3309c0b6a774a4d940369633e395b4c374dc3e6aaa64410cc33b0dcd67ac"
        ref = "https://x.com/malwrhunterteam/status/1745144586727526500"

    strings:
        $a1 = "main.parsePublicKey"
        $a2 = "main.writeKeyToFile"
        $a3 = "main.getSystemInfo"
        $a4 = "main.EncryptTargetedFiles"
        $a5 = "main.shouldEncryptFile"
        $a6 = "main.encryptFile"
        $a7 = "main.deleteSelf"

    condition:
        (uint32(0) == 0xfeedface or     //MH_MAGIC
        uint32(0) == 0xcefaedfe or      //MH_CIGAM
        uint32(0) == 0xfeedfacf or      //MH_MAGIC_64
        uint32(0) == 0xcffaedfe or      //MH_CIGAM_64
        uint32(0) == 0xcafebabe or      //FAT_MAGIC
        uint32(0) == 0xbebafeca) and    //FAT_CIGAM
        all of them
}
