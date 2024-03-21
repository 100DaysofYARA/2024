rule MAL_ChaosRansom_strings {
    meta:
        description = "Matches function name strings found in Chaos ransomware samples."
        last_modified = "2024-03-19"
        author = "@petermstewart"
        DaysofYara = "79/100"
        sha256 = "1ba5ab55b7212ba92a9402677e30e45f12d98a98f78cdcf5864a67d6c264d053"
        sha256 = "a98bc2fcbe8b3c7ea9df3712599a958bae0b689ae29f33ee1848af7a038d518a"

    strings:
        $a1 = "encryptionAesRsa"
        $a2 = "encryptedFileExtension"
        $a3 = "checkdeleteShadowCopies"
        $a4 = "checkdisableRecoveryMode"
        $a5 = "bytesToBeEncrypted"

    condition:
        uint16(0) == 0x5a4d and
        4 of them
}
