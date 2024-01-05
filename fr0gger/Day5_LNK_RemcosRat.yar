rule LNK_File_CheckAV {
    meta:
        description = "Check LNK file checking for Defender installed. Domain used with RemcosRat delivery"
        author = "Thomas Roccia | @fr0gger_"
        reference = "https://www.uptycs.com/blog/remcos-rat-uac-0500-pipe-method"
        sample = "f650a9f1930e55e405d7121c56b90a996ab213a05b772a8f02ceb1cdbeb91165"
    strings:
        $s1 = "powershell.exe" ascii wide
        $s2 = "AntiVirusProduct" ascii wide
        $s3 = "-replace 'Windows Defender'" ascii wide
        $s4 = "new-tech-savvy.com" ascii wide
    condition:
        uint16(0) == 0x004c and 2 of them
}
