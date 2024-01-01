rule TTP_lang_nim {
    meta:
        author = "@captainGeech42"
        date = "2024-01-01"
        desc = "Look for binaries written in Nim."
    strings:
        $s1 = "NimMainModule"
        $s2 = "cmdLine"
        $s3 = "cmdCount"
        $s4 = "gEnv"
        $s5 = "nim_program_result"
        $s6 = ".nim"
        $s7 = "dotdotat"
    condition:
        ($s1 or $s5) and ($5 of them)
}