rule TTP_lang_nim {
    meta:
        author = "@captainGeech42"
        description = "Look for binaries written in Nim."
        date = "2024-01-01"
        version = "1"
        DaysofYARA = "1/100"
    strings:
        $s1 = "NimMainModule"
        $s2 = "cmdLine"
        $s3 = "cmdCount"
        $s4 = "gEnv"
        $s5 = "nim_program_result"
        $s6 = ".nim"
        $s7 = "dotdotat"
    condition:
        ($s1 or $s5) and (5 of them)
}