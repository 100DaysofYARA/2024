rule TTP_lang_rust {
    meta:
        author = "@captainGeech42"
        description = "Look for binaries written in Rust."
        date = "2024-01-04"
        version = "1"
        DaysofYARA = "4/100"

        hash = "073c7ab50e0f32a9b3eaccc1a2a7b0510c98dd2fdbfac0ac093a0bf22028703d" // elf
        hash = "1666a6bf36a10dfeb736785af29f01a5e75f3e84cf86a561f01aea63b4293b87" // pe

    strings:
        $s1 = "/rustc/"
        $s2 = "/library/core/src/"
        $s3 = "/library/std/src/"
        $s4 = "\\library\\core\\src"
        $s5 = "\\library\\std\\src"
        $s6 = "/rust/deps"

    condition:
        (
            uint32(0) == 0x464c457f and
            (#s1 + #s2 + #s3 + #s6) > 15
        ) or (
            uint16(0) == 0x5a4d and
            uint32(uint32(0x3c)) == 0x00004550 and
            (#s1 + #s4 + #s5 + #s6) > 15
        )
}