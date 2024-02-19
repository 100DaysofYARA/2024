rule Dalvik {
    meta:
        description = "Dalvik (dex) compiled files"
        author = "@larsborn"
        date = "2024-02-18"
        reference = "https://source.android.com/docs/core/runtime/dex-format"
        example_hash = "f8718170a98298e56a962e1f12e34c1190535fc93a2523fe1be345db4631e788"

        DaysofYARA = "23/100"
    condition:
        uint32be(0) == 0x6465780a // "dex\n"
        and for all i in ( 1 .. 3 ) : ( // three digits
            uint16(3 + i) & 0xff >= 0x30 and uint16(3 + i) & 0xff <= 0x39
        )
        and uint16(7) & 0xff == 0x0 // null byte "\0"
        and uint32(0x20) == filesize // file size check
}
