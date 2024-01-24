rule ttp_elf_etc_paths_1 : ttp {
    meta: 
        author = "stvemillertime"
        desc = "Looks for ELF EXECs with some etc/ path strings that have to do with passwords n such"
        //yara rulesssss
    strings:
        $a05 = "etc/shadow" xor
        $a06 = "etc/passwd" xor
        $a07 = "etc/group" xor
        $a08 = "etc/nsswitch" xor 
        $a09 = "etc/shadow" base64 base64wide
        $a10 = "etc/passwd" base64 base64wide
        $a11 = "etc/group" base64 base64wide
        $a12 = "etc/nsswitch" base64 base64wide // .conf
        $z01 = "<exclusions go here>" // exclude common OS files & tooling
    condition:
        uint16be(0) == 0x7f45
        and (uint16be(0x10) == 0x0002 or uint8be(0x10) == 0x02) // ET_EXEC
        and 2 of ($a*)
        and not any of ($z*)
}