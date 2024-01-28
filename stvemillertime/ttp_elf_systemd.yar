rule ttp_elf_systemd_1 {
    meta:
        author = "stvemillertime"
        desc = "ELF EXECs with systemd string."
        ref = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592" // fysbis
        ref = "3a1b174f0c19c28f71e1babde01982c56d38d3672ea14d47c35ae3062e49b155" // bpfdoor
        ref = "4837be90842f915e146bf87723e38cc0533732ba1a243462417c13efdb732dcb" // alchemist
        ref = "3876b58d12e27361bdfebd6efc5423d79b6676ca3b9d800f87098e95c3422e84" // teamtnt
     strings:
        $s0 = "systemd" nocase fullword
        $s1 = "/systemd/" xor (0x01-0xff)
        $s2 = "/systemd/" base64
        $z0 = "snapctl.go"
        $z1 = "snap-exec/main.go"
        $z2 = "snap-update-ns/main.go"
        $z3 = "<common xclusions etc>"
    condition:
        uint16be(0) == 0x7f45
        and (uint16be(0x10) == 0x0002 or uint8be(0x10) == 0x02) // ET_EXEC
        and 1 of ($s*)
        and not any of ($z*)
}