rule Hunting_pwntools {
    meta:
        author = "@captainGeech42"
        description = "Hunt for pwntools-based exploit scripts"
        date = "2024-01-12"
        version = "1"
        DaysofYARA = "12/100"
    strings:
        $imp1 = "import pwn" fullword
        $imp2 = "from pwn import *" fullword

        $s1 = "u32("
        $s2 = "u64("
        $s3 = "p32("
        $s4 = "p64("
        $s5 = "remote("
        $s6 = "process("
        $s7 = "recvline("
        $s8 = "recvuntil("
        $s9 = "context"
        $s10 = "interactive("
        $s11 = "pwnlib"
        $s12 = "gdb.attach"

        $fp1 = "<html>"
    condition:
        (
            $imp1 in (0..100) or
            $imp2 in (0..100)
        ) and
        (
            5 of ($s*)
        ) and
        (not $fp1 or $fp1 in (100..filesize))
}