rule MAL_ELF_SEATURTLE_SNAPPYTCP_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to detect SNAPPYTCP used by Sea Turtle."
        reference   = "https://www.pwc.com/gx/en/issues/cybersecurity/cyber-threat-intelligence/tortoise-and-malwahare.html"

        DaysofYARA  = "17/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

        hash        = "3c9e4ba1278b751c24f03ba39cb317b1bc51d2dc5173b0a0b201bc62fdc2c6fd"

    strings:
        $s1 = "./kdd_launch exec:'bash"
        $s2 = "GET /sy.php"
        $h1 = {
            eb ??                // 0x00400d8b: jmp 0x400d90                        (eb 03)
            8b 45 f4             // 0x00400d8d: mov eax, dword [rbp - 0xc]          (8b 45 f4)
            c9                   // 0x00400d90: leave                               (c9)
            c3                   // 0x00400d91: ret                                 (c3)
            55                   // 0x00400d92: push rbp                            (55)
            48 89 e5             // 0x00400d93: mov rbp, rsp                        (48 89 e5)
            48 81 ec 30 01 ?? ?? // 0x00400d96: sub rsp, 0x130                      (48 81 ec 30 01 00 00)
            48 89 bd d8 fe ff ff // 0x00400d9d: mov qword [rbp - 0x128], rdi        (48 89 bd d8 fe ff ff)
            89 b5 d4 fe ff ff    // 0x00400da4: mov dword [rbp - 0x12c], esi        (89 b5 d4 fe ff ff)
            8b 85 d4 fe ff ff    // 0x00400daa: mov eax, dword [rbp - 0x12c]        (8b 85 d4 fe ff ff)
            89 85 f0 fe ff ff    // 0x00400db0: mov dword [rbp - 0x110], eax        (89 85 f0 fe ff ff)
            48 8b 85 d8 fe ff ff // 0x00400db6: mov rax, qword [rbp - 0x128]        (48 8b 85 d8 fe ff ff)
            48 8d 95 f0 fe ff ff // 0x00400dbd: lea rdx, [rbp - 0x110]              (48 8d 95 f0 fe ff ff)
            48 83 c2 04          // 0x00400dc4: add rdx, 4                          (48 83 c2 04)
            48 89 c6             // 0x00400dc8: mov rsi, rax                        (48 89 c6)
            48 89 d7             // 0x00400dcb: mov rdi, rdx                        (48 89 d7)
        }

    condition:
        uint32(0) == 0x464c457f
        and (all of ($s*) or $h1)
}
