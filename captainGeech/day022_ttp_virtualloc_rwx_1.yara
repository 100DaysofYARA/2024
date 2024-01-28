rule TTP_VirtualAlloc_RWX_loose_1 {
    meta:
        author = "@captainGeech42,@stvemillertime"
        description = "Look for PE files that make plausible calls to VirtualAlloc with RWX permissions (based on arg setup+call insn)"
        date = "2024-01-24"
        version = "1"
        DaysofYARA = "22/100"
    strings:
        // .text:00412846 8B F4                             mov     esi, esp
        // .text:00412848 6A 40                             push    40h ; '@'       ; flProtect
        // .text:0041284A 68 00 30 00 00                    push    3000h           ; flAllocationType
        // .text:0041284F 68 00 10 00 00                    push    1000h           ; dwSize
        // .text:00412854 6A 00                             push    0               ; lpAddress
        // .text:00412856 FF 15 00 E0 41 00                 call    ds:VirtualAlloc
        $c_32_1 = {6a40 6800300000 [4-20] ff15}

        // .text:00000001400126BF 41 B9 40 00 00 00         mov     r9d, 40h ; '@'  ; flProtect
        // .text:00000001400126C5 41 B8 00 30 00 00         mov     r8d, 3000h      ; flAllocationType
        // .text:00000001400126CB BA 00 10 00 00            mov     edx, 1000h      ; dwSize
        // .text:00000001400126D0 33 C9                     xor     ecx, ecx        ; lpAddress
        // .text:00000001400126D2 FF 15 F8 19 01 00         call    cs:__imp_VirtualAlloc
        $c_64_1 = {41b940000000 41b800300000 [4-20] ff15}
    condition:
        // PE file hdr, Magic value determines 32-bit or 64-bit PE file
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32?redirectedfrom=MSDN#members

        uint16be(0) == 0x4d5a and (
            (
                // 32-bit
                uint16(uint32(0x3c)+0x18) == 0x10b and // IMAGE_NT_OPTIONAL_HDR32_MAGIC
                any of ($c_32_*)
            ) or (
                // 64-bit
                uint16(uint32(0x3c)+0x18) == 0x20b and // IMAGE_NT_OPTIONAL_HDR64_MAGIC
                any of ($c_64_*)
            )
        )
}