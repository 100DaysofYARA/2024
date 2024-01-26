import "pe"

rule TTP_VirtualAlloc_RWX_tight_1 {
    meta:
        author = "@captainGeech42,@stvemillertime"
        description = "Look for PE files that make RWX calls to VirtualAlloc (xref'd against IAT entry)"
        date = "2024-01-24"
        version = "1"
        DaysofYARA = "23/100"
    strings:
        // .text:00412846 8B F4                             mov     esi, esp
        // .text:00412848 6A 40                             push    40h ; '@'       ; flProtect
        // .text:0041284A 68 00 30 00 00                    push    3000h           ; flAllocationType
        // .text:0041284F 68 00 10 00 00                    push    1000h           ; dwSize
        // .text:00412854 6A 00                             push    0               ; lpAddress
        // .text:00412856 FF 15 00 E0 41 00                 call    ds:VirtualAlloc
        $c_32_1 = {6a40 6800??0000 [4-20] ff15}
    condition:
        // PE file hdr, Magic value determines 32-bit or 64-bit PE file
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header32?redirectedfrom=MSDN#members

        uint16be(0) == 0x4d5a and (
            uint16(uint32(0x3c)+0x18) == 0x10b and // IMAGE_NT_OPTIONAL_HDR32_MAGIC
            $c_32_1 and
            for any imp in pe.import_details : (
                imp.library_name == "KERNEL32.dll" and
                for any func in imp.functions : (
                    func.name == "VirtualAlloc" and
                    uint32(@c_32_1+!c_32_1)&0xfffff == func.rva // only match last 5 nibbles
                )
            )
        )
}