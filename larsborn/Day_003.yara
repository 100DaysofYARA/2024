rule REvil_ApiHashing
{
    meta:
        description = "API Hashing method in REvil / Sodinokibi"
        author = "@larsborn"
        created_at = "2021-03-27"
        example_hash_01 = "12d8bfa1aeb557c146b98f069f3456cc8392863a2f4ad938722cd7ca1a773b39"
        example_hash_02 = "5f56d5748940e4039053f85978074bde16d64bd5ba97f6f0026ba8172cb29e93"

        DaysofYARA = "3/100"
    strings:
        $ = {
            55                // U       push  ebp
            8B EC             // ..      mov   ebp, esp
            8B 55 08          // .U.     mov   edx, dword ptr [ebp + 8]
            6A 2B             // j+      push  0x2b
            58                // X       pop   eax
            EB 0C             // ..      jmp   0x17
            69 C0 0F 01 00 00 // i.....  imul  eax, eax, 0x10f
            42                // B       inc   edx
            0F B6 C9          // ...     movzx ecx, cl
            03 C1             // ..      add   eax, ecx
            8A 0A             // ..      mov   cl, byte ptr [edx]
            84 C9             // ..      test  cl, cl
            75 EE             // u.      jne   0xb
            5D                // ]       pop   ebp
            C3                // .       ret
        }
    condition:
        all of them
}
