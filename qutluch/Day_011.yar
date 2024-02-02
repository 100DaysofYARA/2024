rule MAL_PE_MOONBOUNCE_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule generated using MCRIT for code family MOONBOUNCE."
        reference   = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/01/19115831/MoonBounce_technical-details_eng.pdf"

        DaysofYARA  = "11/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"

    strings:
        // Rule generation selected 10 picblocks, covering 1/1 input sample(s).
        /* picblockhash: 0xc6a4421b3d81570f - coverage: 1/1 samples.
         * 06           | push es
         * fa           | cli
         * 2b2de62ec264 | sub ebp, dword ptr [0x64c22ee6]
         * 0133         | add dword ptr [ebx], esi
         * f9           | stc
         * 2a90a8dc30b5 | sub dl, byte ptr [eax - 0x4acf2358]
         * 1a6ab6       | sbb ch, byte ptr [edx - 0x4a]
         * 48           | dec eax
         * 7fb0         | jg 0xd6186e
         */
        $blockhash_0xc6a4421b3d81570f = {
            06 fa 2b2d???????? 0133 f9 2a90a8dc30b5 1a6ab6 48 7f??
        }

        /* picblockhash: 0xff1d8fb614f45beb - coverage: 1/1 samples.
         * ce         | into
         * a0643c64b3 | mov al, byte ptr [0xb3643c64]
         * 1d3d95635a | sbb eax, 0x5a63953d
         * 07         | pop es
         * 6b6bf4cd   | imul ebp, dword ptr [ebx - 0xc], -0x33
         * f1         | int1
         * c9         | leave
         * 3cf1       | cmp al, 0xf1
         * e3ce       | jecxz 0xd618a2
         */
        $blockhash_0xff1d8fb614f45beb = {
            ce a0???????? 1d3d95635a 07 6b6bf4cd f1 c9 3cf1 e3??
        }

        /* picblockhash: 0x56ba13fa97fe20b - coverage: 1/1 samples.
         * 33f9 | xor edi, ecx
         * 92   | xchg edx, eax
         * b5ca | mov ch, 0xca
         * 3901 | cmp dword ptr [ecx], eax
         * 47   | inc edi
         * 8801 | mov byte ptr [ecx], al
         * c3   | ret
         */
        $blockhash_0x56ba13fa97fe20b = {
            33f9 92 b5ca 3901 47 8801 c3
        }

        /* picblockhash: 0xf00d0d779418ea5 - coverage: 1/1 samples.
         * d406         | aam 6
         * c582b61ad0d0 | lds eax, ptr [edx - 0x2f2fe54a]
         * 24b4         | and al, 0xb4
         * 40           | inc eax
         * b169         | mov cl, 0x69
         * 3cc8         | cmp al, 0xc8
         * 11f6         | adc esi, esi
         * 3400         | xor al, 0
         * 7fb4         | jg 0xd619ea
         */
        $blockhash_0xf00d0d779418ea5 = {
            d406 c582b61ad0d0 24b4 40 b169 3cc8 11f6 3400 7f??
        }

        /* picblockhash: 0x353edfa272be4ef - coverage: 1/1 samples.
         * af     | scasd eax, dword ptr es:[edi]
         * 64d589 | aad 0x89
         * a7     | cmpsd dword ptr [esi], dword ptr es:[edi]
         * 8227fb | and byte ptr [edi], 0xfb
         * 1f     | pop ds
         * 0911   | or dword ptr [ecx], edx
         * a6     | cmpsb byte ptr [esi], byte ptr es:[edi]
         * c212e6 | ret 0xe612
         */
        $blockhash_0x353edfa272be4ef = {
            af 64d589 a7 8227fb 1f 0911 a6 c212e6
        }

        /* picblockhash: 0x416174c3dc803e2 - coverage: 1/1 samples.
         * 1206       | adc al, byte ptr [esi]
         * d9c4       | fld st(4)
         * b6ae       | mov dh, 0xae
         * 48         | dec eax
         * a835       | test al, 0x35
         * 4b         | dec ebx
         * e93cab3d8e | jmp 0x8f13c60c
         */
        $blockhash_0x416174c3dc803e2 = {
            1206 d9c4 b6ae 48 a835 4b e9????????
        }

        /* picblockhash: 0x9069437ae5684a02 - coverage: 1/1 samples.
         * ec     | in al, dx
         * 2b4dba | sub ecx, dword ptr [ebp - 0x46]
         * 6c     | insb byte ptr es:[edi], dx
         * 43     | inc ebx
         * 4c     | dec esp
         * e561   | in eax, 0x61
         * 0a6bfd | or ch, byte ptr [ebx - 3]
         * c3     | ret
         */
        $blockhash_0x9069437ae5684a02 = {
            ec 2b4dba 6c 43 4c e561 0a6bfd c3
        }

        /* picblockhash: 0xe94618df08470b78 - coverage: 1/1 samples.
         * d89ad42bcf11 | fcomp dword ptr [edx + 0x11cf2bd4]
         * 06           | push es
         * ef           | out dx, eax
         * 60           | pushal
         * 6329         | arpl word ptr [ecx], bp
         * fa           | cli
         * a1e70d429e   | mov eax, dword ptr [0x9e420de7]
         * b06e         | mov al, 0x6e
         * 8117d1d5a86a | adc dword ptr [edi], 0x6aa8d5d1
         * f8           | clc
         * 74c1         | je 0xd676db
         */
        $blockhash_0xe94618df08470b78 = {
            d89ad42bcf11 06 ef 60 6329 fa a1???????? b06e 8117d1d5a86a f8 74??
        }

        /* picblockhash: 0x8e8f21c3c3f1220f - coverage: 1/1 samples.
         * f8         | clc
         * 60         | pushal
         * b506       | mov ch, 6
         * 10e0       | adc al, ah
         * fc         | cld
         * 47         | inc edi
         * e8cd2e35bc | call 0xbd0f9940
         * ca6b7e     | retf 0x7e6b
         */
        $blockhash_0x8e8f21c3c3f1220f = {
            f8 60 b506 10e0 fc 47 e8???????? ca6b7e
        }

        /* picblockhash: 0xf4998699aabe0946 - coverage: 1/1 samples.
         * 65123540932c43 | adc dh, byte ptr gs:[0x432c9340]
         * d7             | xlatb
         * 4e             | dec esi
         * a7             | cmpsd dword ptr [esi], dword ptr es:[edi]
         * 4e             | dec esi
         * fa             | cli
         * 4e             | dec esi
         */
        $blockhash_0xf4998699aabe0946 = {
            65123540932c43 d7 4e a7 4e fa 4e
        }

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and 7 of them
}

rule MAL_PE_MOONBOUNCE_2
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule generated using MCRIT for code family MOONBOUNCE."
        reference   = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2022/01/19115831/MoonBounce_technical-details_eng.pdf"

        DaysofYARA  = "11/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"

    strings:
        // Rule generation selected 42 picblocks, covering 9/23 input sample(s).
        /* picblockhash: 0x48ea83dce36c4626 - coverage: 9/9 samples.
         * 55         | push ebp
         * 8bec       | mov ebp, esp
         * 83ec10     | sub esp, 0x10
         * 53         | push ebx
         * 56         | push esi
         * 57         | push edi
         * 8b7d08     | mov edi, dword ptr [ebp + 8]
         * 8b07       | mov eax, dword ptr [edi]
         * 8b703c     | mov esi, dword ptr [eax + 0x3c]
         * 6a04       | push 4
         * 03f0       | add esi, eax
         * 6800200000 | push 0x2000
         * ff7650     | push dword ptr [esi + 0x50]
         * ff7634     | push dword ptr [esi + 0x34]
         * ff5708     | call dword ptr [edi + 8]
         * 8bd8       | mov ebx, eax
         * 85db       | test ebx, ebx
         * 751b       | jne 0x104cc
         */
        $blockhash_0x48ea83dce36c4626 = {
            55 8bec 83ec10 53 56 57 8b7d08 8b07 8b703c 6a04 03f0 6800200000 ff7650 ff7634
            ff5708 8bd8 85db 75??
        }

        /* picblockhash: 0x764296061a725128 - coverage: 9/9 samples.
         * 55           | push ebp
         * 8bec         | mov ebp, esp
         * 682e090100   | push 0x1092e
         * ff15080b0100 | call dword ptr [0x10b08]
         * 6a00         | push 0
         * ff7508       | push dword ptr [ebp + 8]
         * ff15040b0100 | call dword ptr [0x10b04]
         * 5d           | pop ebp
         * c21400       | ret 0x14
         */
        $blockhash_0x764296061a725128 = {
            55 8bec 682e090100 ff15???????? 6a00 ff7508 ff15???????? 5d c21400
        }

        /* picblockhash: 0x49a88ff260995656 - coverage: 9/9 samples.
         * 55           | push ebp
         * 8bec         | mov ebp, esp
         * 53           | push ebx
         * 56           | push esi
         * 57           | push edi
         * 6a30         | push 0x30
         * 33ff         | xor edi, edi
         * 57           | push edi
         * ff15180b0100 | call dword ptr [0x10b18]
         * 8b7508       | mov esi, dword ptr [ebp + 8]
         * 8bd8         | mov ebx, eax
         * 3bdf         | cmp ebx, edi
         * 7422         | je 0x10810
         */
        $blockhash_0x49a88ff260995656 = {
            55 8bec 53 56 57 6a30 33ff 57 ff15???????? 8b7508 8bd8 3bdf 74??
        }

        /* picblockhash: 0xde8b1927abca2188 - coverage: 9/9 samples.
         * 8bff           | mov edi, edi
         * 55             | push ebp
         * 8bec           | mov ebp, esp
         * 83ec30         | sub esp, 0x30
         * 53             | push ebx
         * 33db           | xor ebx, ebx
         * 53             | push ebx
         * ff7508         | push dword ptr [ebp + 8]
         * ff15040b0100   | call dword ptr [0x10b04]
         * 6a40           | push 0x40
         * 6800300000     | push 0x3000
         * 8d45fc         | lea eax, [ebp - 4]
         * 50             | push eax
         * 53             | push ebx
         * 8d4508         | lea eax, [ebp + 8]
         * 50             | push eax
         * 6aff           | push -1
         * 895d08         | mov dword ptr [ebp + 8], ebx
         * c745fc00100400 | mov dword ptr [ebp - 4], 0x41000
         * ff152c0b0100   | call dword ptr [0x10b2c]
         * 85c0           | test eax, eax
         * 0f8cbd000000   | jl 0x10924
         */
        $blockhash_0xde8b1927abca2188 = {
            8bff 55 8bec 83ec30 53 33db 53 ff7508 ff15???????? 6a40 6800300000 8d45fc 50 53
            8d4508 50 6aff 895d08 c745fc00100400 ff15???????? 85c0 0f8c????????
        }

        /* picblockhash: 0x5d9f8f062412cf05 - coverage: 9/9 samples.
         * 55           | push ebp
         * 8bec         | mov ebp, esp
         * 83ec18       | sub esp, 0x18
         * 837d0800     | cmp dword ptr [ebp + 8], 0
         * 0f8440010000 | je 0x10a80
         */
        $blockhash_0x5d9f8f062412cf05 = {
            55 8bec 83ec18 837d0800 0f84????????
        }

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x20b
        and any of them
}
