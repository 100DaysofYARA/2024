rule MAL_ADVOBFUSCATOR_STRINGS_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule detecting ADVObfuscator strings."

        disclaimer  = "THIS RULE IS EXTREMELY NOISY AND UNREFINED. IT WORKS IN THE MOST GENERAL SENSE AND REQUIRES TUNING."

        reference   = "https://github.com/andrivet/ADVobfuscator"
        research    = "https://research.openanalysis.net/advobfuscator/python/obfuscation/strings/tooling/2023/10/08/advobfuscator.html"
        research    = "https://malware.news/t/lets-learn-dissecting-lazarus-windows-x86-loader-involved-in-crypto-trading-app-distribution-snowman-advobfuscator/33904"

        DaysofYARA  = "7/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-07"
        version     = "1.0"

    strings:
        // sub
        $sub1 = {2c ?? 88 [5-9] 40 83 F? ?? 72 ??}
        $sub2 = {2c ?? 88 [5-9] 41 83 F? ?? 72 ??}
        $sub3 = {2c ?? 88 [5-9] 42 83 F? ?? 72 ??}
        $sub4 = {2c ?? 88 [5-9] 43 83 F? ?? 72 ??}
        $sub5 = {2c ?? 88 [5-9] 44 83 F? ?? 72 ??}
        $sub6 = {2c ?? 88 [5-9] 45 83 F? ?? 72 ??}
        $sub7 = {2c ?? 88 [5-9] 46 83 F? ?? 72 ??}
        $sub8 = {2c ?? 88 [5-9] 47 83 F? ?? 72 ??}

        // xor
        $xor1 = {(30|32) [5-9] 40 83 F? ?? 72 ??}
        $xor2 = {(30|32) [5-9] 41 83 F? ?? 72 ??}
        $xor3 = {(30|32) [5-9] 42 83 F? ?? 72 ??}
        $xor4 = {(30|32) [5-9] 43 83 F? ?? 72 ??}
        $xor5 = {(30|32) [5-9] 44 83 F? ?? 72 ??}
        $xor6 = {(30|32) [5-9] 45 83 F? ?? 72 ??}
        $xor7 = {(30|32) [5-9] 46 83 F? ?? 72 ??}
        $xor8 = {(30|32) [5-9] 47 83 F? ?? 72 ??}

        /* may slow down scanning :(
        $ = {
            (32 | 2c ) ??   // xor | sub
            [4-32]
            4?          // .text:00401120 40       inc     eax
            83 f? ??    // .text:00401121 83 F8 0E cmp     eax, 0Eh
            72 ??       // .text:00401124 72 EA    jb      short loc_401110
        }
        */

    condition:
        uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x18) == 0x10b      // 32-bit
        and for any of them : ( # > 10 )
        and filesize < 5MB
}
