rule MAL_ADVOBFUSCATOR_STRINGS_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule improving on Day 7 detecting ADVObfuscator strings."

        DaysofYARA  = "8/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-08"
        version     = "1.0"

    strings:

        $sub1 = {
            (2c | 80 e?) ??
            [4-8]
            (
                40 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
            )
        }

        $xor1 = {
            30

            (c0 | c8 | d0 | d8 | e0 | e8 | f0 | f8 | c1 | c9 | d1 | d9 | e1 | e9
            | f1 | f9 | c2 | ca | d2 | da | e2 | ea | f2 | fa | c3 | cb | d3 | db |
            e3 | eb | f3 | fb | c4 | cc | d4 | dc | e4 | ec | f4 | fc | c5 | cd | d5
            | dd | e5 | ed | f5 | fd | c6 | ce | d6 | de | e6 | ee | f6 | fe | c7 |
            cf | d7 | df | e7 | ef | f7 | ff)

            [4-8]

            (
                40 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
            )
        }

        $xor2 = {
            32

            (c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7 | c8 | c9 | ca | cb | cc | cd
            | ce | cf | d0 | d1 | d2 | d3 | d4 | d5 | d6 | d7 | d8 | d9 | da | db |
            dc | dd | de | df | e0 | e1 | e2 | e3 | e4 | e5 | e6 | e7 | e8 | e9 | ea
            | eb | ec | ed | ee | ef | f0 | f1 | f2 | f3 | f4 | f5 | f6 | f7 | f8 |
            f9 | fa | fb | fc | fd | fe | ff)

            [4-8]

            (
                40 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
                |
                41 83 F? ?? 72 ??
            )
        }

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
        and $sub1
        and for any of ($xor*) : ( # >= 10 )
        //and filesize < 5MB
}
