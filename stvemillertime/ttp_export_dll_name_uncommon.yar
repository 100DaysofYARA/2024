// #100daysofYARA
// day 5 and 6
// stvemillertime
// rules for exported dll names often seen in dll search order, load order, hijacking shenanigans

import "pe"
import "console"

rule ttp_exports_dll_name_mpsvc {
    meta:
        author = "stvemillertime"
        desc = "this looks for unsigned pes with exports dlls named after microsoft malware protection client dlls"
        ref = "e21360d6411ec9a719789e0f82dad5e380ee4a81faa3ebc072c8779e2a1da5ed"
    condition:
        filesize < 10MB
        and uint16be(0) == 0x4d5a
        and pe.number_of_signatures == 0
        and pe.dll_name == "mpsvc.dll"
}
rule ttp_exports_dll_name_mpclient {
    meta:
        author = "stvemillertime"
        desc = "this looks for unsigned pes with exports dlls named after microsoft malware protection client dlls"
        ref = "8efcecc00763ce9269a01d2b5918873144746c4b203be28c92459f5301927961"
    condition:
        filesize < 10MB
        and uint16be(0) == 0x4d5a
        and pe.number_of_signatures == 0
        and pe.dll_name == "mpclient.dll"
}