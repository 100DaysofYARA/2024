// #100daysofYARA
// day 7
// stvemillertime
// simple rules for suspicious ipconfig cmd
// you *will* have to add some exclusions for things like windows ipconfig.exe and netevent.dll 
// you might want to do some tweaking

import "pe"

rule ttp_cmdline_ipconfig_flushdns_reg {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44" // just an example, i didn't look much
    strings:
        $a = "flushdns" nocase ascii wide
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and pe.number_of_signatures == 0
        and $a
        and not any of ($z*)
}
rule ttp_cmdline_ipconfig_flushdns_xor {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"
    strings:
        $a = "flushdns" xor (0x01-0xff)
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and pe.number_of_signatures == 0
        and $a
        and not any of ($z*)
}
rule ttp_cmdline_ipconfig_flushdns_b64 {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"
    strings:
        $a = "flushdns" base64 base64wide
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and $a
        and not any of ($z*)
}
rule ttp_cmdline_ipconfig_flushdns_mixbag {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"
    strings:
        $flushdns_flipflop = "lfsudhsn" nocase
        $flushdns_reverse = "sndhsulf" nocase
        $flushdns_hex_enc_str = "666c757368646e73" nocase
        $flushdns_decimal = "102 108 117 115 104 100 110 115" nocase
        $flushdns_fallchill = "uofhswmh" nocase
        $flushdns_stackpush = "hhdnshflus" nocase
        $flushdns_stackpushnull = "h\x00hdnshflus" nocase
        $flushdns_stackpushdoublenull = "h\x00\x00hdnshflus" nocase
        $flushdns_hex_movebp = {c645??66c645??6cc645??75c645??73c645??68c645??64c645??6ec645??73}
        $flushdns_rot13 = "syhfuqaf" nocase
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and any of ($flushdns*)
        and not any of ($z*)
}
rule ttp_cmdline_ipconfig_flushdns_mixbag_2 {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"
    strings:
        $FLUSHDNS_flipflop = "LFSUDHSN" nocase
        $FLUSHDNS_reverse = "SNDHSULF" nocase
        $FLUSHDNS_hex_enc_str = "464c555348444e53" nocase
        $FLUSHDNS_decimal = "70 76 85 83 72 68 78 83" nocase
        $FLUSHDNS_fallchill = "FLUSHDNS" nocase
        $FLUSHDNS_stackpush = "hHDNShFLUS" nocase
        $FLUSHDNS_stackpushnull = "hHDNS\x00hFLUS" nocase
        $FLUSHDNS_stackpushdoublenull = "hHDNS\x00\x00hFLUS" nocase
        $FLUSHDNS_hex_movebp = {c645??46c645??4cc645??55c645??53c645??48c645??44c645??4ec645??53}
        $FLUSHDNS_rot13 = "SYHFUQAF" nocase
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and any of ($FLUSHDNS*)
        and not any of ($z*)
}
rule ttp_cmdline_ipconfig_flushdns_mixbag_3 {
    meta:
        author = "stvemillertime"
        desc = "Looks for suspicious cmdline string in a PE"
        ref = "884c15502dbd6fe6dd4fca322904a38bce117ab6ed102ab2da84dfb4064c3e44"
    strings:
        $FlushDns_flipflop = "lFsuDhsn" nocase
        $FlushDns_reverse = "snDhsulF" nocase
        $FlushDns_hex_enc_str = "466c757368446e73" nocase
        $FlushDns_decimal = "70 108 117 115 104 68 110 115" nocase
        $FlushDns_fallchill = "FofhsDmh" nocase
        $FlushDns_stackpush = "hhDnshFlus" nocase
        $FlushDns_stackpushnull = "h\x00hDnshFlus" nocase
        $FlushDns_stackpushdoublenull = "h\x00\x00hDnshFlus" nocase
        $FlushDns_hex_movebp = {c645??46c645??6cc645??75c645??73c645??68c645??44c645??6ec645??73}
        $FlushDns_rot13 = "SyhfuQaf" nocase
        $z2 = {69 00 70 00 63 00 6F 00 6E 00 66 00 69 00 67 00 2E 00 65 00 78 00 65 00 00 00 00} //ipconfig.exe vs version info
        $z3 = {4E 00 65 00 74 00 45 00 76 00 65 00 6E 00 74 00 2E 00 44 00 6C 00 6C 00 00 00 00 00} //netevent.dll vs version info
        $z4 = "FlushDnsPolicyUnreachableStatus"
        $z5 = "flushdns</userInput>"
    condition:
        uint16be(0) == 0x4d5a
        and any of ($FlushDns*)
        and not any of ($z*)
}