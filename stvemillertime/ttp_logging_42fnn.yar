import "pe"
rule ttp_logging_42fnn_strings {
    meta:
        author = "stvemillertime"
        date = "2024-01-09"
        description = "This looks for generic logging strings for GB MB KB stuffs"
        sample = "ee5982a71268c84a5c062095ce135780b8c2ffb1f266c2799173fb0f7bfdd33e"
        // rule quickly and easily generated using https://yaratoolkit.securitybreak.io/ 
    strings:
        // a bunch of variations of these basic strings
        // might be seen in lots of malware families, but probably not much goodware
        $str1 = "%4.2f GB" nocase ascii wide 
        $str2 = "%4.2f MB" nocase ascii wide
        $str3 = "%4.2f KB" nocase ascii wide
        $str5 = "%4.2f GB" xor(0x01-0xff)  
        $str6 = "%4.2f MB" xor(0x01-0xff)  
        $str7 = "%4.2f KB" xor(0x01-0xff)  
        $str8 = "%4.2f GB" base64 base64wide
        $str9 = "%4.2f MB" base64 base64wide
        $str10 = "%4.2f KB" base64 base64wide
        $str11 = "%4.2f gb" xor(0x01-0xff)  
        $str12 = "%4.2f mb" xor(0x01-0xff)  
        $str13 = "%4.2f kb" xor(0x01-0xff)  
        $str14 = "%4.2f gb" base64 base64wide  
        $str15 = "%4.2f mb" base64 base64wide
        $str16 = "%4.2f kb" base64 base64wide
    condition:
        uint16be(0) == 0x4d5a and
        pe.number_of_signatures == 0
        2 of them //maybe up this to 3 idk
}