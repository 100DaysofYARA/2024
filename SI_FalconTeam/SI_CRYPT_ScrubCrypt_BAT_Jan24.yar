import "math"

rule SI_CRYPT_ScrubCrypt_BAT_Jan24 : Crypter {

    meta:
        version = "1.2"
        date = "2024-01-02"
        modified = "2024-01-03"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects obfuscated Batch files generated by the ScrubCrypt Crypter"
        category = "TOOL"
        mitre_att = "T1027.002"
        actor_type = "CRIMEWARE"
        reference = "https://perception-point.io/blog/the-rebranded-crypter-scrubcrypt/"
        hash = "b6f71c1b85564ed3f60f5c07c04dd6926a99bafae0661509e4cc996a7e565b36"
        minimum_yara = "4.2"
        best_before = "2025-01-03"

    strings:
        //the Batch files contain patterns like %#% to disrupt easy string detection
        $obfp1 = {25 23 25}
        $obfp2 = {25 3D 25}
        $obfp3 = {25 40 25}
      
        $s_echo = "@echo off"
        $s_exe = ".exe"
        $s_set = "set"
        $s_copy = "copy"

    condition:
        (uint16(0) == 0x3a3a or uint16(0) == 0x6540) //at the beginning of the file there is either a comment (::) followed by b64 or "@echo off"
        and 3 of ($s_*)
        and filesize > 32KB
        and filesize < 10MB
        and #obfp1 > 16
        and #obfp2 > 16
        and #obfp3 > 16
        and math.entropy(0, filesize) >= 6 //due to the stray character obfuscation and base64 contents Shannon entropy is ~6
}