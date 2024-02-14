
rule SUSP_Obfuscated_Mozilla_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_b64 = "Mozilla" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_xor = "Mozilla" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop = "oMizlla" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop_b64 = "oMizlla" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_flipflop_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_flipflop_xor = "oMizlla" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13 = "Zbmvyyn" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13_b64 = "Zbmvyyn" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_rot13_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_rot13_xor = "Zbmvyyn" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse = "allizoM" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse_b64 = "allizoM" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_reverse_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_reverse_xor = "allizoM" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str = "4d6f7a696c6c61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64 = "4d6f7a696c6c61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_xor = "4d6f7a696c6c61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces = "4d 6f 7a 69 6c 6c 61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces_b64 = "4d 6f 7a 69 6c 6c 61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_spaces_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_spaces_xor = "4d 6f 7a 69 6c 6c 61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas = "4d,6f,7a,69,6c,6c,61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas_b64 = "4d,6f,7a,69,6c,6c,61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_commas_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_commas_xor = "4d,6f,7a,69,6c,6c,61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str = "3464366637613639366336633631" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str_b64 = "3464366637613639366336633631" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_double_hex_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_double_hex_enc_str_xor = "3464366637613639366336633631" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str = "NGQ2ZjdhNjk2YzZjNjE=" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str_b64 = "NGQ2ZjdhNjk2YzZjNjE=" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_b64_enc_str_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_b64_enc_str_xor = "NGQ2ZjdhNjk2YzZjNjE=" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed = "16c6c696a7f6d4" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed_b64 = "16c6c696a7f6d4" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_hex_enc_str_reversed_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_hex_enc_str_reversed_xor = "16c6c696a7f6d4" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal = "77 111 122 105 108 108 97" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_b64 = "77 111 122 105 108 108 97" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_xor = "77 111 122 105 108 108 97" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas = "77,111,122,105,108,108,97" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas_b64 = "77,111,122,105,108,108,97" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_decimal_commas_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_decimal_commas_xor = "77,111,122,105,108,108,97" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill = "Mlzrooa" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill_b64 = "Mlzrooa" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_fallchill_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_fallchill_xor = "Mlzrooa" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush = "hllahMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush_b64 = "hllahMozi" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpush_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpush_xor = "hllahMozi" xor(0x01-0xff) ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpushnull {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpushnull = "hlla\x00hMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_stackpushdoublenull {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_stackpushdoublenull = "hlla\x00\x00hMozi" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded = "4d%6f%7a%69%6c%6c%61" nocase ascii wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded_b64 {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded_b64 = "4d%6f%7a%69%6c%6c%61" base64 base64wide
    condition:
        all of them
}

rule SUSP_Obfuscated_Mozilla_url_encoded_xor {
    meta:
        author = "Greg Lesnewich"
        description = "track obfuscated Mozilla strings"
        date = "2024-02-13"
        version = "1.0"
        DaysOfYara = "44/100"
    strings:
        $Mozilla_url_encoded_xor = "4d%6f%7a%69%6c%6c%61" xor(0x01-0xff) ascii wide
    condition:
        all of them
}
