rule SUSP_Obfuscated_Powershell_Casing_Anomaly {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via casing anomalies"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $case1 = "Powershell" nocase ascii wide
    $case2 = "powershell" nocase ascii wide
    $legit1 = "powershell" ascii wide
    $legit2 = "Powershell" ascii wide
  condition:
    none of ($legit*) and any of ($case*)
}


rule SUSP_Obfuscated_Powershell_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $ = "powershell" base64 base64wide
    $ = "Powershell" base64 base64wide
    $ = "PowerShell" base64 base64wide
    $ = "POWERSHELL" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $ = "powershell" xor(0x01-0xff) ascii wide
    $ = "Powershell" xor(0x01-0xff) ascii wide
    $ = "PowerShell" xor(0x01-0xff) ascii wide
    $ = "POWERSHELL" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop = "opewsrehll" nocase ascii wide
    $PowerShell_flipflop = "oPewSrehll" nocase ascii wide
    $Powershell_flipflop = "oPewsrehll" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop_b64 = "opewsrehll" base64 base64wide
    $PowerShell_flipflop_b64 = "oPewSrehll" base64 base64wide
    $Powershell_flipflop_b64 = "oPewsrehll" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_flipflop_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via flipflop_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_flipflop_xor = "opewsrehll" xor(0x01-0xff) ascii wide
    $PowerShell_flipflop_xor = "oPewSrehll" xor(0x01-0xff) ascii wide
    $Powershell_flipflop_xor = "oPewsrehll" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13 = "cbjrefuryy" nocase ascii wide
    $PowerShell_rot13 = "CbjreFuryy" nocase ascii wide
    $Powershell_rot13 = "Cbjrefuryy" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13_b64 = "cbjrefuryy" base64 base64wide
    $PowerShell_rot13_b64 = "CbjreFuryy" base64 base64wide
    $Powershell_rot13_b64 = "Cbjrefuryy" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_rot13_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via rot13_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_rot13_xor = "cbjrefuryy" xor(0x01-0xff) ascii wide
    $PowerShell_rot13_xor = "CbjreFuryy" xor(0x01-0xff) ascii wide
    $Powershell_rot13_xor = "Cbjrefuryy" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse = "llehsrewop" nocase ascii wide
    $PowerShell_reverse = "llehSrewoP" nocase ascii wide
    $Powershell_reverse = "llehsrewoP" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse_b64 = "llehsrewop" base64 base64wide
    $PowerShell_reverse_b64 = "llehSrewoP" base64 base64wide
    $Powershell_reverse_b64 = "llehsrewoP" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_reverse_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via reverse_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_reverse_xor = "llehsrewop" xor(0x01-0xff) ascii wide
    $PowerShell_reverse_xor = "llehSrewoP" xor(0x01-0xff) ascii wide
    $Powershell_reverse_xor = "llehsrewoP" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str = "706f7765727368656c6c" nocase ascii wide
    $PowerShell_hex_enc_str = "506f7765725368656c6c" nocase ascii wide
    $Powershell_hex_enc_str = "506f7765727368656c6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64 = "706f7765727368656c6c" base64 base64wide
    $PowerShell_hex_enc_str_b64 = "506f7765725368656c6c" base64 base64wide
    $Powershell_hex_enc_str_b64 = "506f7765727368656c6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_xor = "706f7765727368656c6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_xor = "506f7765725368656c6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_xor = "506f7765727368656c6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces = "70 6f 77 65 72 73 68 65 6c 6c" nocase ascii wide
    $PowerShell_hex_enc_str_spaces = "50 6f 77 65 72 53 68 65 6c 6c" nocase ascii wide
    $Powershell_hex_enc_str_spaces = "50 6f 77 65 72 73 68 65 6c 6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces_b64 = "70 6f 77 65 72 73 68 65 6c 6c" base64 base64wide
    $PowerShell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 53 68 65 6c 6c" base64 base64wide
    $Powershell_hex_enc_str_spaces_b64 = "50 6f 77 65 72 73 68 65 6c 6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_spaces_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_spaces_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_spaces_xor = "70 6f 77 65 72 73 68 65 6c 6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_spaces_xor = "50 6f 77 65 72 53 68 65 6c 6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_spaces_xor = "50 6f 77 65 72 73 68 65 6c 6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas = "70,6f,77,65,72,73,68,65,6c,6c" nocase ascii wide
    $PowerShell_hex_enc_str_commas = "50,6f,77,65,72,53,68,65,6c,6c" nocase ascii wide
    $Powershell_hex_enc_str_commas = "50,6f,77,65,72,73,68,65,6c,6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas_b64 = "70,6f,77,65,72,73,68,65,6c,6c" base64 base64wide
    $PowerShell_hex_enc_str_commas_b64 = "50,6f,77,65,72,53,68,65,6c,6c" base64 base64wide
    $Powershell_hex_enc_str_commas_b64 = "50,6f,77,65,72,73,68,65,6c,6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_commas_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_commas_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_commas_xor = "70,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_commas_xor = "50,6f,77,65,72,53,68,65,6c,6c" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_commas_xor = "50,6f,77,65,72,73,68,65,6c,6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str = "3730366637373635373237333638363536633663" nocase ascii wide
    $PowerShell_double_hex_enc_str = "3530366637373635373235333638363536633663" nocase ascii wide
    $Powershell_double_hex_enc_str = "3530366637373635373237333638363536633663" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str_b64 = "3730366637373635373237333638363536633663" base64 base64wide
    $PowerShell_double_hex_enc_str_b64 = "3530366637373635373235333638363536633663" base64 base64wide
    $Powershell_double_hex_enc_str_b64 = "3530366637373635373237333638363536633663" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_double_hex_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via double_hex_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_double_hex_enc_str_xor = "3730366637373635373237333638363536633663" xor(0x01-0xff) ascii wide
    $PowerShell_double_hex_enc_str_xor = "3530366637373635373235333638363536633663" xor(0x01-0xff) ascii wide
    $Powershell_double_hex_enc_str_xor = "3530366637373635373237333638363536633663" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide
    $PowerShell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" nocase ascii wide
    $Powershell_hex_enc_str_b64_enc_str = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str_b64 = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide
    $PowerShell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" base64 base64wide
    $Powershell_hex_enc_str_b64_enc_str_b64 = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_b64_enc_str_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_b64_enc_str_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_b64_enc_str_xor = "NzA2Zjc3NjU3MjczNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_b64_enc_str_xor = "NTA2Zjc3NjU3MjUzNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_b64_enc_str_xor = "NTA2Zjc3NjU3MjczNjg2NTZjNmM=" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed = "c6c6568637275677f607" nocase ascii wide
    $PowerShell_hex_enc_str_reversed = "c6c6568635275677f605" nocase ascii wide
    $Powershell_hex_enc_str_reversed = "c6c6568637275677f605" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f607" base64 base64wide
    $PowerShell_hex_enc_str_reversed_b64 = "c6c6568635275677f605" base64 base64wide
    $Powershell_hex_enc_str_reversed_b64 = "c6c6568637275677f605" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_hex_enc_str_reversed_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via hex_enc_str_reversed_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_hex_enc_str_reversed_xor = "c6c6568637275677f607" xor(0x01-0xff) ascii wide
    $PowerShell_hex_enc_str_reversed_xor = "c6c6568635275677f605" xor(0x01-0xff) ascii wide
    $Powershell_hex_enc_str_reversed_xor = "c6c6568637275677f605" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal = "112 111 119 101 114 115 104 101 108 108" nocase ascii wide
    $PowerShell_decimal = "80 111 119 101 114 83 104 101 108 108" nocase ascii wide
    $Powershell_decimal = "80 111 119 101 114 115 104 101 108 108" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_b64 = "112 111 119 101 114 115 104 101 108 108" base64 base64wide
    $PowerShell_decimal_b64 = "80 111 119 101 114 83 104 101 108 108" base64 base64wide
    $Powershell_decimal_b64 = "80 111 119 101 114 115 104 101 108 108" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_xor = "112 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide
    $PowerShell_decimal_xor = "80 111 119 101 114 83 104 101 108 108" xor(0x01-0xff) ascii wide
    $Powershell_decimal_xor = "80 111 119 101 114 115 104 101 108 108" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas = "112,111,119,101,114,115,104,101,108,108" nocase ascii wide
    $PowerShell_decimal_commas = "80,111,119,101,114,83,104,101,108,108" nocase ascii wide
    $Powershell_decimal_commas = "80,111,119,101,114,115,104,101,108,108" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas_b64 = "112,111,119,101,114,115,104,101,108,108" base64 base64wide
    $PowerShell_decimal_commas_b64 = "80,111,119,101,114,83,104,101,108,108" base64 base64wide
    $Powershell_decimal_commas_b64 = "80,111,119,101,114,115,104,101,108,108" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_decimal_commas_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via decimal_commas_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_decimal_commas_xor = "112,111,119,101,114,115,104,101,108,108" xor(0x01-0xff) ascii wide
    $PowerShell_decimal_commas_xor = "80,111,119,101,114,83,104,101,108,108" xor(0x01-0xff) ascii wide
    $Powershell_decimal_commas_xor = "80,111,119,101,114,115,104,101,108,108" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill = "kldvihsvoo" nocase ascii wide
    $PowerShell_fallchill = "PldviSsvoo" nocase ascii wide
    $Powershell_fallchill = "Pldvihsvoo" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill_b64 = "kldvihsvoo" base64 base64wide
    $PowerShell_fallchill_b64 = "PldviSsvoo" base64 base64wide
    $Powershell_fallchill_b64 = "Pldvihsvoo" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_fallchill_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via fallchill_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_fallchill_xor = "kldvihsvoo" xor(0x01-0xff) ascii wide
    $PowerShell_fallchill_xor = "PldviSsvoo" xor(0x01-0xff) ascii wide
    $Powershell_fallchill_xor = "Pldvihsvoo" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush = "hllhrshehpowe" nocase ascii wide
    $PowerShell_stackpush = "hllhrShehPowe" nocase ascii wide
    $Powershell_stackpush = "hllhrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush_b64 = "hllhrshehpowe" base64 base64wide
    $PowerShell_stackpush_b64 = "hllhrShehPowe" base64 base64wide
    $Powershell_stackpush_b64 = "hllhrshehPowe" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpush_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpush_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpush_xor = "hllhrshehpowe" xor(0x01-0xff) ascii wide
    $PowerShell_stackpush_xor = "hllhrShehPowe" xor(0x01-0xff) ascii wide
    $Powershell_stackpush_xor = "hllhrshehPowe" xor(0x01-0xff) ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpushnull {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushnull"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpushnull = "hll\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushnull = "hll\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushnull = "hll\x00hrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_stackpushdoublenull {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via stackpushdoublenull"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_stackpushdoublenull = "hll\x00\x00hrshehpowe" nocase ascii wide
    $PowerShell_stackpushdoublenull = "hll\x00\x00hrShehPowe" nocase ascii wide
    $Powershell_stackpushdoublenull = "hll\x00\x00hrshehPowe" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded = "70%6f%77%65%72%73%68%65%6c%6c" nocase ascii wide
    $PowerShell_url_encoded = "50%6f%77%65%72%53%68%65%6c%6c" nocase ascii wide
    $Powershell_url_encoded = "50%6f%77%65%72%73%68%65%6c%6c" nocase ascii wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded_b64 {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded_b64"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded_b64 = "70%6f%77%65%72%73%68%65%6c%6c" base64 base64wide
    $PowerShell_url_encoded_b64 = "50%6f%77%65%72%53%68%65%6c%6c" base64 base64wide
    $Powershell_url_encoded_b64 = "50%6f%77%65%72%73%68%65%6c%6c" base64 base64wide
  condition:
    any of them
}

rule SUSP_Obfuscated_Powershell_url_encoded_xor {
  meta:
    author = "Greg Lesnewich"
    description = "look for obfsucated powershell strings obfuscated via url_encoded_xor"
    date = "2024-01-31"
    version = "1.0"
    DaysOfYara = "32/100"
  strings:
    $powershell_url_encoded_xor = "70%6f%77%65%72%73%68%65%6c%6c" xor(0x01-0xff) ascii wide
    $PowerShell_url_encoded_xor = "50%6f%77%65%72%53%68%65%6c%6c" xor(0x01-0xff) ascii wide
    $Powershell_url_encoded_xor = "50%6f%77%65%72%73%68%65%6c%6c" xor(0x01-0xff) ascii wide
  condition:
    any of them
}
