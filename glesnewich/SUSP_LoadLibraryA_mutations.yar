
rule SUSP_LoadLibraryA_mutation_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_b64 = "LoadLibraryA" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_xor = "LoadLibraryA" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop = "oLdaiLrbraAy" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop_b64 = "oLdaiLrbraAy" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_flipflop_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_flipflop_xor = "oLdaiLrbraAy" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13 = "YbnqYvoenelN" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13_b64 = "YbnqYvoenelN" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_rot13_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_rot13_xor = "YbnqYvoenelN" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse = "AyrarbiLdaoL" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse_b64 = "AyrarbiLdaoL" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_reverse_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_reverse_xor = "AyrarbiLdaoL" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str = "4c6f61644c69627261727941" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64 = "4c6f61644c69627261727941" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_xor = "4c6f61644c69627261727941" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces = "4c 6f 61 64 4c 69 62 72 61 72 79 41" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces_b64 = "4c 6f 61 64 4c 69 62 72 61 72 79 41" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_spaces_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_spaces_xor = "4c 6f 61 64 4c 69 62 72 61 72 79 41" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas = "4c,6f,61,64,4c,69,62,72,61,72,79,41" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas_b64 = "4c,6f,61,64,4c,69,62,72,61,72,79,41" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_commas_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_commas_xor = "4c,6f,61,64,4c,69,62,72,61,72,79,41" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str = "346336663631363434633639363237323631373237393431" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str_b64 = "346336663631363434633639363237323631373237393431" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_double_hex_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_double_hex_enc_str_xor = "346336663631363434633639363237323631373237393431" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str_b64 = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_b64_enc_str_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_b64_enc_str_xor = "NGM2ZjYxNjQ0YzY5NjI3MjYxNzI3OTQx" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed = "14972716272696c44616f6c4" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed_b64 = "14972716272696c44616f6c4" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_hex_enc_str_reversed_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_hex_enc_str_reversed_xor = "14972716272696c44616f6c4" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal = "76 111 97 100 76 105 98 114 97 114 121 65" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_b64 = "76 111 97 100 76 105 98 114 97 114 121 65" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_xor = "76 111 97 100 76 105 98 114 97 114 121 65" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas = "76,111,97,100,76,105,98,114,97,114,121,65" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas_b64 = "76,111,97,100,76,105,98,114,97,114,121,65" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_decimal_commas_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_decimal_commas_xor = "76,111,97,100,76,105,98,114,97,114,121,65" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill = "LlawLryiaibA" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill_b64 = "LlawLryiaibA" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_fallchill_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_fallchill_xor = "LlawLryiaibA" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush = "haryAhLibrhLoad" nocase ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush_b64 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush_b64 = "haryAhLibrhLoad" base64 base64wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpush_xor {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpush_xor = "haryAhLibrhLoad" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpushnull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpushnull = "haryA\x00hLibrhLoad"
	condition:
		all of them
}

rule SUSP_LoadLibraryA_mutation_stackpushdoublenull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of LoadLibraryA which is commonly used to resolve additional apis"
		date = "2024-01-25"
		version = "1.0"
		DaysofYARA = "25/100"
	strings:
		$LoadLibraryA_stackpushdoublenull = "haryA\x00\x00hLibrhLoad"
	condition:
		all of them
}
