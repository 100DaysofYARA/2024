
rule SUSP_kernel32_mutation_b64 
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_b64 = "kernel32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_xor = "kernel32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop = "eknrle23" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop_b64 = "eknrle23" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_flipflop_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_flipflop_xor = "eknrle23" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13 = "xreary32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13_b64 = "xreary32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_rot13_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_rot13_xor = "xreary32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse = "23lenrek" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse_b64 = "23lenrek" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_reverse_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_reverse_xor = "23lenrek" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str = "6b65726e656c3332" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64 = "6b65726e656c3332" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_xor = "6b65726e656c3332" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces = "6b 65 72 6e 65 6c 33 32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces_b64 = "6b 65 72 6e 65 6c 33 32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_spaces_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_spaces_xor = "6b 65 72 6e 65 6c 33 32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas = "6b,65,72,6e,65,6c,33,32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas_b64 = "6b,65,72,6e,65,6c,33,32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_commas_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_commas_xor = "6b,65,72,6e,65,6c,33,32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str = "36623635373236653635366333333332" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str_b64 = "36623635373236653635366333333332" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_double_hex_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_double_hex_enc_str_xor = "36623635373236653635366333333332" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str = "NmI2NTcyNmU2NTZjMzMzMg==" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str_b64 = "NmI2NTcyNmU2NTZjMzMzMg==" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_b64_enc_str_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_b64_enc_str_xor = "NmI2NTcyNmU2NTZjMzMzMg==" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed = "2333c656e62756b6" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed_b64 = "2333c656e62756b6" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_hex_enc_str_reversed_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_hex_enc_str_reversed_xor = "2333c656e62756b6" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal = "107 101 114 110 101 108 51 50" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_b64 = "107 101 114 110 101 108 51 50" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_xor = "107 101 114 110 101 108 51 50" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas = "107,101,114,110,101,108,51,50" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas_b64 = "107,101,114,110,101,108,51,50" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_decimal_commas_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_decimal_commas_xor = "107,101,114,110,101,108,51,50" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill = "pvimvo32" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill_b64 = "pvimvo32" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_fallchill_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_fallchill_xor = "pvimvo32" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush = "hel32hkern" nocase ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush_b64
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush_b64 = "hel32hkern" base64 base64wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpush_xor
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpush_xor = "hel32hkern" xor(0x01-0xff) ascii wide
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpushnull
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpushnull = "hel32\x00hkern"
	condition:
		all of them
}

rule SUSP_kernel32_mutation_stackpushdoublenull
{
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of kernel32 which can be used for lots of evil things"
		date = "2024-01-24"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$kernel32_stackpushdoublenull = "hel32\x00\x00hkern"
	condition:
		all of them
}
