rule SUSP_ntdlldll_mutation_flipflop {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_flipflop = "tnld.lldl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_reverse {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_reverse = "lld.lldtn" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_hex_enc_str {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_hex_enc_str = "6e74646c6c2e646c6c" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_decimal {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_decimal = "110 116 100 108 108 46 100 108 108" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_fallchill {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_fallchill = "mgwoo.woo" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpush {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpush = "hlhl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpushnull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpushnull = "hl\x00hl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_stackpushdoublenull {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_stackpushdoublenull = "hl\x00\x00hl.dlhntdl" ascii wide nocase
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_hex_movebp {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_hex_movebp = {c645??6ec645??74c645??64c645??6cc645??6cc645??2ec645??64c645??6cc645??6c}
	condition:
		all of them
}

rule SUSP_ntdlldll_mutation_rot13 {
	meta:
		author = "Greg Lesnewich"
		description = "track string mutations of ntdll.dll which can be used for syscalls"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "24/100"
	strings:
		$ntdlldll_rot13 = "agqyy.qyy" ascii wide nocase
	condition:
		all of them
}



rule ntdll_flipflop { strings: $ntdll_flipflop = "tnldl" nocase ascii wide condition: all of them }
rule ntdll_reverse { strings: $ntdll_reverse = "lldtn" nocase ascii wide condition: all of them }
rule ntdll_hex_enc_str { strings: $ntdll_hex_enc_str = "6e74646c6c" nocase ascii wide condition: all of them }
rule ntdll_decimal { strings: $ntdll_decimal = "110 116 100 108 108" nocase ascii wide condition: all of them }
rule ntdll_fallchill { strings: $ntdll_fallchill = "mgwoo" nocase ascii wide condition: all of them }
rule ntdll_stackpush { strings: $ntdll_stackpush = "hlhntdl" nocase ascii wide condition: all of them }
rule ntdll_stackpushnull { strings: $ntdll_stackpushnull = "hl\x00hntdl" nocase ascii wide condition: all of them }
rule ntdll_stackpushdoublenull { strings: $ntdll_stackpushdoublenull = "hl\x00\x00hntdl" nocase ascii wide condition: all of them }
rule ntdll_hex_movebp { strings: $ntdll_hex_movebp = {c645??6ec645??74c645??64c645??6cc645??6c} condition: all of them }
rule ntdll_rot13 { strings: $ntdll_rot13 = "agqyy" nocase ascii wide condition: all of them }



rule zSUSP_NTDLL_Stack_String_Padding
{
	meta:
		author = "Greg Lesnewich"
		description = "detect ntdll.dll being moved to the stack with empty padding being used to clear the register prior to use"
		date = "2024-01-23"
		version = "1.0"
		DaysofYARA = "23/100"

	strings:
		$0x1d5c1369a = { 20202020 ?? 6e74646c [10 - 20] 20202020 ?? 6c2e646c }
		    // 1d5c1369a  0d20202020         or      eax, 0x20202020
		    // 1d5c1369f  3d6e74646c         cmp     eax, 'ntdl'
		    // 1d5c136a4  751b               jne     0x1d5c136c1
		    // 1d5c136a6  488b4598           mov     rax, qword [rbp-0x68 {var_80_1}]
		    // 1d5c136aa  4883c004           add     rax, 0x4
		    // 1d5c136ae  8b00               mov     eax, dword [rax]
		    // 1d5c136b0  0d20202020         or      eax, 0x20202020
		    // 1d5c136b5  3d6c2e646c         cmp     eax, 'l.dl'
	condition:
		all of them
}
