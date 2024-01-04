rule APT_NK_TA444_SpectralBlur
{
	meta:
		author = "Greg Lesnewich"
		description = "track the SpectralBlur backdoor"
		date = "2023-08-21"
		version = "1.0"
		hash = "6f3e849ee0fe7a6453bd0408f0537fa894b17fc55bc9d1729ae035596f5c9220"
		DaysofYARA = "3/100"

	strings:
		$xcrypt1 = {
			99                 // cdq
			f7 [4-8]           // idiv    dword [rbp-0x11c {var_124}]
			8b [4-8]           // mov     eax, dword [rbp-0x14c {var_154_1}]
			48 63 d2           // movsxd  rdx, edx
			0f b6 0c 11        // movzx   ecx, byte [rcx+rdx]
			01 c8              // add     eax, ecx
			b9 00 01 00 00     // mov     ecx, 0x100
			99                 // cdq
			f7 f9              // idiv    ecx
		}

		$xcrypt2 = {
			8b 85 c4 fe ff ff        // mov     eax, dword [rbp-0x13c {var_144_2}]
			83 c0 01                 // add     eax, 0x1
			b9 00 01 00 00           // mov     ecx, 0x100
			99                       // cdq
			f7 f9                    // idiv    ecx
			[20-40]
			01 c8                    // add     eax, ecx
			b9 00 01 00 00           // mov     ecx, 0x100
			99                       // cdq
			f7 f9                    // idiv    ecx
		}

		$symbol1 = "xcrypt" ascii wide
		$symbol2 = "_proc_die" ascii wide
		$symbol3 = "_proc_dir" ascii wide
		$symbol4 = "_proc_download" ascii wide
		$symbol5 = "_proc_download_content" ascii wide
		$symbol6 = "_proc_getcfg" ascii wide
		$symbol7 = "_proc_hibernate" ascii wide
		$symbol8 = "_proc_none" ascii wide
		$symbol9 = "_proc_restart" ascii wide
		$symbol10 = "_proc_rmfile" ascii wide
		$symbol11 = "_proc_setcfg" ascii wide
		$symbol12 = "_proc_shell" ascii wide
		$symbol13 = "_proc_sleep" ascii wide
		$symbol14 = "_proc_stop" ascii wide
		$symbol15 = "_proc_testconn" ascii wide
		$symbol16 = "_proc_upload" ascii wide
		$symbol17 = "_proc_upload_content" ascii wide
		$symbol18 = "_sigchild" ascii wide

		$string1 = "/dev/null" ascii wide
		$string2 = "SHELL" ascii wide
		$string3 = "/bin/sh" ascii wide
		$string4 = {2573200a2573200a2573200a2573200a2573200a2573200a2573200a257320} // %s with repeating new lines string
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and
		(any of ($xcrypt*) or 4 of ($symbol*) or (all of ($string*)))
}
