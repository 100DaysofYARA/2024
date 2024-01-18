rule INFO_Macho_Hunting_Osascript
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for potential scripting interfaces like osascript"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$ = "osascript" nocase ascii wide
		$ = "osacompile" nocase ascii wide
		$ = ".scpt" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and any of them
}

rule INFO_Macho_Hunting_AppleScript_URL
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for potential scripting interfaces like AppleScript"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$ = "applescript://" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and any of them
}


rule INFO_Macho_Hunting_Python
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like python"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"

	strings:
		$str = "python" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
rule INFO_Macho_Hunting_Ruby
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like Ruby"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$str = "Ruby" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
rule INFO_Macho_Hunting_Perl
{
	meta:
		author = "Greg Lesnewich"
		description = "checking Macho files for additional execution strings like perl"
		date = "2024-01-10"
		version = "1.0"
		DaysofYARA = "11/100"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$str = "perl" nocase ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}



rule INFO_Macho_Execution_BinBash
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like bash shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/bash" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		)
		and all of them
}

rule INFO_Macho_Execution_Bin_sh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like sh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/sh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_BinZsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like zsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/zsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}


rule INFO_Macho_Execution_Bin_tcsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like tcsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/tcsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}


rule INFO_Macho_Execution_BinKsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like ksh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/ksh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_Bincsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like csh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "bin/csh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}

rule INFO_Macho_Execution_tclsh
{
	meta:
		author = "Greg Lesnewich"
		date = "2023-02-01"
		version = "1.0"
		DaysofYARA = "11/100"
		description = "checking Macho files for additional execution strings like tclsh shell"
		reference = "https://speakerdeck.com/heirhabarov/hunting-for-macos-attack-techniques-part-1-initial-access-execution-credential-access-persistence?slide=31"

	strings:
		$ = "usr/bin/tclsh" ascii wide
		$ = "bin/tclsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca	// Mach-O FAT_CIGAM
		) and all of them
}
