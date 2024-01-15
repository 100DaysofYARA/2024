rule INFO_Macho_LOObin_csrutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin csrutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "csrutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}


rule INFO_Macho_LOObin_ditto {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ditto"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ditto" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_dnssd {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dns"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dns-sd" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_dscl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dscl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dscl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
}

rule INFO_Macho_LOObin_dsexport {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin dsexport"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "dsexport" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_GetFileInfo {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin GetFileInfo"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "GetFileInfo" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_hdiutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin hdiutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "hdiutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_ioreg {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ioreg"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ioreg" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_lsregister {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin lsregister"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "lsregister" ascii wide

	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_mdfind {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin mdfind"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "mdfind" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_networksetup {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin networksetup"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "networksetup" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_nscurl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin nscurl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "nscurl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_nvram {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin nvram"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "nvram" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}


rule INFO_Macho_LOObin_osacompile {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin osacompile"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "osacompile" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_osascript {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin osascript"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "osascript" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_pbpaste {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin pbpaste"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "pbpaste" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_plutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin plutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "plutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_profiles {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin profiles"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "profiles" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_safaridriver {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin safaridriver"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "safaridriver" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_screencapture {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin screencapture"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "screencapture" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_SetFile {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin SetFile"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "SetFile" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_softwareupdate {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin softwareupdate"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "softwareupdate" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_spctl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin spctl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "spctl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sqlite3 {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin sqlite3"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "sqlite3" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sshkeygen {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin ssh"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "ssh-keygen" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_sysctl {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin sysctl"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "sysctl" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_tclsh {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin tclsh"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "tclsh" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_textutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin textutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "textutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_tmutil {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin tmutil"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "tmutil" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}

rule INFO_Macho_LOObin_xattr {
	meta:
		author = "Greg Lesnewich"
		description = "find Macho files using LOOBin xattr"
		reference = "https://www.loobins.io/"
		date = "2024-01-12"
		version = "1.0"
		DaysofYARA = "12/100"
	strings:
		$ = "xattr" ascii wide
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		)
		and all of them
	}
