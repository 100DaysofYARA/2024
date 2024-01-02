rule INFO_Macho_Long_RPATH
{
	meta:
		author = "Greg Lesnewich"
		description = "check for Macho's that contain an RPath load command, where the data size is larger than 30 bytes"
		date = "2024-01-02"
		version = "1.0"
		DaysofYARA = "2/100"
		reference = "https://securelist.com/trojan-proxy-for-macos/111325/"

	strings:
		$rpath = {1c 00 00 80}
	condition:
		(
		uint32(0) == 0xfeedface or // Mach-O MH_MAGIC
		uint32(0) == 0xcefaedfe or // Mach-O MH_CIGAM
		uint32(0) == 0xfeedfacf or // Mach-O MH_MAGIC_64
		uint32(0) == 0xcffaedfe or // Mach-O MH_CIGAM_64
		uint32(0) == 0xcafebabe or // Mach-O FAT_MAGIC
		uint32(0) == 0xbebafeca    // Mach-O FAT_CIGAM
		) and filesize < 10MB and
			$rpath in (0..2000) and uint16(@rpath + 4) >= 30
}
