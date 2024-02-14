rule TTP_cryptominer_stratum_strings {
	meta:
		description = "Matches stratum URL strings commonly found in cryptominers."
		last_modified = "2024-02-01"
		author = "@petermstewart"
		DaysofYara = "32/100"

	strings:
		$a1 = "stratum+tcp" ascii wide
		$a2 = "stratum+udp" ascii wide
		$a3 = "stratum+ssl" ascii wide

	condition:
		(uint16(0) == 0x5a4d or 		//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		any of them
}
