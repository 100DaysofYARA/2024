rule HUNT_Signal_Desktop_File_References {
	meta:
		description = "Contains references to sensitive database and key files used by Signal desktop application."
		last_modified = "2024-01-28"
		author = "@petermstewart"
		DaysofYara = "28/100"
		ref = "https://www.alexbilz.com/post/2021-06-07-forensic-artifacts-signal-desktop/"
		ref = "https://www.bleepingcomputer.com/news/security/signal-desktop-leaves-message-decryption-key-in-plain-sight/"

	strings:
		$win_db = "\\AppData\\Roaming\\Signal\\sql\\db.sqlite" nocase ascii wide
		$win_key = "\\AppData\\Roaming\\Signal\\config.json" nocase ascii wide
		$lin_db = "config/Signal/sql/db.sqlite" nocase ascii wide
		$lin_key = "config/Signal/config.json" nocase ascii wide
		$macos_db = "/Signal/sql/db.sqlite" nocase ascii wide
		$macos_key = "/Signal/config.json" nocase ascii wide

	condition:
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of them
}
