rule TTP_delete_volume_shadow {
	meta:
		description = "Matches references to 'vssadmin delete' commands - used to remove Volume Shadow Copies."
		last_modified = "2024-03-13"
		author = "@petermstewart"
		DaysofYara = "73/100"

	strings:
		$a = "vssadmin delete" ascii wide nocase
		$b = "vssadmin.exe delete" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d and
		any of them
}
