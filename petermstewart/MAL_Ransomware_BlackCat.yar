rule MAL_BlackCat_Win_strings {
	meta:
		description = "Matches strings found in BlackCat ransomware Windows samples operated by ALPHV."
		last_modified = "2024-01-14"
		author = "@petermstewart"
		DaysofYara = "14/100"
		sha256 = "2587001d6599f0ec03534ea823aab0febb75e83f657fadc3a662338cc08646b0"
		sha256 = "c3e5d4e62ae4eca2bfca22f8f3c8cbec12757f78107e91e85404611548e06e40"

	strings:
		$a = "bcdedit /set {default}bcdedit /set {default} recoveryenabled"
		$b = "vssadmin.exe Delete Shadows /all /quietshadow_copy::remove_all_vss="
		$c = "wmic.exe Shadowcopy Deleteshadow_copy::remove_all_wmic="
		$d = "deploy_note_and_image_for_all_users="
		$e = "Control Panel\\DesktopWallpaperStyleWallPaperC:\\\\Desktop\\.png"
		$f = "Speed:  Mb/s, Data: Mb/Mb, Files processed: /, Files scanned:"

	condition:
		filesize > 2MB and filesize < 4MB and
		uint16(0) == 0x5a4d and
		all of them
}
