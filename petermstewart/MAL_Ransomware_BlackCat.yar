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

rule MAL_BlackCat_Lin_strings {
	meta:
		description = "Matches strings found in BlackCat ransomware Linux samples operated by ALPHV"
		last_modified = "2024-01-15"
		author = "@petermstewart"
		DaysofYara = "15/100"
		sha256 = "3a08e3bfec2db5dbece359ac9662e65361a8625a0122e68b56cd5ef3aedf8ce1"
		sha256 = "f8c08d00ff6e8c6adb1a93cd133b19302d0b651afd73ccb54e3b6ac6c60d99c6"

	strings:
		$a1 = "encrypt_app::linux"
		$a2 = "src/bin/encrypt_app/linux.rs"
		$a3 = "locker::core::os::linux::command"
		$b1 = "note_file_name"
		$b2 = "note_full_text"
		$b3 = "note_short_text"
		$b4 = "default_file_cipher"
		$b5 = "default_file_mode"
		$b6 = "enable_esxi_vm_kill"
		$b7 = "enable_esxi_vm_snapshot_kill"

	condition:
		filesize > 1MB and filesize < 3MB and
		uint32(0) == 0x464c457f and
		2 of ($a*) and
		5 of ($b*)
}
