rule MAL_AsyncRAT_strings {
	meta:
		description = "Matches strings found in AsyncRAT samples."
		last_modified = "2024-02-22"
		author = "@petermstewart"
		DaysofYara = "53/100"
		sha256 = "00cdee79a9afc1bf239675ba0dc1850da9e4bf9a994bb61d0ec22c9fdd3aa36f"
		sha256 = "774e4d4af9175367bc3c7e08f4765778c58f1c66b46df88484a6aa829726f570"

	strings:
		$a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide
		$a2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
		$a3 = "bat.exe" wide
		$a4 = "Stub.exe" wide

	condition:
		uint16(0) == 0x5a4d and
		all of them
}
