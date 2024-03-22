rule MAL_Cactus_strings {
	meta:
		description = "Matches strings found in Cactus ransomware samples."
		last_modified = "2024-03-22"
		author = "@petermstewart"
		DaysofYara = "82/100"
		sha256 = "1ea49714b2ff515922e3b606da7a9f01732b207a877bcdd1908f733eb3c98af3"
		sha256 = "c49b4faa6ac7b5c207410ed1e86d0f21c00f47a78c531a0a736266c436cc1c0a"

	strings:
		$a1 = "vssadmin delete shadows /all /quiet" wide
		$a2 = "WMIC shadowcopy delete" wide
		$a3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" wide
		$a4 = "bcdedit /set {default} recoveryenabled no" wide
		$a5 = "cAcTuS" wide
		$a6 = "CaCtUs.ReAdMe.txt" wide
		$a7 = "schtasks.exe /create /sc MINUTE /mo 5 /rl HIGHEST /ru SYSTEM /tn \"Updates Check Task\" /tr \"cmd /c cd C:\\ProgramData &&" wide
		$a8 = "C:\\Windows\\system32\\schtasks.exe /run /tn \"Updates Check Task\"" wide

	condition:
		uint16(0) == 0x5a4d and
		6 of them
}
