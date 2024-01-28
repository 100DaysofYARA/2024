rule MAL_Kuiper_strings {
	meta:
		description = "Matches strings found in Stairwell analysis blog post of Kuiper ransomware."
		last_modified = "2024-01-22"
		author = "@petermstewart"
		DaysofYara = "22/100"
		ref = "https://stairwell.com/resources/kuiper-ransomware-analysis-stairwells-technical-report/"

	strings:
		$a1 = "kuiper"
		$a2 = "README_TO_DECRYPT.txt"
		$a3 = "vssadmin delete shadows /all /quiet"
		$a4 = "wevtutil cl application"
		$a5 = "wbadmin delete catalog -quiet"
		$a6 = "bcdedit /set {default} recoveryenabled No"
		$a7 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest"
		$a8 = "wevtutil cl securit"
		$a9 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures"
		$a10 = "wbadmin DELETE SYSTEMSTATEBACKUP"
		$a11 = "wevtutil cl system"
		$a12 = "vssadmin resize shadowstorage /for="
		$a13 = "\\C$\\Users\\Public\\safemode.exe"
		$a14 = "process call create \"C:\\Users\\Public\\safemode.exe -reboot no\""

	condition:
		uint16(0) == 0x5a4d and
		10 of them
}
