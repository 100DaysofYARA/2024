rule HUNT_StripedFly {
	meta:
		description = "Matches strings found in Kaspersky Labs analysis of StripedFly malware."
		last_modified = "2024-02-15"
		author = "@petermstewart"
		DaysofYara = "46/100"
		ref = "https://securelist.com/stripedfly-perennially-flying-under-the-radar/110903/"

	strings:
		$a1 = "gpiekd65jgshwp2p53igifv43aug2adacdebmuuri34hduvijr5pfjad.onion" ascii wide
		$a2 = "ghtyqipha6mcwxiz.onion" ascii wide
		$a3 = "ajiumbl2p2mjzx3l.onion" ascii wide
		$b1 = "HKCU\\Software\\Classes\\TypeLib" ascii wide
		$b2 = "uname -nmo" ascii wide
		$b3 = "%s; chmod +x %s; nohup sh -c \"%s; rm %s\" &>/dev/null" ascii wide
		$b4 = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" ascii wide

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		1 of ($a*) and
		1 of ($b*)
}
