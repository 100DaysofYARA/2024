rule MAL_DarkComet_strings {
	meta:
		description = "Matches strings found in DarkComet malware samples."
		last_modified = "2024-02-28"
		author = "@petermstewart"
		DaysofYara = "59/100"
		sha256 = "3e10c254d6536cc63d286b53abfebbf53785e6509ae9fb569920747d379936f6"

	strings:
		$a1 = "I wasn't able to open the hosts file, maybe because UAC is enabled in remote computer!"
		$a2 = "BTRESULTPing|Respond [OK] for the ping !|"
		$a3 = "BTRESULTClose Server|close command receive, bye bye...|"
		$a4 = "BTRESULTHTTP Flood|Http Flood task finished!|"
		$a5 = "BTRESULTMass Download|Downloading File...|"
		$a6 = "ERR|Cannot listen to port, try another one..|"

	condition:
		uint16(0) == 0x5a4d and
		all of them
}
