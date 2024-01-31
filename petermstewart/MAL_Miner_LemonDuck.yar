rule MAL_LemonDuck_strings {
	meta:
		description = "Matches strings found in Lemonduck cryptominer samples."
		last_modified = "2024-01-31"
		author = "@petermstewart"
		DaysofYara = "31/100"
		sha256 = "a5de49d6b14b04ba854246e1945ea1cfc8a7e7e254d0974efaba6415922c756f"

	strings:
		$a1 = "stratum+tcp"
		$a2 = "stratum+ssl"
		$b1 = "\"donate-level\":"
		$b2 = "\"health-print-time\":"
		$b3 = "\"retry-pause\":"
		$b4 = "\"nicehash\":"
		$b5 = "\"coin\":"
		$b6 = "\"randomx\":"
		$b7 = "\"opencl\":"
		$b8 = "\"cuda\":"
		$b9 = "This is a test This is a test This is a test"

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		1 of ($a*) and
		8 of ($b*)
}
