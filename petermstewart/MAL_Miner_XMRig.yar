rule MAL_XMRig_strings {
	meta:
		description = "Matches strings found in XMRig cryptominer samples."
		last_modified = "2024-02-14"
		author = "@petermstewart"
		DaysofYara = "45/100"
		sha256 = "3c54646213638e7bd8d0538c28e414824f5eaf31faf19a40eec608179b1074f1"

	strings:
		$a1 = "Usage: xmrig [OPTIONS]"
		$a2 = "mining algorithm https://xmrig.com/docs/algorithms"
		$a3 = "username:password pair for mining server"
		$a4 = "--rig-id=ID"
		$a5 = "control donate over xmrig-proxy feature"
		$a6 = "https://xmrig.com/benchmark/%s"
		$a7 = "\\xmrig\\.cache\\"
		$a8 = "XMRIG_INCLUDE_RANDOM_MATH"
		$a9 = "XMRIG_INCLUDE_PROGPOW_RANDOM_MATH"
		$a10 = "'h' hashrate, 'p' pause, 'r' resume, 's' results, 'c' connection"

	condition:
		7 of them
}
