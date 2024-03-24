rule MAL_APT_SugarGhost_Loader_strings {
	meta:
		description = "Matches strings found in the DLL loader component of SugarGhost malware."
		last_modified = "2024-03-24"
		author = "@petermstewart"
		DaysofYara = "84/100"
		sha256 = "34cba6f784c8b68ec9e598381cd3acd11713a8cf7d3deba39823a1e77da586b3"
		ref = "https://blog.talosintelligence.com/new-sugargh0st-rat/"

	strings:
		$a1 = "The ordinal %u could not be located in the dynamic link library %s"
		$a2 = "File corrupted!. This program has been manipulated and maybe"
		$a3 = "it's infected by a Virus or cracked. This file won't work anymore."

	condition:
		filesize > 200MB and
		uint16(0) == 0x5a4d and
		all of them
}
