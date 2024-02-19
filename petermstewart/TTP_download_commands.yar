rule TTP_BITS_Download_command {
	meta:
		description = "Matches strings commonly found when creating new BITS download jobs."
		last_modified = "2024-02-19"
		author = "@petermstewart"
		DaysofYara = "50/100"
		ref = "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/"

	strings:
		$a = "bitsadmin /create" nocase ascii wide
		$b = "/addfile" nocase ascii wide
		$c = "/complete" nocase ascii wide
		$d = "http" nocase ascii wide

	condition:
		all of them
}
