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

rule TTP_PowerShell_Download_command {
	meta:
		description = "Matches strings commonly found in PowerShell download cradles."
		last_modified = "2024-02-20"
		author = "@petermstewart"
		DaysofYara = "51/100"
		ref = "https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters"

	strings:
		$a = "powershell" nocase ascii wide
		$b = "IEX" nocase ascii wide
		$c = "New-Object" nocase ascii wide
		$d = "Net.Webclient" nocase ascii wide
		$e = ".downloadstring(" nocase ascii wide

	condition:
		4 of them
}

rule TTP_Certutil_Download_command {
	meta:
		description = "Matches strings commonly found in certutil.exe download commands."
		last_modified = "2024-02-21"
		author = "@petermstewart"
		DaysofYara = "52/100"
		ref = "https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download"

	strings:
		$a = "certutil" nocase ascii wide
		$b = "-urlcache" nocase ascii wide
		$c = "-split" nocase ascii wide
		$d = "http" nocase ascii wide

	condition:
		all of them
}
