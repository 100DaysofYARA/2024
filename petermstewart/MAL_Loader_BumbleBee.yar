rule MAL_BumbleBee_PowerShell_strings {
	meta:
		description = "Matches strings found in BumbleBee PowerShell loaders."
		last_modified = "2024-01-29"
		author = "@petermstewart"
		DaysofYara = "29/100"
		sha256 = "0ff8988d76fc6bd764a70a7a4f07a15b2b2c604138d9aadc784c9aeb6b77e275"
		sha256 = "9b6125e1aa889f2027111106ee406d08a21c894a83975b785a2b82aab3e2ac52"
		sha256 = "2102214c6a288819112b69005737bcfdf256730ac859e8c53c9697e3f87839f2"
		sha256 = "e9a1ce3417838013412f81425ef74a37608754586722e00cacb333ba88eb9aa7"

	strings:
		$a1 = "[System.Convert]::FromBase64String" ascii wide
		$a2 = "System.IO.Compression.GZipStream" ascii wide
		$elem = "$elem" ascii wide
		$invoke1 = ".Invoke(0,1)" ascii wide
		$invoke2 = ".Invoke(0,\"H\")" ascii wide

	condition:
		filesize > 1MB and filesize < 10MB and
		all of ($a*) and
		#elem > 30 and
		#invoke1 > 30 and
		#invoke2 > 30
}

rule MAL_BumbleBee_DLL_strings {
	meta:
		description = "Matches strings found in BumbleBee DLL sample extracted from initial PowerShell loader."
		last_modified = "2024-01-30"
		author = "@petermstewart"
		DaysofYara = "30/100"
		sha256 = "39e300a5b4278a3ff5fe48c7fa4bd248779b93bbb6ade55e38b22de5f9d64c3c"

	strings:
		$a1 = "powershell -ep bypass -Command"
		$a2 = " -Command \"Wait-Process -Id "
		$a3 = "schtasks.exe /F /create /sc minute /mo 4 /TN \""
		$a4 = "/ST 04:00 /TR \"wscript /nologo"
		$b1 = "SELECT * FROM Win32_ComputerSystemProduct"
		$b2 = "SELECT * FROM Win32_ComputerSystem"
		$b3 = "SELECT * FROM Win32_OperatingSystem"
		$b4 = "SELECT * FROM Win32_NetworkAdapterConfiguration" wide
		$b5 = "SELECT * FROM Win32_NTEventlogFile" wide
		$b6 = "SELECT * FROM Win32_PnPEntity" wide

	condition:
		uint16(0) == 0x5a4d and
		3 of ($a*) and
		4 of ($b*)
}
