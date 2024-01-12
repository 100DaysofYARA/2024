rule MAL_Akira_strings {
	meta:
		description = "Matches strings found in Akira ransomware sample."
		last_modified = "2024-01-12"
                author = "@petermstewart"
                DaysofYara = "12/100"
                sha256 = "3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c"

	strings:
		$a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
		$a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$b = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
		$c1 = "This is local disk:" wide
		$c2 = "This is network disk:" wide
		$c3 = "This is network path:" wide
		$c4 = "Not allowed disk:" wide

	condition:
		filesize < 2MB and
		uint16(0) == 0x5a4d and
		1 of ($a*) and
		$b and
		2 of ($c*)
}
