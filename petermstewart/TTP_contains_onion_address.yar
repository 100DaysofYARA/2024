rule TTP_contains_onion_address {
	meta:
		description = "Matches regex for .onion addresses associated with Tor Hidden Services."
		last_modified = "2024-01-11"
                author = "@petermstewart"
                DaysofYara = "11/100"

	strings:
		$r1 = /[a-z2-7]{16}\.onion/ fullword ascii wide
		$r2 = /[a-z2-7]{55}d\.onion/ fullword ascii wide

	condition:
		filesize < 5MB and
		any of them
}
