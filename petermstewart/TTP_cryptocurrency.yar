rule TTP_contains_BTC_address {
	meta:
		description = "Matches regex for Bitcoin wallet addresses."
		last_modified = "2024-01-08"
        	author = "@petermstewart"
        	DaysofYara = "8/100"

	strings:
		$r1 = /(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}
