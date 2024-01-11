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

rule TTP_contains_ETH_address {
	meta:
		description = "Matches regex for Ethereum wallet addresses."
		last_modified = "2024-01-09"
        	author = "@petermstewart"
        	DaysofYara = "9/100"

	strings:
		$r1 = /0x[a-fA-F0-9]{40}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}

rule TTP_contains_XMR_address {
	meta:
		description = "Matches regex for Monero wallet addresses."
		last_modified = "2024-01-10"
        	author = "@petermstewart"
        	DaysofYara = "10/100"

	strings:
		$r1 = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ fullword ascii wide

	condition:
		filesize < 5MB and
		$r1
}
