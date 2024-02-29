rule MAL_SystemBC_Win_strings {
	meta:
		description = "Matches strings found in SystemBC malware Windows samples."
		last_modified = "2024-02-29"
		author = "@petermstewart"
		DaysofYara = "60/100"
		sha256 = "876c2b332d0534704447ab5f04d0eb20ff1c150fd60993ec70812c2c2cad3e6a"
		sha256 = "b9d6bf45d5a7fefc79dd567d836474167d97988fc77179a2c7a57f29944550ba"

	strings:
		$a1 = "User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0"
		$a2 = "GET %s HTTP/1.0"
		$a3 = "Host: %s"
		$a4 = "Connection: close"
		$b1 = "BEGINDATA"
		$b2 = "HOST1:"
		$b3 = "HOST2:"
		$b4 = "PORT1:"
		$b5 = "DNS:"
		$b6 = "-WindowStyle Hidden -ep bypass -file"

	condition:
		uint16(0) == 0x5a4d and
		all of ($a*) or
		5 of ($b*)
}
