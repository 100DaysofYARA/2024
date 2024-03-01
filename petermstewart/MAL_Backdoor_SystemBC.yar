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

rule MAL_SystemBC_Lin_strings {
	meta:
		description = "Matches strings found in SystemBC malware Linux samples."
		last_modified = "2024-03-01"
		author = "@petermstewart"
		DaysofYara = "61/100"
		sha256 = "cf831d33e7ccbbdc4ec5efca43e28c6a6a274348bb7bac5adcfee6e448a512d9"
		sha256 = "b68bfd96f2690058414aaeb7d418f376afe5ba65d18ee4441398807b06d520fd"

	strings:
		$a1 = "Rc4_crypt" fullword
		$a2 = "newConnection" fullword
		$a3 = "/tmp/socks5.sh" fullword
		$a4 = "cat <(echo '@reboot echo" fullword
		$a5 = "socks5_backconnect" fullword

	condition:
		uint32(0) == 0x464c457f and
		2 of them
}
