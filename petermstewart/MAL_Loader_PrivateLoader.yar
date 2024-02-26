rule MAL_PrivateLoader_strings {
	meta:
		description = "Matches strings found in PrivateLoader malware samples."
		last_modified = "2024-02-26"
		author = "@petermstewart"
		DaysofYara = "57/100"
		sha256 = "077225467638a420cf29fb9b3f0241416dcb9ed5d4ba32fdcf2bf28f095740bb"
		sha256 = "27c1ed01c767f504642801a7e7a7de8d87dbc87dee88fbc5f6adb99f069afde4"

	strings:
		$ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" ascii wide
		$b1 = ".?AVBase@Rijndael@CryptoPP@@" ascii
		$b2 = ".?AVCannotFlush@CryptoPP@@" ascii
		$b3 = ".?AVBase64Decoder@CryptoPP@@" ascii
		$b4 = ".?AVCBC_Encryption@CryptoPP@@" ascii
		$b5 = "Cleaner" ascii
		$c1 = "Content-Type: application/x-www-form-urlencoded" wide
		$c2 = "https://ipinfo.io/" wide
		$c3 = "https://db-ip.com/" wide
		$c4 = "https://www.maxmind.com/en/locate-my-ip-address" wide
		$c5 = "https://ipgeolocation.io/" wide

	condition:
		uint16(0) == 0x5a4d and
		($ua and 4 of them) or
		all of ($b*) or
		all of ($c*)
}
