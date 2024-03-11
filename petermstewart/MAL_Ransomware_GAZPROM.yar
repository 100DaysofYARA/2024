rule MAL_GAZPROM_strings {
	meta:
		description = "Matches strings found in Windows samples of GAZPROM ransomware."
		last_modified = "2024-03-11"
		author = "@petermstewart"
		DaysofYara = "71/100"
		sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

	strings:
		$a = ".GAZPROM" wide
		$b1 = "Your files has been encrypted!"
		$b2 = "Need restore? Contact us:"
		$b3 = "Telegram @gazpromlock"
		$b4 = "Dont use any third party software for restoring your data!"
		$b5 = "Do not modify and rename encrypted files!"
		$b6 = "Decryption your files with the help of third parties may cause increased price."
		$b7 = "They add their fee to our and they usually fail or you can become a victim of a scam."
		$b8 = "We guarantee complete anonymity and can provide you with proof and"
		$b9 = "guaranties from our side and our best specialists make everything for restoring"
		$b10 = "but please should not interfere without us."
		$b11 = "If you dont contact us within 24 hours from encrypt your files - price will be higher."
		$b12 = "Your decrypt key:"

	condition:
		filesize > 200KB and filesize < 350KB and
		uint16(0) == 0x5a4d and
		$a and
		10 of ($b*)
}
