rule MAL_BlackSuit_strings {
	meta:
		description = "Matches strings found in open-source reporting on BlackSuit Windows and Linux ransomware."
		last_modified = "2024-01-24"
		author = "@petermstewart"
		DaysofYara = "24/100"
		sha256 = "90ae0c693f6ffd6dc5bb2d5a5ef078629c3d77f874b2d2ebd9e109d8ca049f2c"
		sha256 = "1c849adcccad4643303297fb66bfe81c5536be39a87601d67664af1d14e02b9e"
		ref = "https://twitter.com/siri_urz/status/1653692714750279681"
		ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
		ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

	strings:
		$a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
		$b1 = "Good whatever time of day it is!"
		$b2 = "Your safety service did a really poor job of protecting your files against our professionals."
		$b3 = "Extortioner named  BlackSuit has attacked your system."
		$b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
		$b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
		$b6 = "We are able to solve this problem in one touch."
		$b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
		$b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
		$b9 = "You can have a safety review of your systems."
		$b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
		$b11 = "Contact us through TOR browser using the link:"

	condition:
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		$a and
		8 of ($b*)
}

rule MAL_BlackSuit_ransomnote {
	meta:
		description = "Matches strings found in open-source reporting of BlackSuit ransom notes."
		last_modified = "2024-01-25"
		author = "@petermstewart"
		DaysofYara = "25/100"
		ref = "https://twitter.com/siri_urz/status/1653692714750279681"
		ref = "https://twitter.com/Unit42_Intel/status/1653760405792014336"
		ref = "https://www.trendmicro.com/en_us/research/23/e/investigating-blacksuit-ransomwares-similarities-to-royal.html"

	strings:
		$a = "weg7sdx54bevnvulapqu6bpzwztryeflq3s23tegbmnhkbpqz637f2yd.onion"
		$b1 = "Good whatever time of day it is!"
		$b2 = "Your safety service did a really poor job of protecting your files against our professionals."
		$b3 = "Extortioner named  BlackSuit has attacked your system."
		$b4 = "As a result all your essential files were encrypted and saved at a secure server for further use and publishing on the Web into the public realm."
		$b5 = "Now we have all your files like: financial reports, intellectual property, accounting, law actionsand complaints, personal files and so on and so forth."
		$b6 = "We are able to solve this problem in one touch."
		$b7 = "We (BlackSuit) are ready to give you an opportunity to get all the things back if you agree to makea deal with us."
		$b8 = "You have a chance to get rid of all possible financial, legal, insurance and many others risks and problems for a quite small compensation."
		$b9 = "You can have a safety review of your systems."
		$b10 = "All your files will be decrypted, your data will be reset, your systems will stay in safe."
		$b11 = "Contact us through TOR browser using the link:"

	condition:
		filesize < 5KB and
		$a and
		8 of ($b*)
}
