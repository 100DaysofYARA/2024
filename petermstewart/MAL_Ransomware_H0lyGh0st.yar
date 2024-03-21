rule MAL_H0lyGh0st_SiennaPurple_strings {
	meta:
		description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
		last_modified = "2024-03-17"
		author = "@petermstewart"
		DaysofYara = "77/100"
		sha256 = "99fc54786a72f32fd44c7391c2171ca31e72ca52725c68e2dde94d04c286fccd"
		ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

	strings:
		$pdb = "M:\\ForOP\\attack(utils)\\attack tools\\Backdoor\\powershell\\btlc_C\\Release\\btlc_C.pdb"
		$a1 = "matmq3z3hiovia3voe2tix2x54sghc3tszj74xgdy4tqtypoycszqzqd.onion"
		$a2 = "H0lyGh0st@mail2tor.com"
		$b1 = "We are <HolyGhost>"
		$b2 = "All your important files are stored and encrypted"
		$b3 = "Do not try to decrypt using third party software, it may cause permanent data lose"
		$b4 = "To Decrypt all device, Contact us"
		$b5 = "or install tor browser and visit"

	condition:
		uint16(0) == 0x5a4d and
		6 of them
}

rule MAL_H0lyGh0st_SiennaBlue_strings {
	meta:
		description = "Matches strings found in SiennaPurple variant of H0lyGh0st ransomware binaries."
		last_modified = "2024-03-18"
		author = "@petermstewart"
		DaysofYara = "78/100"
		sha256 = "f8fc2445a9814ca8cf48a979bff7f182d6538f4d1ff438cf259268e8b4b76f86"
		sha256 = "bea866b327a2dc2aa104b7ad7307008919c06620771ec3715a059e675d9f40af"
		ref = "https://blogs.blackberry.com/en/2022/08/h0lygh0st-ransomware"

	strings:
		$a = ".h0lyenc"
		$b1 = "Please Read this text to decrypt all files encrypted"
		$b2 = "We have uploaded all files to cloud"
		$b3 = "Don't worry, you can return all of your files immediately if you pay"
		$b4 = "If you want to restore all of your files, Send mail to"
		$b5 = "with your Id. Your ID is"
		$b6 = "Or install tor browser and contact us with your id or "
		$b7 = "(If all of pcs in your company are encrypted)"
		$b8 = "Our site : "
		$b9 = "H0lyGh0stWebsite"
		$b10 = "After you pay, We will send unlocker with decryption key"

	condition:
		uint16(0) == 0x5a4d and
		$a and
		7 of them
}
