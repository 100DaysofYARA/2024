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
