rule MAL_Royal_strings {
	meta:
		description = "Matches strings found in Windows and Linux samples of Royal ransomware."
		last_modified = "2024-01-20"
		author = "@petermstewart"
		DaysofYara = "20/100"
		sha256 = "312f34ee8c7b2199a3e78b4a52bd87700cc8f3aa01aa641e5d899501cb720775"
		sha256 = "9db958bc5b4a21340ceeeb8c36873aa6bd02a460e688de56ccbba945384b1926"
		sha256 = "b57e5f0c857e807a03770feb4d3aa254d2c4c8c8d9e08687796be30e2093286c"

	strings:
		$a = "royal2xthig3ou5hd7zsliqagy6yygk2cdelaxtni2fyad6dpmpxedid.onion"
		$b1 = "If you are reading this, it means that your system were hit by Royal ransomware"
		$b2 = "Please contact us via :"
		$b3 = "In the meantime, let us explain this case"
		$b4 = "It may seem complicated, but it is not!"
		$b5 = "Most likely what happened was that you decided to save some money on your security infrastructure"
		$b6 = "Alas, as a result your critical data was not only encrypted but also copied from your systems on a secure server"
		$b7 = "From there it can be published online"
		$b8 = "Then anyone on the internet from darknet criminals, ACLU journalists, Chinese government"
		$b9 = "and even your employees will be able to see your internal documentation: personal data, HR reviews, internal lawsuitsand complains, financial reports, accounting, intellectual property, and more"
		$b10 = "Fortunately we got you covered!"
		$b11 = "Royal offers you a unique deal.For a modest royalty(got it; got it ? )"
		$b12 = "Try Royal today and enter the new era of data security"
		$b13 = "We are looking to hearing from you soon"

	condition:
		filesize > 2000KB and filesize < 3500KB and
		(uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
		$a and
		10 of ($b*)
}
