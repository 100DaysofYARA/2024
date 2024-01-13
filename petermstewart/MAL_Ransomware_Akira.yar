rule MAL_Akira_strings {
	meta:
		description = "Matches strings found in Akira ransomware sample."
		last_modified = "2024-01-12"
                author = "@petermstewart"
                DaysofYara = "12/100"
                sha256 = "3c92bfc71004340ebc00146ced294bc94f49f6a5e212016ac05e7d10fcb3312c"

	strings:
		$a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
		$a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$b = "powershell.exe -Command \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\""
		$c1 = "This is local disk:" wide
		$c2 = "This is network disk:" wide
		$c3 = "This is network path:" wide
		$c4 = "Not allowed disk:" wide

	condition:
		filesize < 2MB and
		uint16(0) == 0x5a4d and
		1 of ($a*) and
		$b and
		2 of ($c*)
}

rule MAL_Akira_ransomnote {
	meta:
		description = "Matches strings found in Akira ransom note sample."
		last_modified = "2024-01-13"
		author = "@petermstewart"
		DaysofYara = "13/100"

	strings:
		$a1 = "akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id.onion"
		$a2 = "akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion"
		$b1 = "Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead"
		$b2 = "all your backups - virtual, physical - everything that we managed to reach - are completely removed"
		$b3 = "Moreover, we have taken a great amount of your corporate data prior to encryption"
		$b4 = "Well, for now let's keep all the tears and resentment to ourselves and try to build a constructive dialogue"
		$b5 = "We're fully aware of what damage we caused by locking your internal sources"
		$b6 = "At the moment, you have to know"
		$b7 = "Dealing with us you will save A LOT due to we are not interested in ruining your financially"
		$b8 = "We will study in depth your finance, bank & income statements, your savings, investments etc. and present our reasonable demand to you"
		$b9 = "If you have an active cyber insurance, let us know and we will guide you how to properly use it"
		$b10 = "Also, dragging out the negotiation process will lead to failing of a deal"
		$b11 = "Paying us you save your TIME, MONEY, EFFORTS and be back on track within 24 hours approximately"
		$b12 = "Our decryptor works properly on any files or systems, so you will be able to check it by requesting a test decryption service from the beginning of our conversation"
		$b13 = "If you decide to recover on your own, keep in mind that you can permanently lose access to some files or accidently corrupt them - in this case we won't be able to help"
		$b14 = "The security report or the exclusive first-hand information that you will receive upon reaching an agreement is of a great value"
		$b15 = "since NO full audit of your network will show you the vulnerabilities that we've managed to detect and used in order to get into, identify backup solutions and upload your data"
		$b16 = "As for your data, if we fail to agree, we will try to sell personal information/trade secrets/databases/source codes"
		$b17 = "generally speaking, everything that has a value on the darkmarket - to multiple threat actors at ones"
		$b18 = "Then all of this will be published in our blog"
		$b19 = "We're more than negotiable and will definitely find the way to settle this quickly and reach an agreement which will satisfy both of us"
		$b20 = "If you're indeed interested in our assistance and the services we provide you can reach out to us following simple instructions"
		$b21 = "Install TOR Browser to get access to our chat room"
		$b22 = "Keep in mind that the faster you will get in touch, the less damage we cause"

	condition:
		filesize < 100KB and
		1 of ($a*) and
		18 of ($b*)
}
