rule MAL_AbyssLocker_Lin_strings {
	meta:
		description = "Matches strings found in SentinelOne analysis of Linux variant of the Abyss Locker ransomware."
		last_modified = "2024-02-16"
		author = "@petermstewart"
		DaysofYara = "47/100"
		ref = "https://www.sentinelone.com/anthology/abyss-locker/"

	strings:
		$a1 = "Usage:%s [-m (5-10-20-25-33-50) -v -d] Start Path"
		$b1 = "esxcli vm process list"
		$b2 = "esxcli vm process kill -t=force -w=%d"
		$b3 = "esxcli vm process kill -t=hard -w=%d"
		$b4 = "esxcli vm process kill -t=soft -w=%d"
		$c1 = ".crypt" fullword
		$c2 = "README_TO_RESTORE"

	condition:
		uint32(0) == 0x464c457f and
		all of them
}

rule MAL_AbyssLocker_ransomnote {
	meta:
		description = "Matches strings found in SentinelOne analysis of Abyss Locker note."
		last_modified = "2024-02-17"
		author = "@petermstewart"
		DaysofYara = "48/100"
		ref = "https://www.sentinelone.com/anthology/abyss-locker/"

	strings:
		$a1 = "Your company Servers are locked and Data has been taken to our servers. This is serious."
		$a2 = "Good news:"
		$a3 = "100% of your Server system and Data will be restored by our Decryption Tool;"
		$a4 = "for now, your data is secured and safely stored on our server;"
		$a5 = "nobody in the world is aware about the data leak from your company except you and Abyss Locker team."
		$a6 = "Want to go to authorities for protection?"
		$a7 = "they will do their job properly, but you will not get any win points out of it, only headaches;"
		$a8 = "they will never make decryption for data or servers"
		$a9 = "Also, they will take all of your IT infrastructure as a part of their procedures"
		$a10 = "but still they will not help you at all."
		$a11 = "Think you can handle it without us by decrypting your servers and data using some IT Solution from third-party non-hackers"

	condition:
		filesize < 5KB and
		8 of them
}
