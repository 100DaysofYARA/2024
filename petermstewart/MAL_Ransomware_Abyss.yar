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
