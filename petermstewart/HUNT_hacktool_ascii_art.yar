rule HUNT_Mimikatz_ascii_art {
	meta:
		description = "Matches ascii art Mimikatz logo."
		last_modified = "2024-03-05"
		author = "@petermstewart"
		DaysofYara = "65/100"
		sha256 = "912018ab3c6b16b39ee84f17745ff0c80a33cee241013ec35d0281e40c0658d9"

	strings:
		$a1 = ".#####." ascii wide
		$a2 = ".## ^ ##."  ascii wide
		$a3 = "## / \\ ##" ascii wide
		$a4 = "## \\ / ##" ascii wide
		$a5 = "'## v ##'" ascii wide
		$a6 = "'#####'" ascii wide

	condition:
		all of them
}
