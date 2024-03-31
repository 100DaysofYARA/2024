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

rule HUNT_GAZPROM_ascii_art {
	meta:
		description = "Matches ascii art found in GAZPROM ransomware samples."
		last_modified = "2024-03-12"
		author = "@petermstewart"
		DaysofYara = "72/100"
		sha256 = "5d61fcaa5ca55575eb82df8b87ab8d0a1d08676fd2085d4b7c91f4b16898d2f1"

	strings:
		$a1 = "⠄⠄⠄⠄⠄⠄⢀⣤⣴⣶⡶⠖⠂⠉⠓⠶⣦⣄⠄⠄⠄⠄⠄⠄"
		$a2 = "⠄⠄⠄⠄⢀⣼⣿⣿⡿⠋⠈⠄⠄⠄⠄⠄⠈⠛⠷⣦⡀⠄⠄⠄"
		$a3 = "⠄⠄⠄⣴⣿⣿⠟⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢻⣆⠄⠄"
		$a4 = "⠄⠄⢸⣿⣿⠇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⡄⠄"
		$a5 = "⠄⠄⣾⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠻⠄"
		$a6 = "⠄⠄⣿⣿⣇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⠄"
		$a7 = "⢠⣶⣿⣿⡏⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⣀⣀⠄⠄⢸⡇"
		$a8 = "⠈⠟⣻⣿⡇⠄⠄⠠⣤⣴⣿⣿⣿⣷⡆⠄⣰⣿⣟⣛⣿⠆⢸⠃"
		$a9 = "⠄⠄⠘⣫⢳⡀⠄⠄⠄⠉⠈⠋⠉⠉⠑⠄⠉⠁⠉⠁⠁⠄⠘⠄"
		$a10 = "⠄⠄⠄⠪⣼⣷⣄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⡆⠄"
		$a11 = "⠄⠄⠄⠐⢻⣿⢿⠂⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢀⠁⠄"
		$a12 = "⠄⠄⠄⠄⠄⣿⡏⢣⠄⠄⠄⠄⠄⠑⢶⣤⣤⠂⠄⠄⠄⡼⠄⠄"
		$a13 = "⠄⠄⠄⠄⠄⢸⣷⣄⠄⠄⠄⢀⣄⣀⣀⠉⢀⣀⡄⠄⢠⠇⠄⠄"
		$a14 = "⠄⠄⠄⢀⣴⠈⣿⣿⣦⡀⠄⠈⠱⣧⣭⣭⣭⠟⠁⢀⣼⣧⡀⠄"
		$a15 = "⣶⣶⣶⣿⡟⠄⠙⢿⣿⣿⣦⣄⡀⠄⠄⠄⠄⢀⠴⠋⣼⣿⣿⣷"
		$a16 = "⣿⣿⣿⣿⠇⠄⠄⠄⠙⢿⣿⣿⣿⣿⡿⠟⠋⠁⠄⠄⣿⣿⣿⣿"
		$a17 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a18 = "⣿⣿⣿⡟⠄⠄⠄⠄⣀⣴⣿⣯⣉⠉⠄⠄⠄⠄⠄⣸⣿⣿⣿⣿"
		$a19 = "⣿⣿⣿⠄⠄⠈⠄⠄⠄⣿⣿⣿⠋⠄⠄⠄⠄⠄⢸⣿⣿⣿⣿⣿"
		$a20 = "⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿"

	condition:
		all of them
}

rule HUNT_HuntersInternational_ascii_art {
	meta:
		description = "Matches ascii art found in Hunters International ransomware notes."
		last_modified = "2024-03-31"
		author = "@petermstewart"
		DaysofYara = "91/100"

	strings:
        $a1 = "_   _ _   _ _   _ _____ _____ ____  ____"
        $a2 = "| | | | | | | \\ | |_   _| ____|  _ \\/ ___|"
        $a3 = "| |_| | | | |  \\| | | | |  _| | |_) \\___ \\"
        $a4 = "|  _  | |_| | |\\  | | | | |___|  _ < ___) |"
        $a5 = "|_|_|_|\\___/|_|_\\_|_|_|_|_____|_|_\\_\\____/____ ___ ___  _   _    _    _"
        $a6 = "|_ _| \\ | |_   _| ____|  _ \\| \\ | |  / \\|_   _|_ _/ _ \\| \\ | |  / \\  | |"
        $a7 = "| ||  \\| | | | |  _| | |_) |  \\| | / _ \\ | |  | | | | |  \\| | / _ \\ | |"
        $a8 = "| || |\\  | | | | |___|  _ <| |\\  |/ ___ \\| |  | | |_| | |\\  |/ ___ \\| |___"
        $a9 = "|___|_| \\_| |_| |_____|_| \\_\\_| \\_/_/   \\_\\_| |___\\___/|_| \\_/_/   \\_\\_____|"

	condition:
		all of them
}
