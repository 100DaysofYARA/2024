rule PUP_RMM_ScreenConnect_msi {
	meta:
		description = "Matches strings found in ScreenConnect MSI packages, often abused for unauthorised access."
		last_modified = "2024-03-02"
		author = "@petermstewart"
		DaysofYara = "62/100"
		sha256 = "80b6ec0babee522290588e324026f7c16e3de9d178b9e846ae976ab432058ce7"
		sha256 = "f8c2b122da9c9b217eada5a1e5fde92678925f1bb2ea847253538ffda274f0b9"

	strings:
		$magic = { d0 cf 11 e0 a1 b1 1a e1 }
		$clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$a1 = "ScreenConnect.Client.dll"
		$a2 = "ScreenConnect.WindowsClient.exe"
		$a3 = "Share My Desktop"
		$a4 = "Grab a still image of the remote machine desktop"

	condition:
		$magic at 0 and
		all of them
}

rule PUP_RMM_AnyDesk_exe {
	meta:
		description = "Matches AnyDesk remote management tool, often abused for unauthorised access."
		last_modified = "2024-03-03"
		author = "@petermstewart"
		DaysofYara = "63/100"
		sha256 = "5beab9f13976d174825f9caeedd64a611e988c69f76e63465ed10c014de4392a"
		sha256 = "7a719cd40db3cf7ed1e4b0d72711d5eca5014c507bba029b372ade8ca3682d70"

	strings:
		$pdb = "C:\\Buildbot\\ad-windows-32\\build\\release\\app-32\\win_loader\\AnyDesk.pdb"
		$a1 = "my.anydesk.com"
		$a2 = "AnyDesk Software GmbH" wide

	condition:
		uint16(0)==0x5a4d and
		all of them
}

rule PUP_RMM_AteraAgent_msi {
	meta:
		description = "Matches strings found in Atera Agent remote management tool installer, often abused for unauthorised access."
		last_modified = "2024-03-04"
		author = "@petermstewart"
		DaysofYara = "64/100"
		sha256 = "91d9c73b804aae60057aa93f4296d39ec32a01fe8201f9b73f979d9f9e4aea8b"

	strings:
		$magic = { d0 cf 11 e0 a1 b1 1a e1 }
		$clsid = { 84 10 0c 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
		$a1 = "AteraAgent"
		$a2 = "This installer database contains the logic and data required to install AteraAgent."

	condition:
		$magic at 0 and
		all of them
}
