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
