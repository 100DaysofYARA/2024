rule MAL_AsyncRAT_strings {
	meta:
		description = "Matches strings found in AsyncRAT samples."
		last_modified = "2024-02-22"
		author = "@petermstewart"
		DaysofYara = "53/100"
		sha256 = "00cdee79a9afc1bf239675ba0dc1850da9e4bf9a994bb61d0ec22c9fdd3aa36f"
		sha256 = "774e4d4af9175367bc3c7e08f4765778c58f1c66b46df88484a6aa829726f570"

	strings:
		$a1 = "/c schtasks /create /f /sc onlogon /rl highest /tn" wide
		$a2 = "\\nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" wide
		$a3 = "bat.exe" wide
		$a4 = "Stub.exe" wide

	condition:
		uint16(0) == 0x5a4d and
		all of them
}

rule MAL_AsyncRAT_Github_release {
	meta:
		description = "Matches strings found in AsyncRAT Github release."
		last_modified = "2024-02-23"
		author = "@petermstewart"
		DaysofYara = "54/100"
		sha256 = "06899071233d61009a64c726a4523aa13d81c2517a0486cc99ac5931837008e5"
		ref = "https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp"
        
	strings:
		$a1 = "NYAN-x-CAT"
		$a2 = "This program is distributed for educational purposes only."
		$a3 = "namespace AsyncRAT"
		$b1 = "[!] If you wish to upgrade to new version of AsyncRAT, You will need to copy 'ServerCertificate.p12'." wide
		$b2 = "[!] If you lose\\delete 'ServerCertificate.p12' certificate you will NOT be able to control your clients, You will lose them all." wide
		$b3 = "AsyncRAT | Dot Net Editor" wide
		$b4 = "XMR Miner | AsyncRAT" wide
		$b5 = "SEND A NOTIFICATION WHEN CLIENT OPEN A SPECIFIC WINDOW" wide
		$b6 = "Popup UAC prompt?" wide
		$b7 = "AsyncRAT | Unistall" wide
		$b8 = "recovered passwords successfully @ ClientsFolder" wide
	
	condition:
		uint16(0) == 0x5a4d and
		all of ($a*) or
		6 of ($b*)
}
