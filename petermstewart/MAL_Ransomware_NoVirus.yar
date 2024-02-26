rule MAL_NoVirus_strings {
	meta:
		description = "Matches strings found in ransomware sample uploaded to VirusTotal with filename 'no virus.exe'."
		last_modified = "2024-02-25"
		author = "@petermstewart"
		DaysofYara = "56/100"
		sha256 = "015e546f3ac1350c5b68fedc89e16334a4e456092228e691f054c1a86fefb6c6"
		ref = "https://x.com/malwrhunterteam/status/1745182178474885199"

	strings:
		$a1 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide
		$a2 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide
		$a3 = "wbadmin delete catalog -quiet" wide
		$b1 = "read_it.txt" wide
		$b2 = "(?:[13]{1}[a-km-zA-HJ-NP-Z1-9]{26,33}|bc1[a-z0-9]{39,59})" wide
		$c1 = "Don't worry, you can return all your files!" wide
		$c2 = "All your files like documents, photos, databases and other important are encrypted" wide
		$c3 = "You must follow these steps To decrypt your files" wide
		$c4 = "1) CONTACT US Telegram @CryptoKeeper_Support" wide
		$c5 = "2) Obtain Bitcoin (You have to pay for decryption in Bitcoins." wide
		$c6 = "After payment we will send you the tool that will decrypt all your files.)" wide
		$c7 = "3) Send 500$ worth of btc to the next address:" wide
		$c8 = "17Ym1FfiuXGGWr1SN6enUEEZUwnsuNMUDa" wide

	condition:
		uint16(0) == 0x5a4d and
		8 of them
}
