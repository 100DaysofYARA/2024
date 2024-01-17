rule MAL_Lockbit_2_Win_strings {
	meta:
		description = "Matches strings found in Lockbit 2.0 ransomware Windows samples."
		last_modified = "2024-01-17"
		author = "@petermstewart"
		DaysofYara = "17/100"
		sha256 = "36446a57a54aba2517efca37eedd77c89dfc06e056369eac32397e8679660ff7"
		sha256 = "9feed0c7fa8c1d32390e1c168051267df61f11b048ec62aa5b8e66f60e8083af"

	strings:
		$a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
		$b1 = "All your files stolen and encrypted" wide
		$b2 = "for more information see" wide
		$b3 = "RESTORE-MY-FILES.TXT" wide
		$b4 = "that is located in every encrypted folder." wide
		$b5 = "You can communicate with us through the Tox messenger" wide
		$b6 = "If you want to contact us, use ToxID" wide

	condition:
		filesize > 800KB and filesize < 10MB and
		uint16(0) == 0x5a4d and
		$a and
		4 of ($b*)
}
