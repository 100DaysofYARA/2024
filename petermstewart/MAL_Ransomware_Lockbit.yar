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

rule MAL_Lockbit_2_macOS_strings {
	meta:
		description = "Matches strings found in Lockbit ransomware macOS sample."
		last_modified = "2024-01-18"
		author = "@petermstewart"
		DaysofYara = "18/100"
		sha256 = "3e4bbd21756ae30c24ff7d6942656be024139f8180b7bddd4e5c62a9dfbd8c79"

	strings:
		$a1 = "lockbit"
		$a2 = "restore-my-files.txt"
		$a3 = "_I_need_to_bypass_this_"
		$a4 = "kLibsodiumDRG"
		$b = "_Restore_My_Files_"

	condition:
		filesize < 500KB and
		(uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		#b > 4 and
		all of ($a*)
}

rule MAL_Lockbit_2_ransomnote {
	meta:
		description = "Matches strings found in Lockbit 2.0 ransom note samples."
		last_modified = "2024-01-19"
		author = "@petermstewart"
		DaysofYara = "19/100"

	strings:
		$a = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion"
		$b1 = "https://bigblog.at"
		$b2 = "http://lockbitsup4yezcd5enk5unncx3zcy7kw6wllyqmiyhvanjj352jayid.onion"
		$b3 = "http://lockbitsap2oaqhcun3syvbqt6n5nzt7fqosc6jdlmsfleu3ka4k2did.onion"
		$c1 = "LockBit 2.0 Ransomware"
		$c2 = "Your data are stolen and encrypted"
		$c3 = "The data will be published on TOR website"
		$c4 = "if you do not pay the ransom"
		$c5 = "You can contact us and decrypt on file for free on these TOR sites"
		$c6 = "Decryption ID:"

	condition:
		filesize < 5KB and
		$a and
		2 of ($b*) and
		5 of ($c*)
}
