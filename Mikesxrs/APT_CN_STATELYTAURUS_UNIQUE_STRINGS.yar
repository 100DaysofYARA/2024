rule APT_CN_STATELYTAURUS_UNIQUE_STRINGS {
	meta:
		version = "1"
		date = "2/2/24"
		modified = "2/2/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Unique Strings from blogpost"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "VARIES"
		mitre_att = "TA0002, TA0003, TA0004, TA0005, TA0006, TA0007, TA0009, TA0011"
		actor_type = "APT"
		actor = "Stately Taurus, Bronze President, Camaro Dragon, Earth Preta, Mustang Panda, Red Delta, TEMP.Hex, Luminous Moth"
		report = "https://csirt-cti.net/2024/02/01/stately-taurus-continued-new-information-on-cyberespionage-attacks-against-myanmar-military-junta/"
		hash = "b300afb993b501aca5b727b1c964810345cfa5b032f5774251a2570a3ae16995"
		hash = "6811e4b244a0f5c9fac6f8c135fcfff48940e89a33a5b21a552601c2bceb4614"
		hash = "6c90df591f638134db3b48ff1fd7111c366ec069c69ae28ee60d5cdd36408c02"
	strings:
		$STR1 = "14b0a22e33df6fab9"
		$STR2 = "243503098e6d85bd3367b2e25e144954e88d9a0b"
		$STR3 = "n9243503098e6d85bd3367b2e25e144954e88d9a0b"
		$STR4 = "bd3367b2e25e144954e88d9a0b3503098e6d85bd3367b2e25e"
		$STR5 = "144954e88d9a0b"
		$STR6 = "JeffreyEpsteindocumentsunsealed"
		$STR7 = "ChrisSanders"
	condition:
		any of them
}
