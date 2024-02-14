rule MAL_Sliver_implant_strings {
	meta:
		description = "Matches strings found in open-source Sliver beacon samples."
		last_modified = "2024-02-04"
		author = "@petermstewart"
		DaysofYara = "35/100"
		sha256 = "6037eaaa80348d44a51950b45b98077b3aeb16c66a983a8cc360d079daaaf53e"
		sha256 = "98df535576faab0405a2eabcd1aac2c827a750d6d4c3d76a716c24353bedf0b5"
		sha256 = "789e5fcb242ee1fab8ed39e677d1bf26c7ce275ae38de5a63b4d902c58e512ec"

	strings:
		$a1 = "bishopfox/sliver"
		$a2 = "sliver/protobuf"
		$a3 = "protobuf/commonpbb"
		$b1 = "ActiveC2Fprotobuf:\"bytes,11,opt,name="
		$b2 = "ProxyURLFprotobuf:\"bytes,14,opt,name="
		$b3 = "BeaconJitterNprotobuf:\"varint,3,opt,name="
		$b4 = "BeaconIntervalRprotobuf:\"varint,2,opt,name="
		$b5 = "BeaconIDEprotobuf:\"bytes,8,opt,name="
		$b6 = "BeaconID"
		$b7 = "GetBeaconJitter"
		$b8 = "BeaconRegister"

	condition:
		(filesize > 5MB and filesize < 20MB) and
		(uint16(0) == 0x5a4d or			//PE
		uint32(0) == 0x464c457f or		//ELF
		uint32(0) == 0xfeedface or		//MH_MAGIC
		uint32(0) == 0xcefaedfe or		//MH_CIGAM
		uint32(0) == 0xfeedfacf or		//MH_MAGIC_64
		uint32(0) == 0xcffaedfe or		//MH_CIGAM_64
		uint32(0) == 0xcafebabe or		//FAT_MAGIC
		uint32(0) == 0xbebafeca) and	//FAT_CIGAM
		2 of ($a*) or
		6 of ($b*)
}
