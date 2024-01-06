import "pe"

rule TTP_WIP19_bad_cert {
	meta:
		description = "Matches known bad signing certificate serial number used by China-nexus threat actor WIP19."
		last_modified = "2024-01-05"
    		author = "@petermstewart"
    		DaysofYara = "5/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
		sha256 = "2f2f165ee5b81a101ebda0b161f43b54bc55afd8e4702c9b8056a175a1e7b0e0"
		
	condition:
		uint16(0) == 0x5a4d and
		pe.number_of_signatures > 0 and
		for any sig in pe.signatures:
		(
			sig.serial == "02:10:36:b9:e8:0d:16:ea:7f:8c:f0:e9:06:2b:34:55"
		)
}
