import "pe"
rule INFO_RAMNIT_VIRUS_MARKER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Ramnit virus marker renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6d6101721e2fcd45ae880f3c89ad4bfe"
		hash = "4d146182111be7fe7ff6e48cebc4ae074c9f9964"
		hash = "d9d8a146e5c0180c076c89a9bedd6b9c311a027794078495447d9ed38cb186ce"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".rmnet" 
            )
        )
}
