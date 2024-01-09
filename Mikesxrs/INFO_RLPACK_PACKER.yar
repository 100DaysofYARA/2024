import "pe"
rule INFO_RLPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of RLPack Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "7baf89a70ac2cd239815c9dd0af7a5a6"
		hash = "2b133eaf40810da8d40ac4de3b849799c92c5001"
		hash = "a7a012169519d31fec73db83f628720528c68ce3d5bb462c517c53b8e5f004ba"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".packed" or 
                pe.sections[i].name == ".RLPack"
            )
        )
}
