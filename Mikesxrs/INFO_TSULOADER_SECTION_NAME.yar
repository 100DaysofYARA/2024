import "pe"
rule INFO_TSULOADER_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of TSULoader renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "717f2c41817163e959e537d6fcc6e47e"
		hash = "8f5f5584141f0ac5e8aa44fec10a66b6df96d3a0"
		hash = "7d403eab8b54213c21fd81950e8e8ba57df5a715251e019869759379202265d5"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".tsuarch" or
                pe.sections[i].name == ".tsustub"
            )
        )
}
