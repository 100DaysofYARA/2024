import "pe"
rule INFO_SEAUSFX_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of SeauSFX Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = ""
		hash = ""
		hash = ""
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".seau" 
            )
        )
}
