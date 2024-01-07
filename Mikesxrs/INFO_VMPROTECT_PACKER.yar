import "pe"
rule INFO_VMPROTECT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of VMProtect packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "107537459b6745600eb335ae5e83d340"
		hash = "565ff1685082d3323b54103d7b9ec88d8659b6a2"
		hash = "7442abeabd2a3db17f8f2bec66dfbd8af4988426f3768186bbcf94cdaeb51232"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1" or
                pe.sections[i].name == ".vmp2"
            )
        )
}
