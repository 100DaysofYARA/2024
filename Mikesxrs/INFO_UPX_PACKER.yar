import "pe"
rule INFO_UPX_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of UPX packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "24198b5d069222522a509a10129201ec"
		hash = "e99e91b6fc3d02e47e998be8995cd11b3293aaed"
		hash = "daa6a70b32cde752ad0e75bd36504b7953d8e077792080a6e700cff5f7321b01"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "UPX!" or
                pe.sections[i].name == "UPX0" or
                pe.sections[i].name == "UPX1" or 
                pe.sections[i].name == "UPX2" or 
                pe.sections[i].name == "UPX3" or 
                pe.sections[i].name == ".UPX0" or 
                pe.sections[i].name == ".UPX1" or 
                pe.sections[i].name == ".UPX2"
            )
        )
}
