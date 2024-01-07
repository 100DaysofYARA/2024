import "pe"
rule INFO_THEMIDA_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Themida Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ff121cdd62bafa619e2485c397098f7f"
		hash = "d0b5ad3f3141b4390480f52b456864ffc322e65e"
		hash = "d0bf3cb889cff503c8cffe2a883f191200506a6ef34db658c7173ee08da68fc3"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "Themida" or
                pe.sections[i].name == ".Themida"
            )
        )
}
