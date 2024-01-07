import "pe"
rule INFO_NEOLITE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Neolite Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6a46ce5d22772e496a82755d235f5e3f"
		hash = "fe01b8cd0c53d390252097f1bf80ae2d3ca5ee67"
		hash = "589fa885e561d591ed908dc39459997e78699d7a2efb4d5b49bc658ced378f9e"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".neolite" or 
                pe.sections[i].name == ".neolit"
            )
        )
}
