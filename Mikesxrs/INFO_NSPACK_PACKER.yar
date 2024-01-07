import "pe"
rule INFO_NSPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of NSPACK Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ec7a1955e6a826d407b225111c1a384d"
		hash = "9310d50074d488797703f8b4ab6229a74e7c2127"
		hash = "f71d3c3db66f57a13924571d50c6816f8bf515327e57267782911ba446b5b3eb"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nsp0" or 
                pe.sections[i].name == ".nsp1" or
                pe.sections[i].name == ".nsp2" or
                pe.sections[i].name == "nsp0" or 
                pe.sections[i].name == "nsp1" or
                pe.sections[i].name == "nsp2"
            )
        )
}
