import "pe"
rule INFO_GENTEE_INSTALLER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Gentee Installer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ccefb390d79166a577fc3daf036e902d"
		hash = "11ef5788819e03e9f74ec059261f2a16c3da7d58"
		hash = "a35539d69fce5105782aade3ec061c49d1ecab5e2961e491de87f10802d3da79"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".gentee" 
            )
        )
}
