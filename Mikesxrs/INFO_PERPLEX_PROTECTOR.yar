import "pe"
rule INFO_PERPLEX_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Perplex PE-Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e9a2ce9fa89941ed4aa90a0b1fda071e"
		hash = "bc7bffb6b577b2876c760984b03cb2568e918c42"
		hash = "a6b85778185e469b23e0da8d76f7c9019e2c24463d0a52b96b554aaaf2695462"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".perplex" 
            )
        )
}
