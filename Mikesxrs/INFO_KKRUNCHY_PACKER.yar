import "pe"
rule INFO_KKRUNCHY_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of kkrunchy packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e2f4598f958cf3647dec16c5d09fb9ae"
		hash = "cb817a994afd5fc552907bfc012e05f814fed4fe"
		hash = "3dd4bfa875061d222e57ae998041b1e22347a226cde106666e2a7a11d642b260"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "kkrunchy" 
            )
        )
}
