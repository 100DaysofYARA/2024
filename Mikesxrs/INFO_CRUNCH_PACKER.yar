import "pe"
rule INFO_CRUNCH_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Crunch 2.0 Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "22c4b235e0de288617767567125706bf"
		hash = "3bd508a7733e22bba1c49f0934317d11b9e34ad4"
		hash = "94f3b1421488727995d368fb32909f0a0b04e447ba33075c98592e769db78595"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "BitArts"
            )
        )
}
