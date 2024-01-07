import "pe"
rule INFO_ASPACK_PACKER {
	meta:
		version = "1"
		date = "1/5/24"
		modified = "1/5/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of ASPACK Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "b456385b1e0cb6c85066b7618e52758a"
		hash = "9ff07edb51a737e4a314cc0e495788b8c7b8d02c"
		hash = "866028bad1dd43edb256416a71896584e02294cba419dd508a8a2afc81ac5ebc"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack" or
                pe.sections[i].name == ".adata" or
                pe.sections[i].name == "ASPack" or
                pe.sections[i].name == ".ASPack"
            )
        )
}
