import "pe"
rule INFO_EPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Epack packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "5c6078d30b23cc15da0c7db7adcab4b1"
		hash = "7412d67f7501c51535127438eadf27ae03610549"
		hash = "782198d1eda4866e04ce625424176a0d924ef78ab7dbf7351c129e71f36a3eb4"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "!EPack"
            )
        )
}
