import "pe"
rule INFO_UPACK_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Upack packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "dca1503c73cdd9aef6e771786e5676f0"
		hash = "531f62a49097b79292e30d79ca2870165bbd5295"
		hash = "c7afdd5cfd597e820af8c21bdae641ae16ef74c28c4053c87cdd32c779b0da4d"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".Upack" or
                pe.sections[i].name == ".ByDwing"
            )
        )
}
