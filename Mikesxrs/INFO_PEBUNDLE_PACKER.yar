import "pe"
rule INFO_PEBUNDLE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PEBundle Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "6f1dfd1d01d868bdce1566e4593a5a36"
		hash = "f77dee085637e35ab8f8240f1169a8ae67d95fdb"
		hash = "481966d0c2f96a1c74b1f7e46aa4b040087cb38307f737dc15563a44bd64f0ad"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "pebundle" or 
                pe.sections[i].name == "PEBundle"
            )
        )
}
