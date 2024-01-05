import "pe"
rule INFO_MPRESS_PACKER {
	meta:
		version = "1"
		date = "1/4/24"
		modified = "1/4/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of MPRESS Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/basic-packers-easy-as-pie/"
		hash = "ac61852921c771e1d268b50a5979af49"
		hash = "3041bb48df6a2afc8cd40c24db17f5bf888c0b7a"
		hash = "fb0204d2076d57890c12848ceb39cd6daf40c77c8a434d60e4b6fb4fc113d678"
	strings:
		$STR1 = ".MPRESS1" ascii wide nocase fullword
		$STR2 = ".MPRESS2" ascii wide nocase fullword
  condition:
  	uint16(0) == 0x5A4D or all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2" 
            )
        )
}
