import "pe"
rule INFO_Y0DA_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Y0da Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "f3dd8e593b91c911556fad99b07dfd1c"
		hash = "eb9e98484a16f56b58236ba89d8edbaf92ccbbc2"
		hash = "d8581aeacd0429934eaa279d14a86d473c405d85cd9904237ba0afafbe6ae8f0"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".yP" or 
                pe.sections[i].name == ".y0da"
            )
        )
}
