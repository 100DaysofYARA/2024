import "pe"
rule INFO_ENIGMA_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Enigma Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "5b23d6b5fb0b7195231ec24d5861ef71"
		hash = "6b60c43b3e0e9e56d7b378821ba497ed154f3195"
		hash = "afefa95de9d2a7f8f78b2d07edb791f04cae8910e32925167a015508ece2d790"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma1" or 
                pe.sections[i].name == ".enigma2" 
            )
        )
}
