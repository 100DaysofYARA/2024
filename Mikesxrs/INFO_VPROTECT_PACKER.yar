import "pe"
rule INFO_VPROTECT_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Vprotect Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "83abc83ac4a8a97de062b56f2518a8b1"
		hash = "3275e01497b20161067ad36b964ac719898c0094"
		hash = "99f6d0c080cd05ae1466385b125ccd6744a86c4bae7973441c4147948b8b31e9"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "VProtect" 
            )
        )
}
