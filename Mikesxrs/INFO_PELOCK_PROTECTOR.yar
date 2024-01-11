import "pe"
rule INFO_PELOCK_PROTECTOR {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of PELock Protector renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "ea86363d5c9688b9d3d32d94e5d49b92"
		hash = "010faf66635243e7f4d337ecc397bfa9db9ce60f"
		hash = "2d8e22c485c4e7ff511c7dae1b4e186d5ec5e2af29e12372d8403b03867c6723"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "PELOCKnt" 
            )
        )
}
