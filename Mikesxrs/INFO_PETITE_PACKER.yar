import "pe"
rule INFO_PETITE_PACKER {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Petite Packer renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "e3048c234c314bd06c60e128216b8578"
		hash = "f9dff7b1d0aaf208ddd1061a22b9ed921118904c"
		hash = "b23f3b7e4f8e97e597da88a9638a3474df7eee5ad2a627b6caf0ef11657c1e1c"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".petite" 
            )
        )
}
