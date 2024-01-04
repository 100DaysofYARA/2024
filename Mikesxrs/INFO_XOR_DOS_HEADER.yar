rule INFO_XOR_DOS_HEADER {
	meta:
		version = "1"
		date = "1/3/24"
		modified = "1/3/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of This Program Cannot XOR'd"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = ""
		hash = ""
		hash = ""
		hash = ""
    strings:
        $string = "This program cannot be run in DOS mode" xor (0x01-0xff)
    condition:
        $string in (200..filesize)
}
