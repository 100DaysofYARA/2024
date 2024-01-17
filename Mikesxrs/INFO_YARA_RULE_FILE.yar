rule INFO_YARA_RULE_FILE {
	meta:
		version = "1"
		date = "1/14/24"
		modified = "1/14/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Matching YARA rule format File"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$rulename = {72 75 6c 65 [0-50] 7b}
		$condition = "condition:" fullword
	condition:
		filesize < 50KB and all of them
}
