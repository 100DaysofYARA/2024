rule INFO_HTTP_HTTPS_XOR
{
	meta:
		version = "1"
		date = "2/1/24"
		modified = "2/1/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to find http or https obfuscated with single byte XOR"
		category = "info"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "APT"
		actor = "N/A"
		report = "N/A"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$STR1 = "https://" xor (0x01-0xff)
		$STR2 = "http://" xor (0x01-0xff)
	condition:
		any of them
}
