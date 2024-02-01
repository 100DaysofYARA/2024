rule INFO_CVE_MENTION
{
	meta:
		version = "1"
		date = "1/31/24"
		modified = "1/31/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to find mentions of CVE-####-#### in files"
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
		$CVE = /CVE[-_]\d{4}[-_]\d{4}/ ascii wide
	condition:
		$CVE
}
