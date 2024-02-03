private rule last_modifed
{
	meta:
		version = "1"
		date = "1/29/24"
		modified = "1/29/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to write rule that will parse the last modified field in document files"
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
		$modified = /\<dc\:lastModifiedBy\>.{1,60}\<\/dc\lastModifiedBy\>/
	condition:
		$modified
}
