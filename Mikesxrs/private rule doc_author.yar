private rule doc_author
{
	meta:
		version = "1"
		date = "1/30/24"
		modified = "1/30/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "N/A"
		author = "@x0rc1sm"
		description = "Attempting to write rule that will parse the document author in document files"
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
		$author = /\<dc\:creator\>.{1,60}\<\/dc\:creator\>/
	condition:
		$author
}
