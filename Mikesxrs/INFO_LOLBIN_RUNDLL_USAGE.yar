rule INFO_LOLBIN_RUNDLL_USAGE {
	meta:
		version = "1"
		date = "1/16/24"
		modified = "1/16/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Attempting to find rundll32 LOLBIN usage"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://redcanary.com/blog/lolbins-abuse/"
		hash = ""
		hash = ""
		hash = ""
	strings:
		$rundll32 = "C:\\WINDOWS\\system32\\rundll32.exe" nocase wide
		$rundll64 = "C:\\Windows\\SysWOW64\\Rundll32.exe" nocase wide
	condition:
		any of them
}
