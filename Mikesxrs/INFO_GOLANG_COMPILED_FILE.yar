rule INFO_GOLANG_COMPILED_FILE {
	meta:
		version = "1"
		date = "1/2/24"
		modified = "1/2/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "https://www.sentinelone.com/labs/alphagolang-a-step-by-step-go-malware-reversing-methodology-for-ida-pro/"
		author = "@x0rc1sm"
		description = "Regex of Build ID format for the detection of GO lang compiled files"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://unit42.paloaltonetworks.com/the-gopher-in-the-room-analysis-of-golang-malware-in-the-wild/"
		hash = "2f3ea8b9a4c06905f379ce6b175f686bc31365284b7b2d3de089e24ef530af8e PE GoLang"
		hash = "3098e579356f6292efe007d241dad5aefdc9404d5922f8e0e4b3cdb8adcb6b97 Macho GoLang"
		hash = "f48f86a18986f1b827a8759ba8906a6cdc5a2d5b4c27cc175c06866821eaf7d4 ELF GoLang"
	strings:
		$buildid = "go.buildid"
		$regexGoBuildId = /Go build ID: \"[a-zA-Z0-9\/_-]{40,120}\"/ ascii wide
  condition:
  	(
			(uint16(0) == 0x5a4d) or 
			(uint32(0) == 0x464c457f) or 
			(uint32(0) == 0xfeedfacf) or 
			(uint32(0) == 0xcffaedfe) or 
			(uint32(0) == 0xfeedface) or 
			(uint32(0) == 0xcefaedfe) 
		)
		and
		  (#regexGoBuildId == 1 or #buildid == 1)
}
