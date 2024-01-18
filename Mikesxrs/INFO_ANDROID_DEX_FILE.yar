rule INFO_ANDROID_DEX_FILE {
	meta:
		version = "1"
		date = "1/13/24"
		modified = "1/13/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "matching the magic header of an Android Dalvik executable (Dex) File"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
		hash = "80cb839529f3f94b9bd9b2e8e2e1adef"
		hash = "b65c320dc02cff4d8f1bd32c135c6f4760d7fd83"
		hash = "10d150c2c59207a9b70835d5e0f47be1ce3c75060c4e9cc00676a83efe00e036"
	condition:
    uint32(0) == 0x0a786564
}
