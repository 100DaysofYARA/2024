rule INFO_ANDROID_APK_FILE {
	meta:
		version = "1"
		date = "1/12/24"
		modified = "1/12/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Using header match and common strings in android APK files"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://blog.avast.com/avast-tracks-down-tempting-cedar-spyware"
		hash = "ba2266540f401354f8f013dd222eeef5"
		hash = "7702fb2793fdf02562381f935461317245b7d3cd"
		hash = "2807AB1A912FF0751D5B7C7584D3D38ACC5C46AFFE2F168EEAEE70358DC90006"
	strings:
		$and1 = "classes.dex" ascii
    $and2 = "AndroidManifest" ascii
	condition:
    	uint32be(0) == 0x504B0304 and all of them
}
