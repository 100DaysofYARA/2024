rule INFO_PHP_BASE64_EVAL{
	meta:
		version = "1"
		date = "1/19/24"
		modified = "1/19/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Trying to find base64 obfuscation in PHP files"
		category = "INFO"
		malware_type = "N/A"
		malware_family = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.youtube.com/watch?v=BnmVXJQAQu8"
		hash = "6459a462e3511f016266e3e243b1b55d"
		hash = "3cf3cba9cd54916649774b8ac03715fbb92676d6"
		hash = "cda07c66b05bbfb85c23a345386bb526a397e7a8265abd083f7f124b08fd532e"
    strings:
        $str1 = "<?php"
        $str2 = /eval\s?\(\s?base64_decode\s?\("[A-Za-z0-9+\/]{0,500}/
    condition:
    	 $str1 at 0 and filesize < 1MB and $str2
}
