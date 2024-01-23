rule INFO_NESTED_ZIP {
	meta:
		version = "1"
		date = "1/23/24"
		modified = "1/23/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Attempting to find zip(s) inside of zip files, when analyzing in bulk came across double zipped files"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "N/A"
		hash = "f75d2d5b02fa8bfaa8f9f67f48fa95ed"
		hash = "fdca3351e265f125688cefc8ae3e5cfdc79bc567"
    hash = "5aa582f0bb41cfdd621f218ac7f054dd7be78f0b8d228be38a5112a4cc20e4ad"
	strings:
		$header = {50 4b 03 04}
		$zip_hex = {2e 7a 69 70}
		$zip_ascii = ".zip" nocase
		$zip_head1 = {50 4b 01 02}
		$zip_head2 = {50 4b 03 04}
		$zip_head3 = {50 4b 05 06}
		$zip_head4 = {50 4b 07 08}
	condition:
		$header at 0 and ($zip_hex in (30..180) or $zip_ascii in (30..180) or $zip_head1 in (30..180) or $zip_head2 in (30..180) or $zip_head3 in (30..180) or $zip_head4 in (30..180))
}
