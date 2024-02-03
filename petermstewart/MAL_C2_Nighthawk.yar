rule MAL_Nighthawk_bytes {
	meta:
		description = "Matches hex byte pattern referenced in Proofpoint blog reversing Nighthawk malware."
		last_modified = "2024-02-02"
		author = "@petermstewart"
		DaysofYara = "33/100"
		ref = "https://web.archive.org/web/20221122125826/https://www.proofpoint.com/us/blog/threat-insight/nighthawk-and-coming-pentest-tool-likely-gain-threat-actor-notice"
		sha256 = "9a57919cc5c194e28acd62719487c563a8f0ef1205b65adbe535386e34e418b8"
		sha256 = "0551ca07f05c2a8278229c1dc651a2b1273a39914857231b075733753cb2b988"

	strings:
		//   { 48 8d 0d f9 ff ff ff 51 5a 48 81 c1 20 4e 00 00 48 81 c2 64 27 00 00 ff e2 }
		$a = { 48 8d 0d ?? ff ff ff ?? ?? ?? ?? ?? ?? ?? 00 00 }

	condition:
		filesize > 500KB and filesize < 1MB and
		uint16(0) == 0x5a4d and
		$a
}
