import "pe"

rule APT_CN_TA410_REVOKED_CERTIFICATE {
	meta:
		version = "1"
		date = "1/27/24"
		modified = "1/27/24"
		status = "DEVELOPMENT"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Revoked Certificate Used to sign QuasarRAT"
		category = "malware"
		malware_type = "BACKDOOR"
		malware_family = "QuasarRAT"
		mitre_att = "TA0004, TA0005, TA0007, TA0009, TA0011"
		actor_type = "APT"
		actor = "TA410"
		report = "https://www.welivesecurity.com/2022/04/27/lookback-ta410-umbrella-cyberespionage-ttps-activity/"
		hash = "a7f147bec8b27c3f7183fb23dd17e444"
		hash = "5379fbb0e02694c524463fdf7f267a7361ecdd68"
		hash = "06eb951a9c5d3ce99182d535c5d714cc4e1aae53ef9fe51838189b41fc08380b"
	condition:
		uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_signatures) : (pe.signatures[i].serial == "4e:d8:73:0f:4e:1b:85:58:cd:1c:b0:10:7b:5f:77:6b")
}
