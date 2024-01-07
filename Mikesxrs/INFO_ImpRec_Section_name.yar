import "pe"
rule INFO_ImpRec_Section_name {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of ImpRec created section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "434c3add35ae58605c17dde7cf4c72a4"
		hash = "abe91cb89d2e9d948c912f941cfb2fdf11c0ff4d"
		hash = "509aa1cb0581be5a930b2d03865680bc6060fbe1e5479aa464553e2adcf0c3ee"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".mackt" 
            )
        )
}
