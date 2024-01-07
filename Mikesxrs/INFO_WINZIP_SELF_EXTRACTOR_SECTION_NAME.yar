import "pe"
rule INFO_WINZIP_SELF_EXTRACTOR_SECTION_NAME {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of renamed section name added by WinZip Self-Extractor"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "32c956ef503b080620e60905d77d2730"
		hash = "6f7a9d1896d1e454def52bde2f8a05f445b30555"
		hash = "8afdffe950611d59703520b08904ce23d442defb1875468efd57f4639298f1aa"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "_winzip_" 
            )
        )
}
