import "pe"
rule INFO_EPL_BUILD {
	meta:
		version = "1"
		date = "1/6/24"
		modified = "1/6/24"
		status = "RELEASED"
		sharing = "TLP:CLEAR"
		source = "n/a"
		author = "@x0rc1sm"
		description = "Detection of Built with EPL renamed section names"
		category = "info"
		malware_type = "N/A"
		mitre_att = "N/A"
		actor_type = "N/A"
		actor = "N/A"
		report = "https://www.hexacorn.com/blog/2016/12/15/pe-section-names-re-visited/"
		hash = "cab2bfd427c4f300f4fac81150a4f771"
		hash = "5bea3b19e592a1beef2ca96ce00706f22dc23cbc"
		hash = "73e1de247b452acd32872537084cdaf97bf8a4362a549b00b173560a2b82ab1d"
  condition:
  	uint16(0) == 0x5a4d and for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".ecode" or 
                pe.sections[i].name == ".edata" 
            )
        )
}
