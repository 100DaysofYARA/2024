rule SUSP_PE_References_Lua
{
	meta:
		author = "Greg Lesnewich"
		date = "2024-01-08"
		version = "1.0"
		DaysOfYara = "9/100"
		description = "look for executable files that reference Lua error names, Lua libraries, or Lua debug flags"
		reference = "https://web.archive.org/web/20150311013500/http://www.cyphort.com/evilbunny-malware-instrumented-lua/"
		reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07190154/The-ProjectSauron-APT_research_KL.pdf"
		reference = "https://securelist.com/the-flame-questions-and-answers/34344/"
		hash = "d737644d612e5051f66fb97a34ec592b3508be06e33f743a2fdb31cdf6bd2718" // REMSEC
		hash = "295b089792d00870db938f2107772e0b58b23e5e8c6c4465c23affe87e2e67ac" // FLAME
		hash = "be14d781b85125a6074724964622ab05f89f41e6bacbda398bc7709d1d98a2ef" // Bunny
		hash = "c6a182f410b4cda0665cd792f00177c56338018fbc31bb34e41b72f8195c20cc" // Bunny

	strings:
		$ = "Lua function expected" ascii wide
		$ = "lua_debug" ascii wide
		$ = "lua.libs" nocase ascii wide
	condition:
		uint16be(0) == 0x4d5a and
		filesize <10MB and
		1 of them
}
