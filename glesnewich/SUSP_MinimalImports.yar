import "pe"

rule SUSP_MinimalImports_LoadLibrary_and_GetModuleFileName
{
	meta:
		author = "Greg Lesnewich"
		description = "look for PE's that import less than 10 functions, 2 of which are variants of LoadLibrary and GetModuleFileName, likely to resolve additional APIs"
		date = "2024-01-26"
		version = "1.0"
		DaysOfYara = "26/100"

	condition:
		pe.number_of_imported_functions < 10 and
		pe.imports(/kernel32.dll/i, /LoadLibrary(A|ExA|ExW|W)/i) and
		pe.imports(/kernel32.dll/i, /GetModuleFileName(A|ExA|ExW|W)/i)
}

rule SUSP_MinimalImports_LoadLibrary_and_GetProcAddress
{
	meta:
		author = "Greg Lesnewich"
		description = "look for PE's that import less than 10 functions, 2 of which are variants of LoadLibrary and GetProcAddress, likely to resolve additional APIs"
		date = "2024-01-26"
		version = "1.0"
		DaysOfYara = "26/100"

	condition:
		pe.number_of_imported_functions < 10 and
		pe.imports(/kernel32.dll/i, /LoadLibrary(A|ExA|ExW|W)/i) and
		pe.imports("kernel32.dll", "GetProcAddress")
}
