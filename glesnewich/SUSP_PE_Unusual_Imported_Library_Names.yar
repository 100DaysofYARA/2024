import "pe"
rule SUSP_PE_Unusual_Imported_Library_Names

{
	meta:
		description = "look for PE's whose imported libraries don't end in DLL, and aren't common EXE names"
		author = "Greg Lesnewich"
		date = "2024-01-14"
		version = "1.0"
		DaysOfYARA = "14/100"

	condition:
		for any imp in pe.import_details:
		(
			not imp.library_name iendswith ".dll" and
			not imp.library_name iequals "WINSPOOL.DRV" and
			not imp.library_name iequals "ntoskrnl.exe"
		)
}
