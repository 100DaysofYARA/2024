import "pe"

rule SUSP_PE_RSRCs_Name_Strings_64_and_32_Refs
{
	meta:
		description = "check for PEs that contain both 64 and 32/86 in resource names, potentially indicating second-stage payloads based on bitness"
		author = "Greg Lesnewich"
		date = "2024-01-15"
		version = "1.0"
		DaysofYARA = "15/100"
	condition:
		for any rsrc in pe.resources:
		(
			rsrc.name_string contains "3\x002\x00" or
			rsrc.name_string contains "8\x006\x00"
		)

		and for any rsrc in pe.resources:
		(
			rsrc.name_string contains "6\x004\x00"
			)

}


rule SUSP_PE_RSRCs_Type_Strings_64_and_32_Refs
{
	meta:
		description = "check for PEs that contain both 64 and 32/86 in resource types, potentially indicating second-stage payloads based on bitness"
		author = "Greg Lesnewich"
		date = "2024-01-15"
		version = "1.0"
		DaysofYARA = "15/100"
	condition:
		for any rsrc in pe.resources:
		(
			rsrc.type_string contains "3\x002\x00" or
			rsrc.type_string contains "8\x006\x00"
		)

		and for any rsrc in pe.resources:
		(
			rsrc.type_string contains "6\x004\x00"
			)

}
