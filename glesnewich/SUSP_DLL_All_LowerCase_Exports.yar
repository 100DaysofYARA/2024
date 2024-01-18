import "pe"
rule SUSP_DLL_All_LowerCase_Exports
{
	meta:
		author = "Greg Lesnewich"
		description = "track weird PE's that do not contain any capital letters in their export names, inspired by the CoreLump, MataDoor L-Library Loader, and BruteRatel families"
		date = "2024-01-13"
		version = "1.0"
		hash = "c96ae21b4cf2e28eec222cfe6ca903c4767a068630a73eca58424f9a975c6b7d" // CoreLump
		hash = "8c94a3cef4e45a1db05ae9723ce5f5ed66fc57316e9868f66c995ebee55f5117" // MataDoor L-Library_Loader
		DaysofYARA = "13/100"

	condition:
		for all exps in pe.export_details: (
			for all letter in ("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z"):
			(
				not exps.name contains letter
			)
		)
}
