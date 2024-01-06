import "pe"
rule SUSP_DLL_Duplicated_First_ExportNames
{
	meta:
		author = "Greg Lesnewich"
		description = "track a weird TTP abused by DPRK operators, where a trojanized binary will use a duplicated or incremented export name"
		date = "2024-01-04"
		version = "1.0"
		DaysOfYara = "6/100"
		hash = "c8707d9d7f3ade7f8aa25034e6a73060e5998db980e90452eb0190994036d781" // DRATzarus
		hash = "26a2fa7b45a455c311fd57875d8231c853ea4399be7b9344f2136030b2edc4aa" // DTrack
		hash = "ec254c40abff00b104a949f07b7b64235fc395ecb9311eb4020c1c4da0e6b5c4" // Deathnote
		hash = "722fa0c893b39fef787b7bc277c979d29adc1525d77dd952f0cc61cd4d0597cc" // FP, Turla RPCBackdoor
		hash = "84b5a89917792291e2425b64e093580ca8d2e106532e433e949cdde3c2db4053" // Klackring
		hash = "39ad9ae3780c2f6d41b1897e78f2b2b6d549365f5f024bc68d1fe794b940f9f1" // ThreatNeedle

	condition:
		pe.number_of_exports < 5 and
		(
			((pe.export_details[1].name startswith pe.export_details[0].name) and
			pe.export_details[1].name endswith "W") or

			((pe.export_details[2].name startswith pe.export_details[0].name) and
			pe.export_details[2].name endswith "W") or

			((pe.export_details[2].name startswith pe.export_details[1].name) and
			pe.export_details[2].name endswith "W")
		)

}
