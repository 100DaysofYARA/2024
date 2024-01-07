import "pe"

rule MAL_SQLMaggie_strings {
	meta:
		description = "Matches strings found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
		last_modified = "2024-01-06"
    		author = "@petermstewart"
    		DaysofYara = "6/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"
	
	strings:
		$a1 = "Account Owner Not Found For The SID"
		$a2 = "%s Isn't Successfully Hooked Yet"
		$a3 = "About To Execute: %s %s %s"
		$a4 = "RunAs User Password Command"
		$a5 = "Wait 5 To 10 Seconds For TS Taking Effect"
		$a6 = "Re-Install TS Successfullly"
		$a7 = "ImpersonateLoggedOnUser = %d"
		$a8 = "The Account %s Has Been Cloned To %s"
		$a9 = "Fileaccess ObjectName [TrusteeName] [Permission] Options"
		$a10 = "SQL Scan Already Running"
		$a11 = "HellFire2050"

	condition:
		uint16(0) == 0x5a4d and
		8 of them
}

rule MAL_SQLMaggie_dll_export {
	meta:
		description = "Matches DLL export found in SQLMaggie backdoor used by China-nexus threat actor WIP19."
		last_modified = "2024-01-07"
        	author = "@petermstewart"
        	DaysofYara = "7/100"
		ref = "https://www.sentinelone.com/labs/wip19-espionage-new-chinese-apt-targets-it-service-providers-and-telcos-with-signed-malware/"
		sha256 = "f29a311d62c54bbb01f675db9864f4ab0b3483e6cfdd15a745d4943029dcdf14"

	condition:
		uint16(0) == 0x5a4d and
		pe.number_of_exports == 1 and
		pe.export_details[0].name == "maggie"
}
