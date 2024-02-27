rule MAL_Netwire_strings {
	meta:
		description = "Matches strings found in NetWire malware samples."
		last_modified = "2024-02-27"
		author = "@petermstewart"
		DaysofYara = "58/100"
		sha256 = "05a36b671efa242764695140c004dfff3e0ff9d11df5d74005b7c1c8c53d8f00"
		sha256 = "d2a60c0cb4dd0c53c48bc062ca754d94df400dee9b672cf8881f5a1eff5b4fbe"

	strings:
		$ua = "User-Agent: Mozilla/4.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
		$a1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
		$a2 = "Accept-Language: en-US,en;q=0.8"
		$a3 = "GET %s HTTP/1.1" 
		$b1 = "ping 192.0.2.2 -n 1 -w %d >nul 2>&1"
		$b2 = "DEL /s \"%s\" >nul 2>&1"
		$b3 = "call :deleteSelf&exit /b"
		$b4 = ":deleteSelf"
		$b5 = "start /b \"\" cmd /c del \"%%~f0\"&exit /b"
		$b6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders"
		$c1 = "%6\\EWWnid\\PI0Wld\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c2 = "%6\\PI0Wl4Ql\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c3 = "%6\\PWlWSW\\a0CnWR\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c4 = "%6\\vCRSdf\\vCRSdfc0Wg6d0\\u6d0 aC5C\\ad8CQi5\\mWn4R aC5C"
		$c5 = "%6\\Tsd0C MW85gC0d\\Tsd0C M5CVid\\mWn4R aC5C"

	condition:
		uint16(0) == 0x5a4d and
		12 of them
}
