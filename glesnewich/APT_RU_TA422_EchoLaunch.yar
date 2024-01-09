rule APT_RU_TA422_EchoLaunch
{
	meta:
		author = "Greg Lesnewich"
		description = "track TA422's EchoLaunch scriptlet launcher"
		date = "2023-11-29"
		version = "1.4"
		DaysofYARA = "8/100"
		reference = "https://www.proofpoint.com/us/blog/threat-insight/ta422s-dedicated-exploitation-loop-same-week-after-week"
		reference = "https://securityintelligence.com/x-force/itg05-ops-leverage-israel-hamas-conflict-lures-to-deliver-headlace-malware/"
		hash = "742ba041a0870c07e094a97d1c7fd78b7d2fdf0fcdaa709db04e2637a4364185"
		hash = "8a21077dbba184dc43576a78bf52dc29aaa47df332d1e65694876dd245f35563"
		hash = "b26726448878ffba939c95d01252f62b8c004b51a2c8c8cf48ef2c4f308c1721"
		hash = "c89735e787dd223dac559a95cac9e2c0b6ca75dc15da62199c98617b5af007d3"
	strings:
		$s1 = "echo On Error Resume Next & echo .Run" ascii
		$s2 = "CreateObject^(^\"WScript.shell^\"^)" ascii
		$s3 = ".bat^\"^\"^\"^" ascii
		$s4 = "echo taskkill /im msedge.exe /f" ascii
		$s5 = "echo timeout 5 & echo del /q /f" ascii
		$s6 = "msedge --headless=new --disable-gpu data:text/html;base64" ascii
		$s7 = "echo goto loop" ascii
		$s8 = "> nul 2>&1" ascii
		$s9 = "del /F /A /Q" ascii
		$s10 = "taskkill /F /IM" ascii
		$s11 = "echo move /y \"%userprofile%\\Downloads\\*.css\"" ascii
	condition:
		uint32be(0x0) == 0x40656368 and
		uint32be(filesize - 4) == 0x69740d0a and
		filesize < 3000 and 
		9 of them
}
