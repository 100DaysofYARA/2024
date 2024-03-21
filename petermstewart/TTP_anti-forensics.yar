rule TTP_delete_volume_shadow {
	meta:
		description = "Matches references to 'vssadmin delete' commands - used to remove Volume Shadow Copies."
		last_modified = "2024-03-13"
		author = "@petermstewart"
		DaysofYara = "73/100"

	strings:
		$a = "vssadmin delete" ascii wide nocase
		$b = "vssadmin.exe delete" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d and
		any of them
}

rule TTP_clear_event_logs {
	meta:
		description = "Matches references to 'wevtutil' or 'Clear-Eventlog' - used to clear Windows Event Logs."
		last_modified = "2024-03-14"
		author = "@petermstewart"
		DaysofYara = "74/100"

	strings:
		$a = "wevtutil cl" ascii wide nocase
		$b = "wevtutil.exe cl" ascii wide nocase
		$c = "wevtutil clear log" ascii wide nocase
		$d = "wevtutil.exe clear log" ascii wide nocase
		$e = "Clear-EventLog" ascii wide nocase //PowerShell

	condition:
		uint16(0) == 0x5a4d and
		any of them
}

rule TTP_bcdedit_safeboot_cmd {
	meta:
		description = "Matches bcdedit command used to configure reboot to safemode - can be used to bypass security tools."
		last_modified = "2024-03-15"
		author = "@petermstewart"
		DaysofYara = "75/100"

	strings:
		$a = "bcdedit /set {default} safeboot" ascii wide nocase
		$b = "bcdedit.exe /set {default} safeboot" ascii wide nocase

	condition:
		uint16(0) == 0x5a4d and
		any of them
}
