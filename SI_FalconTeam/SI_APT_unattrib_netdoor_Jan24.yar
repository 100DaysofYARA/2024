rule SI_APT_unattrib_netdoor_Jan24 {
    meta:
        version = "1.0"
        date = "2024-01-17"
        modified = "2024-01-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects the 'netdoor' .NET TCP reverse shell (CMD/Powershell)."
        category = "MALWARE"
        malware_type = "Reverse Shell"
        mitre_att = "T1059"
        actor_type = "APT"
        reference = "https://twitter.com/h2jazi/status/1747334436805341283"
        hash = "8920021af359df74892a2b86da62679c444362320f7603f43c2bd9217d3cb333"
        hash = "7581b86dd1d85593986f1dd34942d007699d065f2407c27683729fa9a32ae1d6"
        hash = "c914343ac4fa6395f13a885f4cbf207c4f20ce39415b81fd7cfacd0bea0fe093"
        minimum_yara = "2.0.0"
        best_before = "2025-01-18"

    strings:
        $w_1 = "Attempting to reconnect in {0} seconds..." wide
        $w_2 = "Error receiving/processing commands:" wide
        $w_3 = "Connection lost. Reconnecting..." wide
        $w_4 = "Exiting the application." wide
        $w_5 = "Server disconnected." wide
        $w_6 = "ServerIP" wide
        $w_7 = "powershell" wide
        $w_8 = "cmd.exe" wide

        $a_1 = "ConnectAndExecuteAsync" ascii
        $a_2 = "SendIdentificationDataAsync" ascii
        $a_3 = "ReceiveAndExecuteCommandsAsync" ascii
        $a_4 = "ProcessCommandsAsync" ascii
        $a_5 = "ExecuteCommandAsync" ascii
        $a_6 = "reconnectionAttempts" ascii

        $origFileName = /[0-9]{4}202[0-9]\.exe/

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100KB
        and 4 of ($w_*)
        and 4 of ($a_*)
        and #origFileName >= 0
}