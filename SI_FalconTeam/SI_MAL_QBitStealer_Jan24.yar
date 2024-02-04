rule SI_MAL_qBitStealer_Jan24 {
    meta:
        version = "1.1"
        date = "2024-01-30"
        modified = "2024-01-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects the 'qBit Stealer' data exfiltration tool"
        category = "MALWARE"
        malware_type = "Stealer"
        mitre_att = "T1119"
        actor_type = "CRIMEWARE"
        reference = "https://cyble.com/blog/decoding-qbit-stealers-source-release-and-data-exfiltration-prowess/"
        hash = "874ac477ea85e1a813ed167f326713c26018d9b2d649099148de7f9e7a163b23"
        hash = "2787246491b1ef657737e217142ca216c876c7178febcfe05f0379b730aae0cc"
        hash = "dab36adf8e01db42efc4a2a4e2ffc5251c15b511a83dae943bfe3d661f2d80ae"
        minimum_yara = "2.0.0"

    strings:
        $qBit_1 = "qBit Stealer RaaS"
        $qBit_2 = "(qbit@hitler.rocks)"
        $qBit_3 = "TRIAL VERSION - 24 Hour Access"
        $qBit_4 = "Email us to Purchase!"
        
        $comp_1 = "qBitStealer.go"
        $comp_2 = "megaFunc.go"
        $comp_3 = "functions.go"
        $comp_4 = "internal.go"
        
        $dbg_1 = "[+] Loaded configJs"
        $dbg_2 = "[+] Logged into Mega..."
        $dbg_3 = "[+] Please wait, files are being uploaded... WORKING!"
        $dbg_4 = "[+] Clean up of Left over Archived files completed with no errors."
        $dbg_5 = "Stolen Folder Name:"
        $dbg_6 = "Targeted File Extensions:"
        
        $api_1 = "http://worldtimeapi.org/api/timezone/Etc/UTC"
        $api_2 = "https://g.api.mega.co.nz"

    condition:
        uint16(0) == 0x5a4d
        and 2 of ($qBit_*)
        and 3 of ($comp_*)
        and 4 of ($dbg_*)
        and all of ($api_*)
}

rule SI_TA_187ir_Keywords_Jan24 {
    meta:
        version = "1.0"
        date = "2024-01-30"
        modified = "2024-01-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects artifacts of the threat actor '187ir' in modified qBit Stealer binaries"
        category = "INFO"
        actor_type = "CRIMEWARE"
        reference = "https://twitter.com/1ZRR4H/status/1751656174515098023"
        hash = "874ac477ea85e1a813ed167f326713c26018d9b2d649099148de7f9e7a163b23"
        minimum_yara = "2.0.0"

    strings:
        $s_1 = "XFiltr8" ascii wide
        $s_2 = "187ir" fullword ascii wide

    condition:
        SI_MAL_qBitStealer_Jan24
        and any of ($s_*)
}

