import "pe"

rule ttp_toolmark_mobile_net_num_str_1 {
	meta:
		author = "stvemillertime"
        desc = "look for executables with mobile network number strings"
        ref = "22e05ebb06947af2236f57432f06bd94c1eb4e76472ccaf3ee40335383a30815"
        ref = "ed5d29a19f3aed2c870051d639b974f16682a2463fd20bd230594102c39958dd"
	strings:
        $a1 = /[^A-Za-z]IMEI(:|=|\x20\x00|_)/  ascii 
        $a2 = /[^A-Za-z]IMSI(:|=|\x20|\x00|_)/  ascii 
        $a3 = /[^A-Za-z]MSISDN(:|=|\x20|\x00|_)/  ascii 
        $a4 = /[^A-Za-z]ICCID(:|=|\x20|\x00|_)/  ascii 
        $z1 = "WiFiNetworkManager.dll" //windows stuff
        $z2 = "WWANSVC.DLL" //??
        $z3 = "NetworkMobileSettings.dll" //win
    condition:
        (
            uint32be(0) == 0x7f454c46 or // elf
            uint32be(0) == 0x504b0304 or // pkzip for apk
            uint32be(0) == 0x6465780a or // dex
            (uint16be(0) == 0x4d5a and pe.number_of_signatures == 0) // mz
        )
        and 2 of ($a*)
        and not any of ($z*)
}


