import "pe"

rule ttp_toolmark_mobile_net_num_str_1 {
	meta:
		author = "stvemillertime"
        desc = "look for executables with mobile network number strings"
        ref = "d5e59be8ad9418bebca786b3a0a681f7e97ea6374f379b0c4352fee1219b3c29"
        ref = "13e457ce16c0fe24ad0f4fe41a6ad251ebffb2fdaaebe7df094d7852ba0cfdc6"
	strings:
        $a1 = /[^A-Za-z]IMEI[^A-Za-z]/ 
        $a2 = /[^A-Za-z]IMSI[^A-Za-z]/ 
        $a3 = /[^A-Za-z]MSISDN[^A-Za-z]/ 
        $a4 = /[^A-Za-z]ICCID[^A-Za-z]/  
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


