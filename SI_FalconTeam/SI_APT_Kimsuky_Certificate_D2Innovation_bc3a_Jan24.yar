import "pe"

rule SI_APT_Kimsuky_Certificate_D2Innovation_bc3a_Jan24 {
    meta:
        version = "1.0"
        date = "2024-01-09"
        modified = "2024-01-09"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "SECUINFRA Falcon Team"
        author = "Marius Genheimer @ Falcon Team"
        description = "Detects PE executables signed by D2innovation Co.,LTD. Malicious use of this cert is attributed to the Kimsuky APT"
        category = "INFO"
        mitre_att = "T1588.003"
        actor_type = "APT"
        actor = "Kimsuky"
        reference = "https://twitter.com/asdasd13asbz/status/1744279858778456325"
        hash = "2e0ffaab995f22b7684052e53b8c64b9283b5e81503b88664785fe6d6569a55e"
        hash = "f8ab78e1db3a3cc3793f7680a90dc1d8ce087226ef59950b7acd6bb1beffd6e3"
        hash = "61b8fbea8c0dfa337eb7ff978124ddf496d0c5f29bcb5672f3bd3d6bf832ac92"
        hash = "ff3718ae6bd59ad479e375c602a81811718dfb2669c2d1de497f02baf7b4adca"
        hash = "a8c24a3e54a4b323973f61630c92ecaad067598ef2547350c9d108bc175774b9"
        minimum_yara = "4.2"
        best_before = "2025-01-09"

    condition:
        uint16(0) == 0x5A4D
        and pe.number_of_signatures > 0
        //and pe.timestamp > 1701385200
        and for any i in (0 .. pe.number_of_signatures): (
            pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" 
            and pe.signatures[i].serial == "00:88:90:ca:b1:cd:51:0c:d2:0d:ab:4c:e5:94:8c:bc:3a")
}