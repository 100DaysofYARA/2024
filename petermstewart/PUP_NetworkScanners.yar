import "pe"
import "hash"

rule PUP_THCHydra_strings {
    meta:
        description = "Matches strings found in the THC-Hydra network scanner."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        ref = "https://github.com/vanhauser-thc/thc-hydra"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    strings:
        $a1 = "hydra -P pass.txt target cisco-enable  (direct console access)"
        $a2 = "hydra -P pass.txt -m cisco target cisco-enable  (Logon password cisco)"
        $a3 = "hydra -l foo -m bar -P pass.txt target cisco-enable  (AAA Login foo, password bar)"
        $a4 = "hydra -L urllist.txt -s 3128 target.com http-proxy-urlenum user:pass"
        $a5 = "hydra -L urllist.txt http-proxy-urlenum://target.com:3128/user:pass"
        $a6 = "USER hydra%d hydra %s :hydra"
        $a7 = "hydra rdp://192.168.0.1/firstdomainname -l john -p doe"
        $a8 = "User-Agent: Mozilla/4.0 (Hydra)"

    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f) and
        all of them
}

rule PUP_THCHydra_default_icon {
    meta:
        description = "Matches the default icon resource section hash found in Windows THC-Hydra network scanner binaries."
        last_modified = "2024-02-24"
        author = "@petermstewart"
        DaysofYara = "55/100"
        sha256 = "ee43a7be375ae2203b635c569652f182f381b426f80430ee495aa6a96f37b4e6"
        ref = "https://github.com/maaaaz/thc-hydra-windows"

    condition:
        uint16(0) == 0x5a4d and
        for any resource in pe.resources:
        (
            hash.md5(resource.offset, resource.length) == "7835bdbf054e7ba813fa0203aa1c5e36"
        )
}

rule PUP_AdvancedIPScanner_strings {
	meta:
		description = "Matches strings found in the Advanced IP Scanner installer, often abused by malicious actors."
		last_modified = "2024-03-10"
		author = "@petermstewart"
		DaysofYara = "70/100"
		sha256 = "26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b"

	strings:
		$a1 = "This installer contains the logic and data to install Advanced IP Scanner"
		$a2 = "www.advanced-ip-scanner.com/link.php?"
		$a3 = "advanced ip scanner; install; network scan; ip scan; LAN"

	condition:
		uint16(0) == 0x5a4d and
		all of them
}
