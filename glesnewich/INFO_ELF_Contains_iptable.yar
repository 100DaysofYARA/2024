rule INFO_ELF_Contains_iptables
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}


rule INFO_ELF_Contains_iptables_b64
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" base64 base64wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}


rule INFO_ELF_Contains_iptables_xor
{
    meta:
        author = "Greg Lesnewich"
        date = "2024-01-21"
        version = "1.0"
        description = "track ELF files that reference iptables likely for portforwarding, redirecting, or listening "
        DaysofYARA = "21/100"

    strings:
        $ = "iptables" xor(0x01-0xff) ascii wide
    condition:
        uint32be(0) == 0x7F454C46 and all of them
}
