rule SUSP_References_Likely_Traffic_Listening_Network_Interface
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to Network-Interface that might get used for traffic sniffing"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "Network-Interface" nocase ascii wide
        $  = "Network Interface" nocase ascii wide
    condition:
        1 of them
}


rule SUSP_References_Likely_Traffic_Capture_eth0
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to eth0 that might get used for traffic capture"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "eth0" nocase ascii wide
    condition:
        1 of them
}


rule SUSP_References_Likely_Traffic_Capture_802_11
{
    meta:
        author = "Greg Lesnewich"
        description = "look for string refs to 802.11 that might get used for localized traffic capture"
        date = "2024-02-11"
        version = "1.0"
        DaysOfYARA = "41/100"
        reference = "https://www.mandiant.com/resources/blog/barracuda-esg-exploited-globally"

    strings:
        $  = "802.11" ascii wide
    condition:
        1 of them
}
