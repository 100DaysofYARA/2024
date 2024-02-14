rule INFO_LNK_Findstr_NSLookup_CMD_LNK
{
    meta:
        author = "Joe Wise"
        description = "Identify LNK files that contain findstr, nslookup, and .cmd"
        date = "2024-02-08"
        version = "1.0"
        hash1 = "37f0cd954554e4bd3b766c79f6224c03dbcfbb4c0f23ac1f48292ce88d2dc767"
        DaysOfYara = "39/100"

    strings:
        $s1 = "nslookup" nocase ascii wide
        $s2 = "findstr" nocase ascii wide
	$s3 = ".cmd" nocase ascii wide
    condition:
        uint32be(0x0) == 0x4c000000 and all of them
}
