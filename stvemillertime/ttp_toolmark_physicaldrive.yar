import "pe"
rule ttp_toolmark_physicaldrive_signed {
    meta:
        author = "stvemillertime"
        desc = "this looks for pes with the toolmark PhysicalDrive which is often a handle to the ... physical drive (raw disk)"
    strings:
        $a = /\x00[\x01-\x7f]{0,50}\\\\\.\\PhysicalDrive(%|[0-9])[\x01-\x7f]{0,50}\x00/ nocase ascii //play with the regex if u wanna get fancy
        // some common exclusions
        $z00 = "RMActivate_isv.pdb\x00" nocase
        $z01 = "RMActivate.pdb\x00" nocase
        $z02 = "iscsidsc.pdb\x00"
        $z03 = "iscsiexe.pdb\x00"
        $z04 = "hostmib.pdb\x00"
        $z05 = "vmtools.pdb\x00"
        $z06 = "scmbridge.pdb\x00"
    condition:  
        uint16be(0) == 0x4d5a 
        and pe.number_of_signatures != 0
        and $a
        and not any of ($z*)
}
rule ttp_toolmark_physicaldrive_unsigned {
    meta:
        author = "stvemillertime"
        desc = "this looks for pes with the toolmark PhysicalDrive which is often a handle to the ... physical drive (raw disk)"
    strings:
        $a = /\x00[\x01-\x7f]{0,50}\\\\\.\\PhysicalDrive(%|[0-9])[\x01-\x7f]{0,50}\x00/ nocase ascii
        // some common exclusions
        $z00 = "RMActivate_isv.pdb\x00" nocase
        $z01 = "RMActivate.pdb\x00" nocase
        $z02 = "iscsidsc.pdb\x00"
        $z03 = "iscsiexe.pdb\x00"
        $z04 = "hostmib.pdb\x00"
        $z05 = "vmtools.pdb\x00"
        $z06 = "scmbridge.pdb\x00"
    condition:  
        uint16be(0) == 0x4d5a 
        and pe.number_of_signatures == 0
        and $a
        and not any of ($z*)
}
rule ttp_toolmark_physicaldrive_xor {
    meta:
        author = "stvemillertime"
        desc = "this looks for pes with the xored toolmark PhysicalDrive which is often a handle to the ... physical drive (raw disk)"
    strings:
        $a = "PhysicalDrive" xor(0x01-0xff)
        $b = "physicaldrive" xor(0x01-0x19)
        $c = "physicaldrive" xor(0x21-0xff)
        $d = "PHYSICALDRIVE" xor(0x01-0x19)
        $e = "PHYSICALDRIVE" xor(0x21-0xff)
    condition:  
        uint16be(0) == 0x4d5a 
        and any of them
}