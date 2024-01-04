rule HUNT_SUSPICIOUS_UDF_VOLUMEID_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Hunting rule looking for UDF files with suspicious Volume Set Identifiers."

        DaysofYARA  = "2/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-02"
        version     = "1.0"

        hash1       = "723d804cfc334cad788f86c39c7fb58b42f452a72191f7f39400cf05d980b4f3"
        hash2       = "1aeb51a19fb0162d8c0cf5bc27f666a2885d4497b1738f6ad9c7125a8bc3c2d9"

    strings:
        $vol_descr_type_1 = "BEA01"
        $vol_descr_type_2 = "NSR0"
        // Tune and add as needed:
        $susp_volume_id_1 = "Commission" ascii nocase fullword

    condition:
        all of ($vol_descr_type*)
        and $vol_descr_type_1 at 0x8001
        and uint16(0x80000) == 0x2
        and any of ($susp_volume_id*) in (0x1000..0x10200)
        //and filesize < 100MB
}
