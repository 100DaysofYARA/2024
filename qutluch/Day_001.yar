rule HUNT_UDF_FILE_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule for matching on Universal Disk Format files."
        disclaimer  = "This rule is a basis for hunting rules and does not denote a suspicious file by itself."
        reference   = "http://www.osta.org/specs/pdf/udf260.pdf"

        DaysofYARA  = "1/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-01"
        version     = "1.0"
        hash        = "4f7bbe7ebd29fc2ab71c580d9968d12b32d407c3b73756c9590b9b3ef7a94e7c"

    strings:
        // Denotes the beginning of the extended descriptor section.
        $vol_descr_type_1 = "BEA01"

        // Indicates that this volume contains a UDF file system.
        $vol_descr_type_2 = "NSR0"

    condition:
        all of ($vol_descr_type*)
        and $vol_descr_type_1 at 0x8001

        // Anchor Volume Descriptor Pointer->DescriptorTag->TagIdentifier
        and uint16(0x80000) == 0x2

        //and filesize < 10MB
}
