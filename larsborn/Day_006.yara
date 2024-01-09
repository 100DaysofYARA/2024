import "pe"

rule PEResourceWithBase64EncodedZip {
    meta:
        description = "A resource in a PE file starting with a base64 encoded ZIP file"
        author = "@larsborn"
        created_at = "2024-01-07"

        DaysofYARA = "6/100"
    condition:
        pe.number_of_resources > 0 and for any i in (0 .. pe.number_of_resources) : (
            // first four bytes of base64 encoding of 'PK\x03\x04'
            uint32be(pe.resources[i].offset) == 0x55457344
        )
}
