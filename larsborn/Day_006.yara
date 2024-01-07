import "pe"

rule PEResourceWithBae64EncodedZip {
    condition:
        pe.number_of_resources > 0 and for any i in (0 .. pe.number_of_resources) : (
            // first four bytes of base64 encoding of 'PK\x03\x04'
            uint32be(pe.resources[i].offset) == 0x55457344
        )
}
