import "pe"

rule SUSP_PE_DRIVER_SIGNED_SIZE_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Adapted version of rule from Day 10 looking for the same signer but drivers under a certain size which is suspicious."

        DaysofYARA  = "31/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"

        hash        = "821e9fe79677dfd89ae5b54e4a14444bbad6c4977d945da68cabf9b421524972"

    condition:
        filesize < 50KB
        and uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x5C) == 0x0001
        and pe.number_of_signatures > 0
        and for any sig in pe.signatures: (
            sig.subject == "/businessCategory=Private Organization/serialNumber=91500107MA5YTRH15X/jurisdictionC=CN/jurisdictionST=Chongqing/C=CN/ST=\\xE9\\x87\\x8D\\xE5\\xBA\\x86/L=\\xE9\\x87\\x8D\\xE5\\xBA\\x86"
        )
}
