import "pe"

rule SUSP_PE_DRIVER_GITHUB_PDB_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find signed Windows drivers with github -master PDB paths"

        DaysofYARA  = "32/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-27"
        version     = "1.0"


        hash        = "454e0f3ccbcc9805b0117413819d25099c3f3d73f0477892092f875a0cea001b"
        hash        = "7fdd11d2f1933cfe60be8e4f728fa3ade03d04acb7533bb33ff49b93e6363b57"
        hash        = "07b4b4c57f3786ad55dc7b40369ee647d13d43f8815dcd2ab47e36eec98d13cc"

    strings:
        $ = "-master\\"

    condition:
        any of them
        and uint16(0) == 0x5A4D
        and (uint32(uint32(0x3C)) == 0x00004550)
        and uint16(uint32(0x3C)+0x5C) == 0x0001
        and pe.number_of_signatures > 0
        and pe.pdb_path icontains "-master\\"

        // Filter for specific signers.
        /*
        and for any sig in pe.signatures: (
            sig.subject == "/businessCategory=Private Organization/serialNumber=91500107MA5YTRH15X/jurisdictionC=CN/jurisdictionST=Chongqing/C=CN/ST=\\xE9\\x87\\x8D\\xE5\\xBA\\x86/L=\\xE9\\x87\\x8D\\xE5\\xBA\\x86"
        )
        */
}
