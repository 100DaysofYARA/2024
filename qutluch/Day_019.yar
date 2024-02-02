rule MAL_DOCX_LODEINFO_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find LODEINFO documents."

        DaysofYARA  = "19/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-30"
        version     = "1.0"

        hash        = "f21745cc6306461d1ddb3c35ed6016468ce984bbd64bfb86139a392e3a45c495"

    strings:
        $ = {65 6a 58 62 ?? 59 4f 67 50 44}

    condition:
        uint32be(0) == 0xd0cf11e0
        and all of them
}
