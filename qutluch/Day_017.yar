rule MAL_DOCX_TURLA_KOPILUAK_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find Turla Kopiluwak documents."

        DaysofYARA  = "17/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-29"
        version     = "1.0"

        hash        = "2299ff9c7e5995333691f3e68373ebbb036aa619acd61cbea6c5210490699bb6"
        hash        = "fe97090dd3496cb811235e770f869d3b3db98411280424248a1bd946fedbb8c7"

    strings:
        $ = "mailform.js"
        $ = "vbscript.regexp"

    condition:
        uint32be(0) == 0xd0cf11e0
        and all of them
}
