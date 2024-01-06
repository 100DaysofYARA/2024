rule MAL_DOCX_CRC32_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule detecting specific docProps/app.xml in OOXML documents."
        reference   = "https://www.proofpoint.com/us/blog/threat-insight/ta422s-dedicated-exploitation-loop-same-week-after-week"
        hash        = "e699a7971a38fe723c690f37ba81187eb8ed78e51846aa86aa89524c325358b4"

        DaysofYARA  = "6/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-06"
        version     = "1.0"

    strings:
        $crc = {1967cf15}
        $ext = ".xml"
        $ufs = {53060000}

    condition:
        $ufs at @crc[1] + 8 and $ext at @crc[1] + uint16(@crc[1] + 12) + 16 - 4
}
