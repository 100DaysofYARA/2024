rule APT_TURLA_KOPILUWAK_1
{

    meta:
        author      = "@qutluch@infosec.exchange"
        description = "Rule to find Turla KopiLuwak."
        reference   = "https://securelist.com/kopiluwak-a-new-javascript-payload-from-turla/77429/"

        DaysofYARA  = "22/100"

        license     = "BSD-2-Clause"
        date        = "2024-01-30"
        version     = "1.0"

        hash        = "498803a3d9962a9ce2aa55abfaa3fa2ad25804db800c093889d283d7a9d7d4bf"
        hash        = "a9febe8c2cd6b4e6819939828da0e66e0441ec9f7c6c574d1b6ceb03faef0579"

    strings:
        $sa1    = "%27%D"
        $sa2    = "D%07%F"
        $sa3    = "%DB%"
        $sa4    = "0%B0%"
        $sa5    = "7%3E%"
        $sa6    = "%C4%"

        $sb1    = ".charCodeAt("
        $sb2    = "+=String.fromCharCode("
        $sb3    = "=new Function($"
        $sb4    = { 24 58 [32] 28 29 3b }

    condition:
        uint16(0) != 0x5A4D
        and filesize < 1MB
        and all of them
        and (#sa1 + #sa2 + #sa3 + #sa4 + #sa5 + #sa6) > 500
}
