import "pe"

rule AutoHotkey_ResourceName {
    meta:
        description = "Resource name of compiled AutoHotkey (.ahk) scripts"
        author = "@larsborn"
        created_at = "2024-01-10"
        reference = "https://www.autohotkey.com/docs/v1/Scripts.htm#ahk2exe-base"

        DaysofYARA = "8/100"
    condition:
        for any i in (0..pe.number_of_resources - 1):
            (pe.resources[i].name_string == ">\x00A\x00U\x00T\x00O\x00H\x00O\x00T\x00K\x00E\x00Y\x00 \x00S\x00C\x00R\x00I\x00P\x00T\x00<\x00")
}
